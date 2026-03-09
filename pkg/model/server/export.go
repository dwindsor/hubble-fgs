// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	appModelV1 "github.com/isovalent/ipa/application_model/v1alpha"
	commonV1 "github.com/isovalent/ipa/common/v1alpha"
	graphV1 "github.com/isovalent/ipa/graph/v1alpha"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/cilium/tetragon/pkg/version"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"

	"github.com/isovalent/hubble-fgs/pkg/metrics/networkmetrics"
	"github.com/isovalent/hubble-fgs/pkg/model"
	"github.com/isovalent/hubble-fgs/pkg/model/diff"
	"github.com/isovalent/hubble-fgs/pkg/model/types"
	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"
)

func exportTelemetry(ctx context.Context, last time.Time, telemetry, connection *json.Encoder, newModel, lastModel *appModelV1.ApplicationModel, telemetryMap model.TelemetryMap) (time.Time, error) {
	now := time.Now()

	networkDiffModel, processDiffModel, err := diff.ApplicationModelDiff(newModel, lastModel)
	if err != nil {
		logger.GetLogger().Error("Failed to produce application model difference as JSON", logfields.Error, err)
		return last, err
	}

	// If nothing has changed do not update last model and skip writing empty record
	if networkDiffModel == nil && processDiffModel == nil {
		return last, nil
	}

	if telemetry != nil {
		procFlatPack, err := diff.ApplicationModelToProcessFlat(ctx, processDiffModel, telemetryMap)
		if err != nil {
			logger.GetLogger().Error("Failed to decode application model to process telemetry", logfields.Error, err)
			return last, err
		}

		for _, entry := range procFlatPack {
			if err := telemetry.Encode(entry); err != nil {
				logger.GetLogger().Error("Failed to encode process telemetry as JSON", logfields.Error, err)
				return last, err
			}
		}
	}

	netFlatPack, err := diff.ApplicationModelToNetworkFlat(ctx, networkDiffModel)
	if err != nil {
		logger.GetLogger().Error("Failed to decode application model to network telemetry", logfields.Error, err)
		return last, err
	}

	var conns []*graphV1.Connection
	for _, entry := range netFlatPack {
		networkmetrics.Collect(entry)
		if telemetry != nil {
			if err := telemetry.Encode(entry); err != nil {
				logger.GetLogger().Error("Failed to encode network telemetry as JSON", logfields.Error, err)
				return last, err
			}
		}
		if connection != nil {
			conn := diff.TelemetryToConnection(entry)
			if conn != nil {
				conns = append(conns, conn)
			}
		}
	}

	if connection != nil && len(conns) > 0 {
		log := graphV1.ConnectionLog{
			Emitter: &commonV1.Emitter{
				Name:    "Tetragon",
				Version: strings.TrimPrefix(version.Version, "v"),
			},
			WindowStart: timestamppb.New(last),
			WindowEnd:   timestamppb.New(now),
			Connections: conns,
		}
		if err := connection.Encode(&log); err != nil {
			logger.GetLogger().Warn("Failed to encode connection log as JSON", logfields.Error, err)
		}
	}
	return now, nil
}

// exportTick processes a single export cycle: converts process models to an
// application model, encodes it (non-fatal on failure), and exports telemetry
// and connection diffs. Extracted from ExportApplicationModel so the
// error-handling behavior is testable independently of the server loop.
func exportTick(
	ctx context.Context,
	processModels []*types.ProcessModel,
	appModelEncoder, telemetryEncoder, connectionEncoder *json.Encoder,
	lastModel *appModelV1.ApplicationModelEvent,
	lastTime time.Time,
	emptyFilter map[string]bool,
) (*appModelV1.ApplicationModelEvent, time.Time) {
	newModel, processData := model.ProcessModelToApplicationModelWithProcessData(processModels, emptyFilter)
	telemetryMap := model.BuildTelemetryMap(processData)

	if appModelEncoder != nil {
		if enterpriseOption.Config.ApplicationModelExportFragments {
			fragments := model.SplitApplicationModelEvent(newModel)
			for _, fragment := range fragments {
				if err := appModelEncoder.Encode(fragment); err != nil {
					logger.GetLogger().Error("Failed to encode application model fragment as JSON", logfields.Error, err)
				}
			}
		} else {
			if err := appModelEncoder.Encode(newModel); err != nil {
				logger.GetLogger().Error("Failed to encode application model as JSON", logfields.Error, err)
			}
		}
	}

	if telemetryEncoder != nil || connectionEncoder != nil {
		lastTime, _ = exportTelemetry(ctx, lastTime, telemetryEncoder, connectionEncoder,
			newModel.ApplicationModel, lastModel.ApplicationModel, telemetryMap)
		lastModel = newModel
	}

	return lastModel, lastTime
}

func ExportApplicationModel(ctx context.Context, server *Server, writer io.Writer, flatWriter io.Writer, connectionWriter io.Writer, interval time.Duration) {
	var encoder *json.Encoder
	var telemetry *json.Encoder
	var connection *json.Encoder

	lastTime := time.Now()

	res, err := server.GetProcessModel(ctx, []string{}, false)
	if err != nil {
		if errors.Is(err, ErrApplicationModelNotEnabled) {
			logger.GetLogger().Info("Application Model not enabled", logfields.Error, err)
		} else {
			logger.GetLogger().Error("Failed to get process model from Tetragon", logfields.Error, err)
		}
		return
	}
	emptyFilter := make(map[string]bool)
	lastModel, _ := model.ProcessModelToApplicationModelWithProcessData(res, emptyFilter)

	if writer != nil {
		encoder = json.NewEncoder(writer)
	}

	// *Writer is an interface so we can't nil check it and we drop back to
	// the enterprise option the source of truth. Although its annoying for
	// CI.
	if enterpriseOption.Config.TelemetryExportFilename != "" {
		telemetry = json.NewEncoder(flatWriter)
	}

	if enterpriseOption.Config.ConnectionLogFileName != "" {
		connection = json.NewEncoder(connectionWriter)
	}

	ticker := time.NewTicker(interval)
	logger.GetLogger().Info("Exporting process model", "interval", interval)
	for {
		select {
		case <-ticker.C:
			res, err := server.GetProcessModel(ctx, []string{}, false)
			if err != nil {
				logger.GetLogger().Error("Failed to get process model from Tetragon", logfields.Error, err)
				continue
			}

			var appModelEncoder *json.Encoder
			if enterpriseOption.Config.ApplicationModelExportFilename != "" {
				appModelEncoder = encoder
			}

			lastModel, lastTime = exportTick(ctx, res, appModelEncoder, telemetry, connection, lastModel, lastTime, emptyFilter)
		case <-ctx.Done():
			return
		}
	}
}

// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

//go:build !nok8s

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
	"uuid"

	appModelV1 "github.com/isovalent/ipa/application_model/v1alpha"
	commonV1 "github.com/isovalent/ipa/common/v1alpha"
	graphV1 "github.com/isovalent/ipa/graph/v1alpha"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/cilium/tetragon/pkg/version"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/reader/node"

	"github.com/isovalent/hubble-fgs/pkg/metrics/appmodelmetrics"
	"github.com/isovalent/hubble-fgs/pkg/metrics/networkmetrics"
	"github.com/isovalent/hubble-fgs/pkg/model"
	"github.com/isovalent/hubble-fgs/pkg/model/diff"
	"github.com/isovalent/hubble-fgs/pkg/model/types"
	"github.com/isovalent/hubble-fgs/pkg/node/local"
	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"
)

func exportTelemetry(ctx context.Context, last time.Time, telemetry, connection *json.Encoder, newModel, lastModel *appModelV1.ApplicationModel, telemetryMap model.TelemetryMap, metadataService local.MetadataService) (time.Time, error) {
	now := time.Now()

	diffStart := time.Now()
	networkDiffModel, processDiffModel, err := diff.ApplicationModelDiff(newModel, lastModel)
	appmodelmetrics.RecordDuration(appmodelmetrics.PhaseDiff, float64(time.Since(diffStart).Microseconds()))
	if err != nil {
		logger.GetLogger().Error("Failed to produce application model difference as JSON", logfields.Error, err)
		appmodelmetrics.RecordError(appmodelmetrics.PhaseDiff)
		return last, err
	}

	// If nothing has changed do not update last model and skip writing empty record
	if networkDiffModel == nil && processDiffModel == nil {
		appmodelmetrics.RecordNoChanges()
		return last, nil
	}

	if telemetry != nil {
		procFlatPack, err := diff.ApplicationModelToProcessFlat(ctx, processDiffModel, telemetryMap, metadataService)
		if err != nil {
			logger.GetLogger().Error("Failed to decode application model to process telemetry", logfields.Error, err)
			appmodelmetrics.RecordError(appmodelmetrics.PhaseExportProcess)
			return last, err
		}
		appmodelmetrics.RecordTelemetryEntries(appmodelmetrics.TelemetryProcess, len(procFlatPack))

		for _, entry := range procFlatPack {
			if err := telemetry.Encode(entry); err != nil {
				logger.GetLogger().Error("Failed to encode process telemetry as JSON", logfields.Error, err)
				appmodelmetrics.RecordError(appmodelmetrics.PhaseExportProcess)
				return last, err
			}
		}
	}

	netFlatPack, err := diff.ApplicationModelToNetworkFlat(ctx, networkDiffModel, metadataService)
	if err != nil {
		logger.GetLogger().Error("Failed to decode application model to network telemetry", logfields.Error, err)
		appmodelmetrics.RecordError(appmodelmetrics.PhaseExportNetwork)
		return last, err
	}
	appmodelmetrics.RecordTelemetryEntries(appmodelmetrics.TelemetryNetwork, len(netFlatPack))

	var conns []*graphV1.Connection
	for _, entry := range netFlatPack {
		networkmetrics.Collect(entry)
		if telemetry != nil {
			if err := telemetry.Encode(entry); err != nil {
				logger.GetLogger().Error("Failed to encode network telemetry as JSON", logfields.Error, err)
				appmodelmetrics.RecordError(appmodelmetrics.PhaseExportNetwork)
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
		agentVersion := strings.TrimPrefix(version.Version, "v")
		log := graphV1.ConnectionLog{
			Uuid: uuid.New().String(),
			Emitter: &commonV1.Emitter{
				Name:    "Tetragon",
				Version: agentVersion,
				Observer: &commonV1.Observer{
					Name:       "Tetragon",
					Version:    agentVersion,
					Identifier: observerIdentifier(),
				},
			},
			WindowStart: timestamppb.New(last),
			WindowEnd:   timestamppb.New(now),
			Connections: conns,
		}
		if err := connection.Encode(&log); err != nil {
			logger.GetLogger().Warn("Failed to encode connection log as JSON", logfields.Error, err)
			appmodelmetrics.RecordError(appmodelmetrics.PhaseExportNetwork)
		}
	}
	return now, nil
}

// observerIdentifier returns the identifier for this observer instance,
// following the Hubble "cluster/node" convention. When no cluster name is
// configured it falls back to the bare node name, mirroring the flow export
// path in pkg/encoder/json_encoder.go.
func observerIdentifier() string {
	nodeName := node.GetNodeNameForExport()
	if cluster := option.Config.ClusterName; cluster != "" {
		return fmt.Sprintf("%s/%s", cluster, nodeName)
	}
	return nodeName
}

// countEntities tallies all entity kinds in an application model. It is a pure
// function: no metrics side effects, which makes it independently unit-testable.
func countEntities(am *appModelV1.ApplicationModel) map[appmodelmetrics.EntityKind]int {
	counts := map[appmodelmetrics.EntityKind]int{
		appmodelmetrics.EntityNamespace: len(am.GetNamespaces()),
	}
	for _, ns := range am.GetNamespaces() {
		counts[appmodelmetrics.EntityWorkload] += len(ns.GetWorkloads())
		for _, wl := range ns.GetWorkloads() {
			counts[appmodelmetrics.EntityContainer] += len(wl.GetContainers())
			for _, c := range wl.GetContainers() {
				for _, pg := range c.GetProcesses() {
					counts[appmodelmetrics.EntityProcess]++
					counts[appmodelmetrics.EntityConnection] += len(pg.GetConnections())
				}
			}
		}
	}
	// Count host-namespace processes (not part of any namespace/workload)
	for _, pg := range am.GetHost().GetProcesses() {
		counts[appmodelmetrics.EntityProcess]++
		counts[appmodelmetrics.EntityConnection] += len(pg.GetConnections())
	}
	return counts
}

// isSizeLimitError reports whether err is lumberjack rejecting a write larger
// than the configured maximum file size. Lumberjack returns a plain fmt.Errorf
// with no sentinel or typed error, so a substring match on its stable message
// is the only way to detect this case.
func isSizeLimitError(err error) bool {
	return err != nil && strings.Contains(err.Error(), "exceeds maximum file size")
}

// logAppModelEncodeError logs a failed application model encode. When the
// failure is the export file size limit, it appends an actionable remedy naming
// the levers the operator can pull; other errors are logged as-is to avoid
// misdirecting the reader.
func logAppModelEncodeError(err error, msg, sizeLimitHint string) {
	if isSizeLimitError(err) {
		msg = msg + "; " + sizeLimitHint
	}
	logger.GetLogger().Error(msg, logfields.Error, err)
	appmodelmetrics.RecordError(appmodelmetrics.PhaseExportAppModel)
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
	nodeLabels map[string]string,
	metadataService local.MetadataService,
) (*appModelV1.ApplicationModelEvent, time.Time) {
	convStart := time.Now()
	newModel, processData := model.ProcessModelToApplicationModelWithProcessData(processModels, emptyFilter, nodeLabels)
	appmodelmetrics.RecordDuration(appmodelmetrics.PhaseConversion, float64(time.Since(convStart).Microseconds()))

	telemetryMap := model.BuildTelemetryMap(processData)

	// Count entities from the converted model
	if am := newModel.GetApplicationModel(); am != nil {
		for kind, count := range countEntities(am) {
			appmodelmetrics.SetEntities(kind, count)
		}
	}

	if appModelEncoder != nil {
		if enterpriseOption.Config.ApplicationModelExportFragments {
			fragments := model.SplitApplicationModelEvent(newModel)
			for _, fragment := range fragments {
				if err := appModelEncoder.Encode(fragment); err != nil {
					logAppModelEncodeError(err, "Failed to encode application model fragment as JSON",
						"raise application-model-export-file-max-size-mb or lower application-model-split-max-host-processes")
				}
			}
		} else {
			if err := appModelEncoder.Encode(newModel); err != nil {
				logAppModelEncodeError(err, "Failed to encode application model as JSON",
					"raise application-model-export-file-max-size-mb or set application-model-export-fragments=true")
			}
		}
	}

	if telemetryEncoder != nil || connectionEncoder != nil {
		exportStart := time.Now()
		lastTime, _ = exportTelemetry(ctx, lastTime, telemetryEncoder, connectionEncoder,
			newModel.ApplicationModel, lastModel.ApplicationModel, telemetryMap, metadataService)
		appmodelmetrics.RecordDuration(appmodelmetrics.PhaseExport, float64(time.Since(exportStart).Microseconds()))
		lastModel = newModel
	}

	return lastModel, lastTime
}

func ExportApplicationModel(ctx context.Context, server *Server, writer io.Writer, flatWriter io.Writer, connectionWriter io.Writer, interval time.Duration) {
	var encoder *json.Encoder
	var telemetry *json.Encoder
	var connection *json.Encoder
	metadataService, err := local.GetMetadataService()
	if err != nil {
		logger.GetLogger().Warn("Failed to get metadata service. Node labels will be incomplete", logfields.Error, err)
		metadataService = &local.NoopMetadataService{}
	}

	lastTime := time.Now()

	res, err := server.GetProcessModel(ctx, []string{}, false)
	if err != nil {
		if errors.Is(err, ErrApplicationModelNotEnabled) {
			logger.GetLogger().Info("Application Model not enabled", logfields.Error, err)
			return
		}
		// Transient error (e.g. BPF maps not yet pinned): log and start with an
		// empty baseline so the ticker loop can produce a full diff on its first
		// successful tick.
		logger.GetLogger().Warn("Failed to get initial process model, starting with empty baseline", logfields.Error, err)
		res = nil
	}
	emptyFilter := make(map[string]bool)
	lastModel, _ := model.ProcessModelToApplicationModelWithProcessData(res, emptyFilter, server.GetNodeLabels(ctx))

	if writer != nil {
		encoder = json.NewEncoder(writer)
	}

	// *Writer is an interface so we can't nil check it and we drop back to
	// the enterprise option the source of truth. Although its annoying for
	// CI.
	if enterpriseOption.Config.TelemetryExportFilename != "" {
		telemetry = json.NewEncoder(appmodelmetrics.NewExportedBytesCounterWriter(flatWriter))
	}

	if enterpriseOption.Config.ConnectionLogFileName != "" {
		connection = json.NewEncoder(connectionWriter)
	}

	ticker := time.NewTicker(interval)
	logger.GetLogger().Info("Exporting process model", "interval", interval)
	for {
		select {
		case <-ticker.C:
			tickStart := time.Now()

			res, err := server.GetProcessModel(ctx, []string{}, false)
			if err != nil {
				logger.GetLogger().Error("Failed to get process model from Tetragon", logfields.Error, err)
				appmodelmetrics.RecordError(appmodelmetrics.PhaseGetProcessModel)
				continue
			}

			appmodelmetrics.RecordExport()

			var appModelEncoder *json.Encoder
			if enterpriseOption.Config.ApplicationModelExportFilename != "" {
				appModelEncoder = encoder
			}

			lastModel, lastTime = exportTick(ctx, res, appModelEncoder, telemetry, connection, lastModel, lastTime, emptyFilter, server.GetNodeLabels(ctx), metadataService)
			appmodelmetrics.RecordDuration(appmodelmetrics.PhaseExportTick, float64(time.Since(tickStart).Microseconds()))
		case <-ctx.Done():
			return
		}
	}
}

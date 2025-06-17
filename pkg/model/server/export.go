//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package server

import (
	"context"
	"encoding/json"
	"io"
	"time"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/isovalent/hubble-fgs/pkg/metrics/networkmetrics"
	"github.com/isovalent/hubble-fgs/pkg/model"
	"github.com/isovalent/hubble-fgs/pkg/model/diff"
	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"
	appModelV1 "github.com/isovalent/ipa/application_model/v1alpha"
	graphV1 "github.com/isovalent/ipa/graph/v1alpha"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func ExportApplicationModel(ctx context.Context, server *Server, writer io.Writer, flatWriter io.Writer, connectionWriter io.Writer, interval time.Duration) {
	startTime := time.Now()
	var encoder *json.Encoder
	var flatEncoder *json.Encoder
	var connectionEncoder *json.Encoder

	isDiffModel := enterpriseOption.Config.ApplicationModelDiffExportFilename != "" || enterpriseOption.Config.ApplicationModelEnableDiff

	res, err := server.GetProcessModel(ctx, []string{}, false)
	if err != nil {
		logger.GetLogger().WithError(err).Error("Failed to get process model from Tetragon")
		return
	}
	emptyFilter := make(map[string]bool)
	lastModel := model.ProcessModelToApplicationModel(res, emptyFilter)

	if writer != nil {
		encoder = json.NewEncoder(writer)
	}

	if flatWriter != nil {
		flatEncoder = json.NewEncoder(flatWriter)
	}

	if connectionWriter != nil {
		connectionEncoder = json.NewEncoder(connectionWriter)
	}

	ticker := time.NewTicker(interval)
	logger.GetLogger().WithField("interval", interval).Info("Exporting process model")
	for {
		var networkDiffModel, processDiffModel *appModelV1.ApplicationModel

		select {
		case <-ticker.C:
			res, err := server.GetProcessModel(ctx, []string{}, false)
			if err != nil {
				logger.GetLogger().WithError(err).Error("Failed to get process model from Tetragon")
				return
			}

			newModel := model.ProcessModelToApplicationModel(res, emptyFilter)
			if isDiffModel {
				networkDiffModel, processDiffModel, err = diff.ApplicationModelDiff(newModel.ApplicationModel, lastModel.ApplicationModel)
				if err != nil {
					logger.GetLogger().WithError(err).Error("Failed to produce application model difference as JSON")
					return
				}

				// If nothing has changed do not update last model and skip writing empty record
				if networkDiffModel == nil && processDiffModel == nil {
					continue
				}
				lastModel = newModel
			}

			if enterpriseOption.Config.ApplicationModelExportFilename != "" {
				if err := encoder.Encode(newModel); err != nil {
					logger.GetLogger().WithError(err).Error("Failed to encode application model as JSON")
					return
				}
			}

			if enterpriseOption.Config.ApplicationModelDiffExportFilename != "" {
				procFlatPack, err := diff.ApplicationModelToProcessFlat(ctx, processDiffModel)
				if err != nil {
					logger.GetLogger().WithError(err).Error("Failed to decode application model to slim process model")
					return
				}
				for _, entry := range procFlatPack {
					if err := flatEncoder.Encode(entry); err != nil {
						logger.GetLogger().WithError(err).Error("Failed to encode slim process application model as JSON")
						return
					}
				}

				netFlatPack, err := diff.ApplicationModelToNetworkFlat(ctx, networkDiffModel)
				if err != nil {
					logger.GetLogger().WithError(err).Error("Failed to decode application model to slim network model")
					return
				}

				var conns []*graphV1.Connection
				for _, entry := range netFlatPack {
					networkmetrics.Collect(entry)
					if err := flatEncoder.Encode(entry); err != nil {
						logger.GetLogger().WithError(err).Error("Failed to encode slim application model as JSON")
						return
					}
					conn := diff.TelemetryToConnection(entry)
					if conn != nil {
						conns = append(conns, conn)
					}
				}
				if connectionEncoder != nil && len(conns) > 0 {
					endTime := time.Now()
					log := graphV1.ConnectionLog{
						Emitter:     graphV1.Emitter_EMITTER_TETRAGON,
						WindowStart: timestamppb.New(startTime),
						WindowEnd:   timestamppb.New(endTime),
						Connections: conns,
					}
					if err := connectionEncoder.Encode(&log); err != nil {
						logger.GetLogger().WithError(err).Warn("Failed to encode connection log as JSON")
					}
					startTime = endTime
				}
			}
		case <-ctx.Done():
			return
		}
	}
}

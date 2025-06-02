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

	appModelV1 "github.com/isovalent/ipa/application_model/v1alpha"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/isovalent/hubble-fgs/pkg/model"
	"github.com/isovalent/hubble-fgs/pkg/model/diff"
	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"
)

func ExportApplicationModel(ctx context.Context, server *Server, writer io.Writer, flatWriter io.Writer, interval time.Duration) {
	var encoder *json.Encoder
	var flatEncoder *json.Encoder

	isDiffModel := enterpriseOption.Config.ApplicationModelDiffExportFilename != "" || enterpriseOption.Config.ApplicationModelEnableDiff

	res, err := server.GetProcessModel(ctx, &tetragon.GetProcessModelRequest{})
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

	ticker := time.NewTicker(interval)
	logger.GetLogger().WithField("interval", interval).Info("Exporting process model")
	for {
		var diffModel *appModelV1.ApplicationModel

		select {
		case <-ticker.C:
			res, err := server.GetProcessModel(ctx, &tetragon.GetProcessModelRequest{})
			if err != nil {
				logger.GetLogger().WithError(err).Error("Failed to get process model from Tetragon")
				return
			}

			newModel := model.ProcessModelToApplicationModel(res, emptyFilter)
			if isDiffModel {
				diffModel, err = diff.ApplicationModelDiff(newModel.ApplicationModel, lastModel.ApplicationModel)
				if err != nil {
					logger.GetLogger().WithError(err).Error("Failed to produce application model difference as JSON")
					return
				}

				// If nothing has changed do not update last model and skip writing empty record
				if diffModel == nil {
					continue
				}
				lastModel = newModel
			}

			if enterpriseOption.Config.ApplicationModelEnableDiff {
				diffModelEvent := &appModelV1.ApplicationModelEvent{
					ClusterName:      lastModel.ClusterName,
					NodeName:         lastModel.NodeName,
					Time:             lastModel.Time,
					ApplicationModel: diffModel,
				}
				if err := encoder.Encode(diffModelEvent); err != nil {
					logger.GetLogger().WithError(err).Error("Failed to encode application model difference as JSON")
					return
				}
			} else {
				if err := encoder.Encode(newModel); err != nil {
					logger.GetLogger().WithError(err).Error("Failed to encode application model as JSON")
					return
				}
			}

			if enterpriseOption.Config.ApplicationModelDiffExportFilename != "" {
				netFlatPack, err := diff.ApplicationModelToNetworkFlat(ctx, diffModel)
				if err != nil {
					logger.GetLogger().WithError(err).Error("Failed to decode application model to slim model")
					return
				}
				for _, entry := range netFlatPack {
					if err := flatEncoder.Encode(entry); err != nil {
						logger.GetLogger().WithError(err).Error("Failed to encode slim application model as JSON")
						return
					}
				}
			}
		case <-ctx.Done():
			return
		}
	}
}

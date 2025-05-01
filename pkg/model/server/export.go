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
)

func ExportApplicationModel(ctx context.Context, server *Server, writer io.Writer, interval time.Duration) {
	encoder := json.NewEncoder(writer)
	ticker := time.NewTicker(interval)
	logger.GetLogger().WithField("interval", interval).Info("Exporting process model")
	for {
		select {
		case <-ticker.C:
			res, err := server.GetProcessModel(ctx, &tetragon.GetProcessModelRequest{})
			if err != nil {
				logger.GetLogger().WithError(err).Error("Failed to get process model from Tetragon")
				return
			}
			appModel := model.ProcessModelToApplicationModel(res)
			if err := encoder.Encode(appModel); err != nil {
				logger.GetLogger().WithError(err).Error("Failed to encode application model as JSON")
				return
			}
		case <-ctx.Done():
			return
		}
	}
}

func ExportApplicationModelDiff(ctx context.Context, server *Server, writer io.Writer, interval time.Duration) {
	res, err := server.GetProcessModel(ctx, &tetragon.GetProcessModelRequest{})
	if err != nil {
		logger.GetLogger().WithError(err).Error("Failed to get process model from Tetragon")
		return
	}
	lastModel := model.ProcessModelToApplicationModel(res)
	encoder := json.NewEncoder(writer)
	ticker := time.NewTicker(interval)
	logger.GetLogger().WithField("interval", interval).Info("Exporting application difference model")
	for {
		select {
		case <-ticker.C:
			res, err := server.GetProcessModel(ctx, &tetragon.GetProcessModelRequest{})
			if err != nil {
				logger.GetLogger().WithError(err).Error("Failed to get process model from Tetragon")
				return
			}
			newModel := model.ProcessModelToApplicationModel(res)
			diffModel, err := diff.ApplicationModelDiff(newModel.ApplicationModel, lastModel.ApplicationModel)
			if err != nil {
				logger.GetLogger().WithError(err).Error("Failed to produce application model difference as JSON")
				return
			}

			lastModel = newModel
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
		case <-ctx.Done():
			return
		}
	}
}

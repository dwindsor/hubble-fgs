//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package model

import (
	"context"
	"encoding/json"
	"io"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/logger"
)

func ExportProcessModel(ctx context.Context, server *Server, writer io.Writer, interval time.Duration) {
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
			appModel := ProcessModelToApplicationModel(res)
			if err := encoder.Encode(appModel); err != nil {
				logger.GetLogger().WithError(err).Error("Failed to encode application model as JSON")
				return
			}
		case <-ctx.Done():
			return
		}
	}
}

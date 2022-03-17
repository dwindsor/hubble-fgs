// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package getevents

import (
	"context"
	"encoding/json"
	"errors"
	"os"

	"github.com/isovalent/hubble-fgs/api/v1/fgs"
	"github.com/isovalent/hubble-fgs/cmd/hubble-enterprise/common"
	"github.com/isovalent/hubble-fgs/pkg/logger"
	"github.com/spf13/cobra"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func getEvents(ctx context.Context, client fgs.FineGuidanceSensorsClient) {
	stream, err := client.GetEvents(ctx, &fgs.GetEventsRequest{})
	if err != nil {
		logger.GetLogger().WithError(err).Fatal("Failed to call GetEvents")
	}
	encoder := json.NewEncoder(os.Stdout)
	for {
		res, err := stream.Recv()
		if err != nil {
			if !errors.Is(err, context.Canceled) && status.Code(err) != codes.Canceled {
				logger.GetLogger().WithError(err).Fatal("Failed to receive events")
			}
			return
		}
		if err = encoder.Encode(res); err != nil {
			logger.GetLogger().WithError(err).Fatal("Failed to encode event")
		}
	}
}

func New() *cobra.Command {
	return &cobra.Command{
		Use:   "getevents",
		Short: "Print events",
		Run: func(cmd *cobra.Command, args []string) {
			common.CliRun(getEvents)
		},
	}

}

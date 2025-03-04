// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package mandate

import (
	"context"
	"fmt"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/cmd/tetra/common"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func statusCmd() *cobra.Command {
	return &cobra.Command{
		Use:          "status",
		Short:        "mandate status",
		Long:         "retrieve mandate status from the tetragon agent",
		Args:         cobra.ExactArgs(0),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := context.WithTimeout(context.Background(), common.Timeout)
			defer cancel()

			conn, err := grpc.NewClient(common.ResolveServerAddress(),
				grpc.WithTransportCredentials(insecure.NewCredentials()),
				grpc.WithMaxCallAttempts(common.Retries+1), // maxAttempt includes the first call
			)
			if err != nil {
				return err
			}
			defer conn.Close()

			client := tetragon.NewMandateServiceClient(conn)
			res, err := client.GetMandateStatus(ctx, &tetragon.GetMandateStatusReq{})
			if err != nil || res == nil {
				return fmt.Errorf("failed to retrieve mandate status: %w", err)
			}

			b, err := res.MarshalJSON()
			if err != nil {
				return fmt.Errorf("failed to generate json: %w", err)
			}
			cmd.Println(string(b))
			return nil
		},
	}

}

func New() *cobra.Command {
	ret := &cobra.Command{
		Use:   "mandate",
		Short: "mandate utilities",
	}

	ret.AddCommand(
		statusCmd(),
	)

	return ret
}

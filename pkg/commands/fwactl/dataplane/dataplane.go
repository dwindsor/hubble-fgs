// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package dataplane

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/isovalent/hubble-fgs/pkg/commands/fwactl"
	"github.com/isovalent/hubble-fgs/pkg/dpu"
)

const PdsGrpcAddr = "localhost:11357"

var (
	API_PATH string
	DpuAgent *dpu.DPUAgent
)

var (
	GrpcConn *grpc.ClientConn
)

func InitGrpcPdsConnection() error {
	opts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	conn, err := grpc.NewClient(PdsGrpcAddr, opts...)
	if err != nil {
		return fmt.Errorf("failed to connect: %v", err)
	}
	GrpcConn = conn
	return nil
}

// dataplaneCmd represents the dataplane command
var DataplaneCmd = &cobra.Command{
	Use:          "dataplane",
	SilenceUsage: true,
	Aliases:      []string{"dp"},
	Short:        "Send commands to a dataplane",
	Long:         `Used to send commands directly to the dataplane.`,
	PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		DpuAgent = dpu.NewDPUAgent("")
		err := DpuAgent.Config(ctx, fwactl.CONFIG, fwactl.DP_SOCKET_PATH, true, true)
		if err != nil {
			return err
		}

		// Initializing dataplane object
		API_PATH = DpuAgent.Cfg.Dataplane.CliSockFile
		return nil
	},
}

func init() {
	fwactl.RootCmd.AddCommand(DataplaneCmd)
}

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
	"os"

	"github.com/cilium/tetragon/cmd/tetra/common"

	"github.com/cilium/tetragon/api/v1/tetragon"

	"github.com/isovalent/hubble-fgs/cmd/tetra/alertrule"
	eecommon "github.com/isovalent/hubble-fgs/cmd/tetra/common"
	"github.com/isovalent/hubble-fgs/pkg/mandate"
	"github.com/isovalent/hubble-fgs/pkg/mandate/cli"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func statusCmd() *cobra.Command {
	var output string
	var attemptsLog bool
	var printAll bool
	ret := &cobra.Command{
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

			switch output {
			case "json":
				b, err := res.MarshalJSON()
				if err != nil {
					return fmt.Errorf("failed to generate json: %w", err)
				}
				cmd.Println(string(b))

			case "text":
				cnf := cli.PrintConfig{
					AttemptsLog: attemptsLog,
					PrintAll:    printAll,
				}
				cli.Print(os.Stdout, res, cnf)
			}

			if res.LoadedMandate != nil {
				if output == "text" {
					fmt.Printf("policies:\n")
				}
				eecommon.ListPolicies(cmd, output, mandate.OrigPolName)
				if output == "text" {
					fmt.Printf("alerts:\n")
				}
				alertrule.ListAlerts(cmd, output, mandate.OrigAlertName)
			}

			return nil
		},
	}

	flags := ret.Flags()
	flags.StringVarP(&output, "output", "o", "text", "Specify the output format: text|json")
	flags.BoolVar(&attemptsLog, "attempts-log", false, "Print attempts log")
	flags.BoolVar(&printAll, "print-all", false, "Print all entries in the attempts log")
	return ret

}

func refreshCmd() *cobra.Command {
	ret := &cobra.Command{
		Use:          "refresh",
		Short:        "refresh mandate",
		Long:         "instruct tetragon agent to refresh the mandate URL",
		Args:         cobra.ExactArgs(0),
		SilenceUsage: true,
		RunE: func(_ *cobra.Command, _ []string) error {
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
			res, err := client.MandateConfigure(ctx, &tetragon.MandateConfigureReq{
				Refresh: true,
			})
			if err != nil || res == nil {
				return fmt.Errorf("failed to refresh: %w", err)
			}
			return nil
		},
	}
	return ret
}

func setURLCmd() *cobra.Command {
	var refresh bool
	ret := &cobra.Command{
		Use:          "set-url",
		Short:        "set the mandate URL",
		Long:         "modify the mandate URL in the Tetragon agent",
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(_ *cobra.Command, args []string) error {
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

			url := args[0]
			client := tetragon.NewMandateServiceClient(conn)
			res, err := client.MandateConfigure(ctx, &tetragon.MandateConfigureReq{
				Url:     &url,
				Refresh: refresh,
			})
			if err != nil || res == nil {
				return fmt.Errorf("failed to set URL: %w", err)
			}
			return nil
		},
	}
	flags := ret.Flags()
	flags.BoolVarP(&refresh, "refresh", "r", true, "refresh after setting new mandate URL")
	return ret
}

func New() *cobra.Command {
	ret := &cobra.Command{
		Use:   "mandate",
		Short: "mandate utilities",
	}

	ret.AddCommand(
		statusCmd(),
		refreshCmd(),
		setURLCmd(),
	)

	return ret
}

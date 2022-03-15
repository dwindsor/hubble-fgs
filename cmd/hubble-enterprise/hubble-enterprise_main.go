package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"

	"github.com/isovalent/hubble-fgs/api/v1/fgs"
	"github.com/isovalent/hubble-fgs/cmd/hubble-enterprise/bugtool"
	"github.com/isovalent/hubble-fgs/cmd/hubble-enterprise/common"
	"github.com/isovalent/hubble-fgs/cmd/hubble-enterprise/sensors"
	"github.com/isovalent/hubble-fgs/cmd/hubble-enterprise/stacktracetree"
	"github.com/isovalent/hubble-fgs/cmd/hubble-enterprise/tracingpolicy"
	"github.com/isovalent/hubble-fgs/cmd/hubble-enterprise/version"
	"github.com/isovalent/hubble-fgs/pkg/logger"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/sys/unix"
)

var (
	rootCmd *cobra.Command
)

func getStatus(client fgs.FineGuidanceSensorsClient) {
	response, err := client.GetHealth(context.Background(), &fgs.GetHealthStatusRequest{})
	if err != nil {
		fmt.Printf("status error: %s\n", err)
		return
	}
	fmt.Printf("Health Status: %s\n", response.GetHealthStatus()[0].Details)
}

func getEvents(client fgs.FineGuidanceSensorsClient) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, unix.SIGINT, unix.SIGTERM)
		select {
		case <-sigs:
		case <-ctx.Done():
			signal.Stop(sigs)
		}
		cancel()
	}()
	stream, err := client.GetEvents(ctx, &fgs.GetEventsRequest{})
	if err != nil {
		logger.GetLogger().WithError(err).Fatal("Failed to call GetEvents")
	}
	encoder := json.NewEncoder(os.Stdout)
	for {
		res, err := stream.Recv()
		if err != nil {
			logger.GetLogger().WithError(err).Fatal("Failed to receive events")
		}
		if err = encoder.Encode(res); err != nil {
			logger.GetLogger().WithError(err).Fatal("Failed to encode event")
		}
	}
}

func init() {
	rootCmd = &cobra.Command{
		Use:   "hubble-enterprise",
		Short: "Hubble Enterprise CLI",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Help()
		},
	}

	getEventsCmd := &cobra.Command{
		Use:   "getevents",
		Short: "Print events",
		Run: func(cmd *cobra.Command, args []string) {
			common.CliRun(getEvents)
		},
	}

	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "Print health status",
		Run: func(cmd *cobra.Command, args []string) {
			common.CliRun(getStatus)
		},
	}

	rootCmd.AddCommand(getEventsCmd)
	rootCmd.AddCommand(statusCmd)
	rootCmd.AddCommand(bugtool.New())
	rootCmd.AddCommand(sensors.New())
	rootCmd.AddCommand(stacktracetree.New())
	rootCmd.AddCommand(tracingpolicy.New())
	rootCmd.AddCommand(version.New())

	flags := rootCmd.PersistentFlags()
	flags.BoolP(common.KeyDebug, "d", true, "Enable debug messages")
	flags.String(common.KeyServerAddress, "localhost:54321", "gRPC server address")
	viper.BindPFlags(flags)

}

func hubbleEnterpriseMain() {
	rootCmd.Execute()
}

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/isovalent/hubble-fgs/api/v1/fgs"
	"github.com/isovalent/hubble-fgs/pkg/logger"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
)

var (
	serverAddress string

	rootCmd *cobra.Command
)

func cliRunErr(fn func(cli fgs.FineGuidanceSensorsClient), fnErr func(err error)) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := grpc.DialContext(ctx, serverAddress, grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		fnErr(err)
		logger.GetLogger().WithError(err).Fatal("Failed to connect")
	}
	defer conn.Close()
	client := fgs.NewFineGuidanceSensorsClient(conn)
	fn(client)
}

func cliRun(fn func(cli fgs.FineGuidanceSensorsClient)) {
	cliRunErr(fn, func(_ error) {})
}

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
			cliRun(getEvents)
		},
	}

	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "Print health status",
		Run: func(cmd *cobra.Command, args []string) {
			cliRun(getStatus)
		},
	}

	rootCmd.AddCommand(getEventsCmd)
	rootCmd.AddCommand(statusCmd)
	initBugtoolCmd()

	flags := rootCmd.PersistentFlags()
	flags.BoolP("debug", "d", true, "Enable debug messages")
	flags.StringVar(&serverAddress, "server-address", "localhost:54321", "gRPC server address")
	viper.BindPFlags(flags)

}

func hubbleEnterpriseMain() {
	rootCmd.Execute()
}

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/covalentio/hubble-fgs/api/v1/fgs"
	"github.com/covalentio/hubble-fgs/pkg/logger"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
)

var (
	observerDir   = "/sys/fs/bpf/tcpmon/"
	serverAddress string
	status        bool

	cmd *cobra.Command
)

func hubbleFGSPrinter() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := grpc.DialContext(ctx, serverAddress, grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		logger.GetLogger().WithError(err).Fatal("Failed to connect")
	}
	defer conn.Close()
	client := fgs.NewFineGuidanceSensorsClient(conn)
	if status {
		getStatus(client)
	} else {
		getEvents(client)
	}
}

func getStatus(client fgs.FineGuidanceSensorsClient) {
	ctx, _ := context.WithCancel(context.Background())
	response, err := client.GetHealth(ctx, &fgs.GetHealthStatusRequest{})
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
	cmd = &cobra.Command{
		Use:   "hubble-fgs-printer",
		Short: "Hubble FGS",
		Run: func(cmd *cobra.Command, args []string) {
			hubbleFGSPrinter()
		},
	}

	flags := cmd.PersistentFlags()
	flags.BoolP("debug", "d", true, "Enable debug messages")
	flags.StringVar(&serverAddress, "server-address", "localhost:54321", "gRPC server address")
	flags.BoolVar(&status, "status", false, "Print health status")
	viper.BindPFlags(flags)
}

func hubbleFGSMainPrinter() {
	cmd.Execute()
}

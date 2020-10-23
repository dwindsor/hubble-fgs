package main

import (
	"context"
	"fmt"

	"github.com/covalentio/hubble-fgs/api/v1/fgs"

	"github.com/spf13/cobra"
)

func init() {
	sensorsCmd := &cobra.Command{
		Use:   "sensors",
		Short: "Manage sensors",
	}

	sensorsListCmd := &cobra.Command{
		Use:   "list",
		Short: "List available sensors",
		Run: func(cmd *cobra.Command, args []string) {
			cliRun(listSensors)
		},
	}

	sensorsCmd.AddCommand(sensorsListCmd)
	rootCmd.AddCommand(sensorsCmd)
}

func listSensors(client fgs.FineGuidanceSensorsClient) {
	ctx, _ := context.WithCancel(context.Background())
	sensors, err := client.ListSensors(ctx, &fgs.ListSensorsRequest{})
	if err != nil {
		fmt.Printf("error: %s\n", err)
		return
	} else if sensors == nil {
		fmt.Printf("Unexpected error\n")
	}

	for _, sensor := range sensors.Sensors {
		enabled := ""
		if sensor.Enabled {
			enabled = "(enabled)"
		} else {
			enabled = "(not enabled)"
		}
		fmt.Printf("%s %s\n", sensor.Name, enabled)
	}
}

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

	sensorEnableCmd := &cobra.Command{
		Use:   "enable",
		Short: "Enable sensor",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			sensor := args[0]
			cliRun(func(cli fgs.FineGuidanceSensorsClient) {
				enableSensor(cli, sensor)
			})
		},
	}

	sensorDisableCmd := &cobra.Command{
		Use:   "disable",
		Short: "Disable sensor",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			sensor := args[0]
			cliRun(func(cli fgs.FineGuidanceSensorsClient) {
				disableSensor(cli, sensor)
			})
		},
	}

	sensorsCmd.AddCommand(sensorsListCmd)
	sensorsCmd.AddCommand(sensorEnableCmd)
	sensorsCmd.AddCommand(sensorDisableCmd)
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

func enableSensor(client fgs.FineGuidanceSensorsClient, sensor string) {
	ctx, _ := context.WithCancel(context.Background())
	_, err := client.EnableSensor(ctx, &fgs.EnableSensorRequest{Name: sensor})
	if err == nil {
		fmt.Printf("sensor %s enabled\n", sensor)
	} else {
		fmt.Printf("failed to enable sensor %s: %s\n", sensor, err)
	}
}

func disableSensor(client fgs.FineGuidanceSensorsClient, sensor string) {
	ctx, _ := context.WithCancel(context.Background())
	_, err := client.DisableSensor(ctx, &fgs.DisableSensorRequest{Name: sensor})
	if err == nil {
		fmt.Printf("sensor %s disabled\n", sensor)
	} else {
		fmt.Printf("failed to disable sensor %s: %s\n", sensor, err)
	}
}

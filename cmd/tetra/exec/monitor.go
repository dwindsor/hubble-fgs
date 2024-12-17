// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package exec

import (
	"fmt"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/cmd/tetra/common"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/isovalent/hubble-fgs/pkg/model"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func monitor(interval time.Duration, namespaces []string) error {
	c := NewConnectedModelClient()
	defer c.Close()

	res, err := getProcessModel(c, &tetragon.GetProcessModelRequest{
		Namespaces: namespaces,
		Debug:      common.Debug,
	})
	if err != nil {
		logger.GetLogger().WithError(err).Error("Failed to retrieve events from Tetragon")
		return err
	}
	currentData, _, _ := model.ConvertToMonitorData(res, false)

	ticker := time.NewTicker(interval)
	for {
		select {
		case <-ticker.C:
			res, err := getProcessModel(c, &tetragon.GetProcessModelRequest{Namespaces: namespaces})
			if err != nil {
				logger.GetLogger().WithError(err).Error("Failed to retrieve events from Tetragon")
				return err
			}
			newData, quota, _ := model.ConvertToMonitorData(res, false)
			diff := model.Diff(currentData, newData)
			quota.Print()
			diff.Print()
			currentData = newData
		case <-c.Ctx.Done():
			fmt.Print("\r")
			return nil
		}
	}
}

func NewMonitor() *cobra.Command {
	ret := &cobra.Command{
		Use:    "monitor",
		Short:  "Periodically monitor events and statistics collected by Tetragon",
		Hidden: true, // Still under development. Keep it hidden.
		RunE: func(_ *cobra.Command, _ []string) error {
			interval := viper.GetDuration("interval")
			namespaces := viper.GetStringSlice("namespaces")
			if viper.GetBool("host") {
				namespaces = append(namespaces, model.HostNamespace)
			}
			return monitor(interval, namespaces)
		},
	}

	flags := ret.Flags()
	flags.DurationP("interval", "i", 5*time.Second, "Monitor interval")
	flags.StringSliceP("namespaces", "n", nil, "Monitor processes in specific namespaces")
	flags.Bool("host", false, "Monitor host processes")

	viper.BindPFlags(flags)
	return ret
}

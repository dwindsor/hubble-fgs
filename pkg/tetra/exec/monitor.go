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
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	appModelV1 "github.com/isovalent/ipa/application_model/v1alpha"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/cilium/tetragon/api/v1/tetragon"

	"github.com/isovalent/hubble-fgs/pkg/encoder"
	"github.com/isovalent/hubble-fgs/pkg/model"
)

func monitor(namespaces []string, host bool) error {
	var buf bytes.Buffer
	compactEncoder := encoder.NewEnterpriseEncoder(&buf, "always", true)

	c, err := NewApplicationModelClient(context.Background())
	if err != nil {
		return err
	}
	defer c.Close()
	req := &appModelV1.StreamTelemetryRequest{
		Namespaces: namespaces,
		Host:       host,
	}

	stream, err := c.Client.StreamTelemetry(c.Ctx, req)
	if err != nil {
		logger.GetLogger().Error("failed streaming model request", logfields.Error, err)
		return err
	}

	for {
		select {
		case <-c.Ctx.Done():
			return nil
		default:
			res, err := stream.Recv()
			if err != nil {
				return nil
			}

			network := res.GetNetworkConnect()
			if network == nil {
				logger.GetLogger().Error("stream received unknown event type")
				return err
			}

			s, err := compactEncoder.AppModelEventToString(network)
			if err != nil {
				return err
			}
			fmt.Println(s)
		}
	}
}

func monitorStdin() error {
	var buf bytes.Buffer
	compactEncoder := encoder.NewEnterpriseEncoder(&buf, "always", true)
	decoder := json.NewDecoder(bufio.NewReader(os.Stdin))
	for {
		newEntry := &appModelV1.NetworkConnectTelemetry{}
		err := decoder.Decode(newEntry)
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		s, err := compactEncoder.AppModelEventToString(newEntry)
		if err != nil {
			return err
		}
		fmt.Println(s)
	}
	return nil
}

func monitorStdinAlerts(_ time.Duration, _ []string) error {
	decoder := json.NewDecoder(bufio.NewReader(os.Stdin))
	for {
		alertSingleton := make(map[string][]*tetragon.Alert, 1)
		alertCount := make(map[string]int)

		alert := &tetragon.Alert{}
		err := decoder.Decode(&alert)
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		if errors.Is(err, io.EOF) {
			continue
		}

		alertSingleton[alert.Rule.Name] = append(alertSingleton[alert.Rule.Name], alert)
		alertCount[alert.Rule.Name]++

		prettyPrintAlert(alertSingleton, alertCount)
	}
}

func NewMonitorAlerts() *cobra.Command {
	var s3 bool
	bucket := ""

	ret := &cobra.Command{
		Use:    "alerts",
		Short:  "Periodically monitor alerts and statistics collected by Tetragon",
		Hidden: true, // Still under development. Keep it hidden.
		RunE: func(_ *cobra.Command, _ []string) error {
			interval := viper.GetDuration("interval")
			namespaces := viper.GetStringSlice("namespaces")
			if viper.GetBool("host") {
				namespaces = append(namespaces, model.HostNamespace)
			}
			// Check if stdin is being piped, if so, monitor application models
			// from stdin instead of connecting to Tetragon gRPC endpoint.
			fi, _ := os.Stdin.Stat()
			if fi.Mode()&os.ModeNamedPipe != 0 {
				return monitorStdinAlerts(interval, namespaces)
			}
			if s3 {
				return s3MonitorAlert(bucket, interval, namespaces)
			}
			return nil
		},
	}

	flags := ret.Flags()
	flags.BoolVarP(&verbose, "verbose", "v", false, "Print all fields when pretty printing")
	flags.BoolVar(&s3, "s3", false, "S3 source")
	flags.StringVar(&bucket, "bucket", "alerts", "S3 bucket source")
	viper.BindPFlags(flags)

	return ret
}

func NewMonitor() *cobra.Command {
	ret := &cobra.Command{
		Use:    "monitor",
		Short:  "Periodically monitor events and statistics collected by Tetragon",
		Hidden: true, // Still under development. Keep it hidden.
		RunE: func(_ *cobra.Command, _ []string) error {
			s3 := viper.GetBool("s3")
			bucket := viper.GetString("bucket")
			interval := viper.GetDuration("interval")
			namespaces := viper.GetStringSlice("namespaces")
			host := viper.GetBool("host")
			if host {
				namespaces = append(namespaces, model.HostNamespace)
			}
			// Check if stdin is being piped, if so, monitor application models
			// from stdin instead of connecting to Tetragon gRPC endpoint.
			fi, _ := os.Stdin.Stat()
			if fi.Mode()&os.ModeNamedPipe != 0 {
				return monitorStdin()
			}
			if s3 {
				return s3Monitor(bucket, interval, namespaces)
			}
			return monitor(namespaces, host)
		},
	}

	ret.AddCommand(NewMonitorAlerts())

	flags := ret.Flags()
	flags.BoolVarP(&verbose, "verbose", "v", false, "Print all fields when pretty printing")
	flags.DurationP("interval", "i", 5*time.Second, "Monitor interval")
	flags.StringSliceP("namespaces", "n", nil, "Monitor processes in specific namespaces")
	flags.Bool("host", false, "Monitor host processes")
	flags.Bool("s3", false, "Monitor S3 source")
	flags.String("bucket", "appmodel", "S3 bucket source")

	viper.BindPFlags(flags)
	return ret
}

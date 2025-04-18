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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/cmd/tetra/common"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/isovalent/hubble-fgs/pkg/model"
	appModelV1 "github.com/isovalent/ipa/application_model/v1alpha"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func s3Monitor(bucket string, interval time.Duration, namespaces []string) error {
	ctx := context.Background()

	sdkConfig, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		fmt.Println("Couldn't load default configuration. Have you set up your AWS account?")
		fmt.Println(err)
		return nil
	}

	s3Client := s3.NewFromConfig(sdkConfig, func(o *s3.Options) {
		o.DisableLogOutputChecksumValidationSkipped = true
	})
	_, err = s3Client.HeadBucket(ctx, &s3.HeadBucketInput{
		Bucket: aws.String(bucket),
	})
	if err != nil {
		fmt.Printf("s3Client bucket lookup error: %s\n", err)
		return err
	}

	lastKey, err := s3GetLastKey(ctx, s3Client, bucket, "")
	if err != nil {
		fmt.Printf("s3GetLastKey failed: %s\n", err)
		return err
	}

	currentModel, err := getS3Model(ctx, s3Client, bucket, lastKey, namespaces)
	if err != nil {
		return err
	}

	ticker := time.NewTicker(interval)
	for range ticker.C {
		key, err := s3GetLastKey(ctx, s3Client, bucket, lastKey)
		if err != nil {
			fmt.Printf("s3GetLastKey error: %s\n", err)
			continue
		}
		// If last key is empty then we failed to find a new object.
		if key == "" {
			continue
		}

		if lastKey != key {
			newModel, err := getS3Model(ctx, s3Client, bucket, lastKey, namespaces)
			if err != nil {
				fmt.Printf("getS3Model error: %s\n", err)
				continue
			}

			currentnmd := model.NetworkMonitorData{}
			currentpmd := model.ProcessMonitorData{}
			newnmd := model.NetworkMonitorData{}
			newpmd := model.ProcessMonitorData{}
			model.ToMonitorData(currentnmd, currentpmd, currentModel.GetApplicationModel())
			model.ToMonitorData(newnmd, newpmd, newModel.GetApplicationModel())

			diffnmd := model.Diff(currentnmd, newnmd)
			diffnmd.Print()

			currentModel = newModel
			lastKey = key
		}
	}
	return nil
}

func monitor(interval time.Duration, namespaces []string) error {
	c := NewConnectedModelClient()
	defer c.Close()

	res, err := getProcessModel(&c, &tetragon.GetProcessModelRequest{
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
			res, err := getProcessModel(&c, &tetragon.GetProcessModelRequest{Namespaces: namespaces})
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

func monitorStdin() error {
	currentModel := &appModelV1.ApplicationModelEvent{}
	decoder := json.NewDecoder(bufio.NewReader(os.Stdin))
	if err := decoder.Decode(currentModel); err != nil {
		return err
	}
	for {
		newModel := &appModelV1.ApplicationModelEvent{}
		err := decoder.Decode(newModel)
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		currentnmd := model.NetworkMonitorData{}
		currentpmd := model.ProcessMonitorData{}
		newnmd := model.NetworkMonitorData{}
		newpmd := model.ProcessMonitorData{}
		model.ToMonitorData(currentnmd, currentpmd, currentModel.GetApplicationModel())
		model.ToMonitorData(newnmd, newpmd, newModel.GetApplicationModel())

		processKeys := slices.Collect(maps.Keys(newpmd))
		slices.SortFunc(processKeys, model.CompareProcessKeys)
		for _, key := range processKeys {
			if _, ok := currentpmd[key]; !ok {
				fmt.Println("🚀", key)
			}
		}

		networkKeys := slices.Collect(maps.Keys(newnmd))
		slices.SortFunc(networkKeys, model.CompareNetworkKeys)
		for _, key := range networkKeys {
			if _, ok := currentnmd[key]; !ok {
				fmt.Println("🔌", key)
			}
		}
		currentModel = newModel
	}
	return nil
}

func s3MonitorAlert(bucket string, interval time.Duration, _ []string) error {
	ctx := context.Background()
	config, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return err
	}
	client := s3.NewFromConfig(config, func(o *s3.Options) {
		o.DisableLogOutputChecksumValidationSkipped = true
	})
	if bucket == "" {
		bucket = DefaultAlertsBucket
	}
	last, err := s3GetLastKey(ctx, client, bucket, "")
	if err != nil {
		return err
	}
	ticker := time.NewTicker(interval)
	for range ticker.C {
		key, err := s3GetLastKey(ctx, client, bucket, last)
		if err != nil {
			continue
		}
		// If last key is empty then we failed to find a new object.
		if key == "" {
			continue
		}

		if last != key {
			alertSingleton, alertCount, err := getS3Alerts(ctx, client, bucket, last)
			if err != nil {
				fmt.Printf("gets3Alerts error: %s", err)
				return err
			}
			prettyPrintAlert(alertSingleton, alertCount)
			last = key
		}
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
			if viper.GetBool("host") {
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
			return monitor(interval, namespaces)
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

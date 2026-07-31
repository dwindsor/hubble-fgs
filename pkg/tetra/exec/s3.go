// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

// The nocloud tag gates the AWS SDK out of the slim tetrabox binary.
//go:build !nocloud

package exec

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	appModelV1 "github.com/isovalent/ipa/application_model/v1alpha"

	"github.com/cilium/tetragon/api/v1/tetragon"

	"github.com/isovalent/hubble-fgs/pkg/model"
)

// newS3Client loads the default AWS configuration and returns an S3 client.
func newS3Client(ctx context.Context) (*s3.Client, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, err
	}
	return s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.DisableLogOutputChecksumValidationSkipped = true
	}), nil
}

// s3FetchAlerts retrieves the latest alerts from the given S3 bucket.
func s3FetchAlerts(bucket string) (map[string][]*tetragon.Alert, map[string]int, error) {
	ctx := context.Background()
	client, err := newS3Client(ctx)
	if err != nil {
		return nil, nil, err
	}
	if bucket == "" {
		bucket = DefaultAlertsBucket
	}
	last, err := s3GetLastKey(ctx, client, bucket, "")
	if err != nil {
		return nil, nil, err
	}
	return getS3Alerts(ctx, client, bucket, last)
}

// s3FetchAppModel retrieves the latest application model from the given S3 bucket.
func s3FetchAppModel(bucket string, namespaces []string) (*appModelV1.ApplicationModelEvent, error) {
	ctx := context.Background()
	client, err := newS3Client(ctx)
	if err != nil {
		return nil, err
	}
	last, err := s3GetLastKey(ctx, client, bucket, "")
	if err != nil {
		return nil, err
	}
	return getS3Model(ctx, client, bucket, last, namespaces)
}

func getS3Alerts(ctx context.Context, s3Client *s3.Client, bucket, lastKey string) (map[string][]*tetragon.Alert, map[string]int, error) {
	alertBin := make(map[string][]*tetragon.Alert)
	alertCount := make(map[string]int)

	result, err := s3Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(lastKey),
	})
	if err != nil {
		return alertBin, alertCount, fmt.Errorf("getObject error: %w", err)
	}
	body, err := io.ReadAll(result.Body)
	if err != nil {
		return alertBin, alertCount, fmt.Errorf("object ReadAll error: %w", err)
	}
	reader := bytes.NewReader(body)
	gzreader, err := gzip.NewReader(reader)
	if err != nil {
		return alertBin, alertCount, fmt.Errorf("gzip reader error: %w", err)
	}
	data, err := io.ReadAll(gzreader)
	if err != nil {
		return alertBin, alertCount, fmt.Errorf("appmodel reader error: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	for {
		alert := &tetragon.Alert{}
		err := decoder.Decode(&alert)
		if err != nil && !errors.Is(err, io.EOF) {
			return alertBin, alertCount, err
		}
		if errors.Is(err, io.EOF) {
			break
		}
		alertBin[alert.Rule.Name] = append(alertBin[alert.Rule.Name], alert)
		alertCount[alert.Rule.Name]++
	}
	return alertBin, alertCount, nil
}

func getS3Model(ctx context.Context, s3Client *s3.Client, bucket, lastKey string, namespaces []string) (*appModelV1.ApplicationModelEvent, error) {
	result, err := s3Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(lastKey),
	})
	if err != nil {
		return nil, fmt.Errorf("getObject error: %w", err)
	}
	body, err := io.ReadAll(result.Body)
	if err != nil {
		return nil, fmt.Errorf("object ReadAll error: %w", err)
	}
	reader := bytes.NewReader(body)
	gzreader, err := gzip.NewReader(reader)
	if err != nil {
		return nil, fmt.Errorf("gzip reader error: %w", err)
	}
	bytes, err := io.ReadAll(gzreader)
	if err != nil {
		return nil, fmt.Errorf("appmodel reader error: %w", err)
	}
	models := strings.Split(string(bytes), "\n")
	appModel := models[len(models)-1]

	event := &appModelV1.ApplicationModelEvent{}
	decoder := json.NewDecoder(strings.NewReader(appModel))
	if err := decoder.Decode(event); err != nil {
		return nil, err
	}

	if len(namespaces) == 0 {
		return event, nil
	}

	filteredNS := []*appModelV1.ApplicationNamespace{}
	for _, ns := range event.ApplicationModel.Namespaces {
		for _, filter := range namespaces {
			if filter == ns.Name {
				filteredNS = append(filteredNS, ns)
			}
		}
	}
	event.ApplicationModel.Host = nil
	event.ApplicationModel.Namespaces = filteredNS
	return event, nil
}

func s3GetLastKey(ctx context.Context, s3Client *s3.Client, bucket, lastKey string) (string, error) {
	var err error
	var output *s3.ListObjectsV2Output

	input := &s3.ListObjectsV2Input{
		Bucket: aws.String(bucket),
	}

	if lastKey != "" {
		input.StartAfter = &lastKey
	}

	var objects []types.Object
	objectPaginator := s3.NewListObjectsV2Paginator(s3Client, input)
	for objectPaginator.HasMorePages() {
		output, err = objectPaginator.NextPage(ctx)
		if err != nil {
			if noBucket, ok := errors.AsType[*types.NoSuchBucket](err); ok {
				return "", error(noBucket)
			}
			break
		}
		objects = append(objects, output.Contents...)
	}

	var objKeys []string
	for _, object := range objects {
		objKeys = append(objKeys, *object.Key)
	}

	// If objectKeys == 0 then there are no new objects in the bucket
	if len(objKeys) > 0 {
		return objKeys[len(objKeys)-1], nil
	}
	return "", fmt.Errorf("bucket empty, no objects found")
}

func s3Monitor(bucket string, interval time.Duration, namespaces []string) error {
	ctx := context.Background()
	client, err := newS3Client(ctx)
	if err != nil {
		fmt.Println("Couldn't load default configuration. Have you set up your AWS account?")
		fmt.Println(err)
		return nil
	}

	_, err = client.HeadBucket(ctx, &s3.HeadBucketInput{
		Bucket: aws.String(bucket),
	})
	if err != nil {
		fmt.Printf("s3Client bucket lookup error: %s\n", err)
		return err
	}

	lastKey, err := s3GetLastKey(ctx, client, bucket, "")
	if err != nil {
		fmt.Printf("s3GetLastKey failed: %s\n", err)
		return err
	}

	currentModel, err := getS3Model(ctx, client, bucket, lastKey, namespaces)
	if err != nil {
		return err
	}

	ticker := time.NewTicker(interval)
	for range ticker.C {
		key, err := s3GetLastKey(ctx, client, bucket, lastKey)
		if err != nil {
			fmt.Printf("s3GetLastKey error: %s\n", err)
			continue
		}
		// If last key is empty then we failed to find a new object.
		if key == "" {
			continue
		}

		if lastKey != key {
			newModel, err := getS3Model(ctx, client, bucket, lastKey, namespaces)
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

func s3MonitorAlert(bucket string, interval time.Duration, _ []string) error {
	ctx := context.Background()
	client, err := newS3Client(ctx)
	if err != nil {
		return err
	}
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

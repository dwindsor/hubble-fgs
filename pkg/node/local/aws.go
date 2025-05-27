// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package local

import (
	"bufio"
	"context"
	"fmt"
	"io"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
)

type AWSMetadataService struct {
	imdsClient *imds.Client
}

func NewAWSMetadataService() (*AWSMetadataService, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		return nil, err
	}
	return &AWSMetadataService{imdsClient: imds.NewFromConfig(cfg)}, nil
}

func (m *AWSMetadataService) GetLabels(ctx context.Context) (map[string]string, error) {
	tags := make(map[string]string)
	out, err := m.imdsClient.GetMetadata(ctx, &imds.GetMetadataInput{Path: "/tags/instance"})
	if err != nil {
		return nil, err
	}
	scanner := bufio.NewScanner(out.Content)
	for scanner.Scan() {
		key := scanner.Text()
		val, err := m.imdsClient.GetMetadata(ctx, &imds.GetMetadataInput{Path: fmt.Sprintf("/tags/instance/%s", key)})
		if err != nil {
			return nil, err
		}
		valString, err := io.ReadAll(val.Content)
		if err != nil {
			return nil, err
		}
		tags[key] = string(valString)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return tags, nil
}

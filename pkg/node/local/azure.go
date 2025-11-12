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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

const (
	// Azure IMDS compute endpoint, see https://aka.ms/azureimds
	metadataEndpoint = "http://169.254.169.254/metadata/instance"
)

type AzureMetadataService struct {
	endpoint string
	client   *http.Client
}

func NewAzureMetadataService() (*AzureMetadataService, error) {
	res := &AzureMetadataService{
		endpoint: metadataEndpoint,
		client:   http.DefaultClient,
	}
	return res, nil
}

func (a *AzureMetadataService) GetHostname(ctx context.Context) (string, error) {
	resp, err := a.metadata(ctx)
	if err != nil {
		return "", err
	}
	return resp.GetHostname(), nil
}

func (a *AzureMetadataService) GetLabels(ctx context.Context) (map[string]string, error) {
	resp, err := a.metadata(ctx)
	if err != nil {
		return nil, err
	}
	return resp.GetTags(), nil
}

func (a *AzureMetadataService) GetInstanceId(ctx context.Context) (string, error) {
	resp, err := a.metadata(ctx)
	if err != nil {
		return "", err
	}
	return resp.GetID(), nil
}

func (a *AzureMetadataService) GetInternalIP(ctx context.Context) (string, error) {
	resp, err := a.metadata(ctx)
	if err != nil {
		return "", err
	}
	return resp.GetInternalIP(), nil
}

func (a *AzureMetadataService) GetExternalIP(ctx context.Context) (string, error) {
	resp, err := a.metadata(ctx)
	if err != nil {
		return "", err
	}
	return resp.GetExternalIP(), nil
}

func (a *AzureMetadataService) GetInternalDNS(_ context.Context) (string, error) {
	// Azure IMDS does not provide internal DNS info
	return "", nil
}

func (a *AzureMetadataService) GetExternalDNS(_ context.Context) (string, error) {
	// Azure IMDS does not provide external DNS info
	return "", nil
}

func (a *AzureMetadataService) metadata(ctx context.Context) (*VMData, error) {
	const (
		// API version used
		apiVersionKey = "api-version"
		apiVersion    = "2025-04-07"
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Add("Metadata", "True")
	q := req.URL.Query()
	q.Add(apiVersionKey, apiVersion)
	req.URL.RawQuery = q.Encode()

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to query Azure IMDS: %v", err)
	} else if resp.StatusCode != 200 {
		return nil, fmt.Errorf("azure IMDS replied with status code: %s", resp.Status)
	}

	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read Azure IMDS response: %v", err)
	}

	var metadata *VMData
	err = json.Unmarshal(respBody, &metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to decode Azure IMDS response: %v", err)
	}
	return metadata, nil
}

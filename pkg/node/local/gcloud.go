// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

//go:build !nocloud

package local

import (
	"context"
	"net/http"

	"cloud.google.com/go/compute/metadata"
)

type GCloudMetadataService struct {
	client *metadata.Client
}

func NewGCloudMetadataService() (*GCloudMetadataService, error) {
	return &GCloudMetadataService{
		client: metadata.NewClient(http.DefaultClient),
	}, nil
}

func (g *GCloudMetadataService) GetHostname(ctx context.Context) (string, error) {
	return g.client.HostnameWithContext(ctx)
}

// GetLabels retrieves all instance attributes as labels.
// GCP does not have a dedicated labels endpoint in the metadata service, so we are using instance attributes as labels.
func (g *GCloudMetadataService) GetLabels(ctx context.Context) (map[string]string, error) {
	labels := baseHostLabels()
	keys, err := g.client.InstanceAttributesWithContext(ctx)
	if err != nil {
		return nil, err
	}
	for _, key := range keys {
		value, err := g.client.InstanceAttributeValueWithContext(ctx, key)
		if err != nil {
			return nil, err
		}
		if _, ok := labels[key]; !ok { // host-derived labels win over cloud tags
			labels[key] = value
		}
	}
	return labels, nil
}

func (g *GCloudMetadataService) GetInstanceId(ctx context.Context) (string, error) {
	return g.client.InstanceIDWithContext(ctx)
}

func (g *GCloudMetadataService) GetInternalIP(ctx context.Context) (string, error) {
	return g.client.InternalIPWithContext(ctx)
}

func (g *GCloudMetadataService) GetExternalIP(ctx context.Context) (string, error) {
	return g.client.ExternalIPWithContext(ctx)
}

func (g *GCloudMetadataService) GetInternalDNS(ctx context.Context) (string, error) {
	return g.client.HostnameWithContext(ctx)
}

func (g *GCloudMetadataService) GetExternalDNS(_ context.Context) (string, error) {
	// TODO: GCP does not provide external DNS via metadata service
	return "", nil
}

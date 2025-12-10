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

	ossOption "github.com/cilium/tetragon/pkg/option"

	"github.com/isovalent/hubble-fgs/pkg/manager"
	"github.com/isovalent/hubble-fgs/pkg/option"
)

var (
	_ MetadataService = (*AWSMetadataService)(nil)
	_ MetadataService = (*GCloudMetadataService)(nil)
	_ MetadataService = (*AzureMetadataService)(nil)
	_ MetadataService = (*KubernetesMetadataService)(nil)
	_ MetadataService = (*GenericMetadataService)(nil)
	_ MetadataService = (*NoopMetadataService)(nil)
)

type MetadataService interface {
	GetHostname(ctx context.Context) (string, error)
	GetLabels(ctx context.Context) (map[string]string, error)
	GetInstanceId(ctx context.Context) (string, error)
	GetInternalIP(ctx context.Context) (string, error)
	GetExternalIP(ctx context.Context) (string, error)
	GetInternalDNS(ctx context.Context) (string, error)
	GetExternalDNS(ctx context.Context) (string, error)
}

func GetMetadataService() (MetadataService, error) {
	switch {
	case option.Config.Environment == option.EnvironmentAWS:
		return NewAWSMetadataService()
	case option.Config.Environment == option.EnvironmentGCloud:
		return NewGCloudMetadataService()
	case option.Config.Environment == option.EnvironmentAzure:
		return NewAzureMetadataService()
	case option.Config.Environment == option.EnvironmentKubernetes || ossOption.Config.EnableK8s:
		return NewKubernetesMetadataService(manager.Get())
	case option.K8SControlPlaneEnabled():
		return NewGenericMetadataService()
	default:
		return &NoopMetadataService{}, nil
	}
}

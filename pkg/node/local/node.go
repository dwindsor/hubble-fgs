// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

//go:build !nok8s

package local

import (
	"context"

	ossOption "github.com/cilium/tetragon/pkg/option"

	"github.com/isovalent/hubble-fgs/pkg/manager"
	"github.com/isovalent/hubble-fgs/pkg/option"
)

var (
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
	if svc, ok, err := getCloudMetadataService(); ok {
		if err != nil {
			return svc, err
		}
		return withAdditionalNodeLabels(svc), nil
	}
	switch {
	case option.Config.Environment == option.EnvironmentKubernetes || ossOption.Config.EnableK8s:
		svc, err := NewKubernetesMetadataService(manager.Get())
		if err != nil {
			return nil, err
		}
		return withAdditionalNodeLabels(svc), nil
	case option.K8SControlPlaneEnabled():
		svc, err := NewGenericMetadataService()
		if err != nil {
			return nil, err
		}
		return withAdditionalNodeLabels(svc), nil
	default:
		return withAdditionalNodeLabels(&NoopMetadataService{}), nil
	}
}

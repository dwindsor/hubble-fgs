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
	"github.com/isovalent/hubble-fgs/pkg/option"
)

var (
	_ MetadataService = (*AWSMetadataService)(nil)
	_ MetadataService = (*GCloudMetadataService)(nil)
	_ MetadataService = (*AzureMetadataService)(nil)
)

// getCloudMetadataService returns a MetadataService for the configured cloud
// provider environment. The boolean return is false when the environment is
// not a recognised cloud provider, leaving the caller to fall back to its own
// (Kubernetes/generic/noop) handling.
//
// In nocloud builds the cloud provider SDKs are compiled out and the stub in
// cloud_nocloud.go always reports the environment as unhandled.
func getCloudMetadataService() (MetadataService, bool, error) {
	switch option.Config.Environment {
	case option.EnvironmentAWS:
		svc, err := NewAWSMetadataService()
		return svc, true, err
	case option.EnvironmentGCloud:
		svc, err := NewGCloudMetadataService()
		return svc, true, err
	case option.EnvironmentAzure:
		svc, err := NewAzureMetadataService()
		return svc, true, err
	default:
		return nil, false, nil
	}
}

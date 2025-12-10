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
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenericMetadataService_GetHostname(t *testing.T) {
	svc, err := NewGenericMetadataService()
	require.NoError(t, err)

	hostname, err := svc.GetHostname(context.Background())
	require.NoError(t, err)

	expected, err := os.Hostname()
	require.NoError(t, err)

	assert.Equal(t, expected, hostname)
}

func TestGenericMetadataService_GetInstanceId(t *testing.T) {
	svc, err := NewGenericMetadataService()
	require.NoError(t, err)

	instanceId, err := svc.GetInstanceId(context.Background())
	require.NoError(t, err)

	// Instance ID should equal hostname for generic environments
	expected, err := os.Hostname()
	require.NoError(t, err)

	assert.Equal(t, expected, instanceId)
}

func TestGenericMetadataService_GetLabels(t *testing.T) {
	svc, err := NewGenericMetadataService()
	require.NoError(t, err)

	labels, err := svc.GetLabels(context.Background())
	require.NoError(t, err)

	assert.Contains(t, labels, "tetragon.io/environment")
	assert.Equal(t, "generic", labels["tetragon.io/environment"])
}

func TestGenericMetadataService_GetInternalIP(t *testing.T) {
	svc, err := NewGenericMetadataService()
	require.NoError(t, err)

	ip, err := svc.GetInternalIP(context.Background())
	require.NoError(t, err)

	// IP should either be empty or a valid non-loopback address
	if ip != "" {
		assert.NotEqual(t, "127.0.0.1", ip)
	}
}

func TestGenericMetadataService_GetExternalIP(t *testing.T) {
	svc, err := NewGenericMetadataService()
	require.NoError(t, err)

	ip, err := svc.GetExternalIP(context.Background())
	require.NoError(t, err)

	// External IP should be empty for generic environments
	assert.Empty(t, ip)
}

func TestGenericMetadataService_GetInternalDNS(t *testing.T) {
	svc, err := NewGenericMetadataService()
	require.NoError(t, err)

	dns, err := svc.GetInternalDNS(context.Background())
	require.NoError(t, err)

	// Internal DNS should equal hostname
	expected, err := os.Hostname()
	require.NoError(t, err)

	assert.Equal(t, expected, dns)
}

func TestGenericMetadataService_GetExternalDNS(t *testing.T) {
	svc, err := NewGenericMetadataService()
	require.NoError(t, err)

	dns, err := svc.GetExternalDNS(context.Background())
	require.NoError(t, err)

	// External DNS should be empty for generic environments
	assert.Empty(t, dns)
}

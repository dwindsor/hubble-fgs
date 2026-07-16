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
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBaseHostLabels(t *testing.T) {
	labels := baseHostLabels()

	require.Equal(t, runtime.GOARCH, labels[labelArch])
	require.Equal(t, runtime.GOOS, labels[labelOS])

	hostname, err := os.Hostname()
	require.NoError(t, err)
	require.Equal(t, hostname, labels[labelHostname])
}

func TestNoopMetadataService_GetLabels(t *testing.T) {
	svc := &NoopMetadataService{}
	labels, err := svc.GetLabels(context.Background())
	require.NoError(t, err)
	require.Equal(t, runtime.GOARCH, labels[labelArch])
	require.Equal(t, runtime.GOOS, labels[labelOS])
}

func TestGenericMetadataService_GetLabels_HostLabels(t *testing.T) {
	svc, err := NewGenericMetadataService()
	require.NoError(t, err)
	labels, err := svc.GetLabels(context.Background())
	require.NoError(t, err)
	require.Equal(t, runtime.GOARCH, labels[labelArch])
	require.Equal(t, "generic", labels["tetragon.io/environment"])
}

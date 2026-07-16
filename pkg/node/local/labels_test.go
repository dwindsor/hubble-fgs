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

	ossOption "github.com/cilium/tetragon/pkg/option"
)

func TestBaseHostLabels(t *testing.T) {
	labels := baseHostLabels()

	require.Equal(t, runtime.GOARCH, labels[labelArch])
	require.Equal(t, runtime.GOOS, labels[labelOS])

	hostname, err := os.Hostname()
	require.NoError(t, err)
	require.Equal(t, hostname, labels[labelHostname])
}

func TestKernelVersion(t *testing.T) {
	orig := ossOption.Config.KernelVersion
	t.Cleanup(func() { ossOption.Config.KernelVersion = orig })

	for _, tt := range []struct {
		release            string
		wantMajor, wantMin int
		wantOK             bool
	}{
		{release: "6.18.38-1-lts", wantMajor: 6, wantMin: 18, wantOK: true},
		{release: "4.19.221", wantMajor: 4, wantMin: 19, wantOK: true},
		{release: "5.10", wantMajor: 5, wantMin: 10, wantOK: true},
		{release: "garbage", wantOK: false},
	} {
		t.Run(tt.release, func(t *testing.T) {
			ossOption.Config.KernelVersion = tt.release
			major, minor, ok := kernelVersion()
			require.Equal(t, tt.wantOK, ok)
			require.Equal(t, tt.wantMajor, major)
			require.Equal(t, tt.wantMin, minor)
		})
	}
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

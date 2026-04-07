// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package fscgroupid

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/types"
)

type mockFSScanner struct {
	mock.Mock
}

func (m *mockFSScanner) FindPodPath(podID types.UID) (string, error) {
	args := m.Called(podID)
	return args.String(0), args.Error(1)
}

func TestNew(t *testing.T) {
	resolver := New()
	assert.NotNil(t, resolver)
}

func TestNewWithScanner(t *testing.T) {
	scanner := new(mockFSScanner)
	resolver := NewWithScanner(scanner)
	assert.NotNil(t, resolver)
}

func TestGetCgroupIDFromPodUIDScannerError(t *testing.T) {
	scanner := new(mockFSScanner)
	scanner.On("FindPodPath", types.UID("test-uid")).Return("", fmt.Errorf("pod not found"))

	resolver := NewWithScanner(scanner)

	_, err := resolver.GetPodCgroupID(types.UID("test-uid"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "pod not found")

	scanner.AssertExpectations(t)
}

func TestGetCgroupIDFromPodUIDEmptyPath(t *testing.T) {
	scanner := new(mockFSScanner)
	scanner.On("FindPodPath", types.UID("static-pod-uid")).Return("", nil)

	resolver := NewWithScanner(scanner)

	cgroupID, err := resolver.GetPodCgroupID(types.UID("static-pod-uid"))
	require.NoError(t, err)
	assert.Equal(t, uint64(0), cgroupID, "empty path should return 0 for static pods")

	scanner.AssertExpectations(t)
}

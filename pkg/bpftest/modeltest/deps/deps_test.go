// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

//go:build sudo_tests

package deps

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProcessRegistry(t *testing.T) {
	registry := NewProcessRegistry()

	// Test registering and checking a process
	assert.False(t, registry.IsRegistered("test-process"))

	registry.Register("test-process")
	assert.True(t, registry.IsRegistered("test-process"))
}

func TestProcessRunning(t *testing.T) {
	registry := NewProcessRegistry()
	ctx := context.Background()

	// Test with a process that should exist (kernel threads)
	dep, err := NewProcessRunning("\\[.*\\]")
	require.NoError(t, err)

	satisfied, err := dep.Check(ctx, registry)
	require.NoError(t, err)
	assert.True(t, satisfied, "should find kernel threads")

	// Test with a process that shouldn't exist
	dep2, err := NewProcessRunning("this-process-should-not-exist-12345")
	require.NoError(t, err)

	satisfied2, err := dep2.Check(ctx, registry)
	require.NoError(t, err)
	assert.False(t, satisfied2, "should not find non-existent process")
}

func TestProcessStarted(t *testing.T) {
	registry := NewProcessRegistry()
	ctx := context.Background()

	dep := NewProcessStarted("test-id")

	// Should not be satisfied initially
	satisfied, err := dep.Check(ctx, registry)
	require.NoError(t, err)
	assert.False(t, satisfied)

	// Register the process
	registry.Register("test-id")

	// Should now be satisfied
	satisfied, err = dep.Check(ctx, registry)
	require.NoError(t, err)
	assert.True(t, satisfied)
}

func TestTCPPortOpen(t *testing.T) {
	registry := NewProcessRegistry()
	ctx := context.Background()

	// Start a TCP listener on a random available port
	listener, err := net.Listen("tcp", ":0")
	require.NoError(t, err)
	defer listener.Close()

	// Get the actual port that was assigned
	port := listener.Addr().(*net.TCPAddr).Port

	// Test that the dependency check finds the open port
	dep := NewTCPPortOpen(uint16(port))

	satisfied, err := dep.Check(ctx, registry)
	require.NoError(t, err)
	assert.True(t, satisfied, "port %d should be open", port)
}

func TestCheckDependencies(t *testing.T) {
	registry := NewProcessRegistry()
	ctx := context.Background()

	// Test with satisfied dependencies
	dep1 := NewProcessStarted("test1")
	dep2 := NewProcessStarted("test2")

	registry.Register("test1")
	registry.Register("test2")

	err := CheckDependencies(ctx, []Dependency{dep1, dep2}, registry, 1*time.Second)
	assert.NoError(t, err)

	// Test with unsatisfied dependencies (should timeout)
	dep3 := NewProcessStarted("non-existent")

	start := time.Now()
	err = CheckDependencies(ctx, []Dependency{dep3}, registry, 200*time.Millisecond)
	duration := time.Since(start)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "dependency check timed out")
	assert.GreaterOrEqual(t, duration, 200*time.Millisecond)
	assert.Less(t, duration, 300*time.Millisecond) // Should not take much longer than timeout
}

func TestNewProcessRunningInvalidRegex(t *testing.T) {
	_, err := NewProcessRunning("[invalid-regex")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid regex pattern")
}

func TestDependencyStrings(t *testing.T) {
	dep1, _ := NewProcessRunning("test.*pattern")
	assert.Equal(t, "ProcessRunning(test.*pattern)", dep1.String())

	dep2 := NewProcessStarted("test-id")
	assert.Equal(t, "ProcessStarted(test-id)", dep2.String())

	dep3 := NewTCPPortOpen(8080)
	assert.Equal(t, "TCPPortOpen(8080)", dep3.String())
}

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

	"github.com/cilium/tetragon/pkg/cgroups"
	"github.com/cilium/tetragon/pkg/cgroups/fsscan"
	"k8s.io/apimachinery/pkg/types"
)

// FSPodScanner is an interface for finding pod paths in the filesystem.
// This is re-exported from dnsparser to avoid circular dependencies.
type FSPodScanner interface {
	FindPodPath(podID types.UID) (string, error)
}

// Resolver abstracts cgroup ID resolution to make it mockable for testing.
type Resolver interface {
	// GetCgroupIDFromPodUID resolves a cgroup ID from a pod UID.
	GetCgroupIDFromPodUID(uid types.UID) (uint64, error)
}

// resolver is the production implementation that uses the filesystem.
type resolver struct {
	fsScanner FSPodScanner
}

// New creates a new Resolver with a default filesystem scanner.
func New() Resolver {
	return &resolver{fsScanner: fsscan.New()}
}

// NewWithScanner creates a new Resolver with a custom filesystem scanner.
// This is primarily used for testing.
func NewWithScanner(scanner FSPodScanner) Resolver {
	return &resolver{fsScanner: scanner}
}

func (r *resolver) GetCgroupIDFromPodUID(uid types.UID) (uint64, error) {
	podDir, err := r.fsScanner.FindPodPath(uid)
	if err != nil {
		return 0, fmt.Errorf("failed to find the Pod %s cgroup path: %w", uid, err)
	}
	if podDir == "" {
		// Pods from which we can't find the cgroup path might be static pods, let's ignore them
		return 0, nil
	}
	// From that we get the cgroup ID
	cgroupID, err := cgroups.GetCgroupIdFromPath(podDir)
	if err != nil {
		return 0, fmt.Errorf("failed getting the cgroup ID from the cgroup directory %s: %w", podDir, err)
	}
	return cgroupID, nil
}

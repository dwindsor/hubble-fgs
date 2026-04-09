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

package dnsparser

import (
	"errors"
	"fmt"

	"github.com/cilium/tetragon/pkg/cgroups"
	"github.com/cilium/tetragon/pkg/cgroups/fsscan"
)

// GetKubepodsSliceCgroupID is a global var that can be set for testing purposes.
var GetKubepodsSliceCgroupID = getKubepodsSliceCgroupID

// getKubepodsSliceCgroupID scans the filesystem for the "kubepods.slice"
// cgroup directory
func getKubepodsSliceCgroupID() (uint64, error) {
	fsscanner := fsscan.New()
	podDir, err := fsscanner.FindPodPath("kubepods.slice")
	if err != nil {
		return 0, fmt.Errorf("failed to find kubepods.slice cgroup directory: %w", err)
	}

	if podDir == "" {
		return 0, errors.New("kubepods.slice was not found in the cgroup hierarchy")
	}

	cgid, err := cgroups.GetCgroupIdFromPath(podDir)
	if err != nil {
		return 0, fmt.Errorf("failed getting the cgroup ID from the cgroup directory: %w", err)
	}

	return cgid, nil
}

// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

//go:build nok8s

package dnsparser

import "errors"

// GetKubepodsSliceCgroupID is a global var that can be set for testing purposes.
var GetKubepodsSliceCgroupID = getKubepodsSliceCgroupID

// getKubepodsSliceCgroupID scans the filesystem for the "kubepods.slice"
// cgroup directory
func getKubepodsSliceCgroupID() (uint64, error) {
	return 0, errors.New("k8s disabled build: cannot find kubpods.slice")
}

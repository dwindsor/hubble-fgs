// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build nok8s

package option

func K8SControlPlaneEnabled() bool {
	return false
}

func InClusterControlPlaneEnabled() bool {
	return false
}

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
	"os"
	"runtime"
)

// Node label keys derived from the local host. They are used only in
// non-Kubernetes environments (Kubernetes nodes are matched against their real
// Node labels), so they carry a tetragon.io prefix to avoid being confused with
// kubelet-assigned kubernetes.io labels.
const (
	LabelArch     = "tetragon.io/arch"
	LabelOS       = "tetragon.io/os"
	LabelHostname = "tetragon.io/hostname"
)

// baseHostLabels returns labels derived from the local host (architecture, OS,
// and hostname). These are always knowable regardless of the environment and
// let nodeSelector target non-Kubernetes agents by arch, OS, or hostname.
func baseHostLabels() map[string]string {
	labels := map[string]string{
		LabelArch: runtime.GOARCH,
		LabelOS:   runtime.GOOS,
	}
	if hostname, err := os.Hostname(); err == nil && hostname != "" {
		labels[LabelHostname] = hostname
	}
	return labels
}

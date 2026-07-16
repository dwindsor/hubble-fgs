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
	"maps"
	"os"
	"runtime"
	"sync"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
)

// Node label keys derived from the local host. They are used only in
// non-Kubernetes environments (Kubernetes nodes are matched against their real
// Node labels), so they carry a tetragon.io prefix to avoid being confused with
// kubelet-assigned kubernetes.io labels.
const (
	labelArch               = "tetragon.io/arch"
	labelOS                 = "tetragon.io/os"
	labelHostname           = "tetragon.io/hostname"
	labelKernelBuildID      = "tetragon.io/kernel-build-id"
	labelKernelMajorVersion = "tetragon.io/kernel-major-version"
	labelKernelMinorVersion = "tetragon.io/kernel-minor-version"
)

// labelProviders resolve the optional host labels; an error or empty value
// omits the label.
var labelProviders = []struct {
	key string
	get func() (string, error)
}{
	{labelHostname, os.Hostname},
	{labelKernelBuildID, kernelBuildID},
	{labelKernelMajorVersion, kernelMajorVersion},
	{labelKernelMinorVersion, kernelMinorVersion},
}

// hostLabels resolves once: the values are fixed for the life of the process,
// while GetLabels runs on the periodic model-export path.
var hostLabels = sync.OnceValue(func() map[string]string {
	labels := map[string]string{
		labelArch: runtime.GOARCH,
		labelOS:   runtime.GOOS,
	}
	for _, p := range labelProviders {
		v, err := p.get()
		if err != nil || v == "" {
			logger.GetLogger().Debug("host label omitted", "label", p.key, logfields.Error, err)
			continue
		}
		labels[p.key] = v
	}
	return labels
})

// baseHostLabels returns a copy of the host labels, so callers can merge their
// own into it.
func baseHostLabels() map[string]string {
	return maps.Clone(hostLabels())
}

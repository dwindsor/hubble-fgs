// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package sockmap

import (
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
)

// ParseTLSSpec parses the input yaml/crd and outputs the kernel selectors
// needed for BPF to run match logic.
func ParseTLSSpec(spec *v1alpha1.TlsSpec, https *v1alpha1.HttpsSpec) []uint32 {
	var ports []uint32

	if spec != nil {
		for _, selector := range spec.Selectors {
			ports = append(ports, selector.MatchPorts...)
		}
	}

	if https != nil {
		for _, selector := range https.Selectors {
			ports = append(ports, selector.MatchPorts...)
		}
	}

	return ports
}

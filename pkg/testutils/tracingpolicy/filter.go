// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package tracingpolicy

import (
	"testing"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
)

func selAddPidFilter(pid int, selectors []v1alpha1.KProbeSelector) []v1alpha1.KProbeSelector {

	pidSelector := v1alpha1.PIDSelector{
		Operator:       "In",
		IsNamespacePID: false,
		FollowForks:    true,
		Values:         []uint32{uint32(pid)},
	}

	if len(selectors) == 0 {
		selectors = make([]v1alpha1.KProbeSelector, 1)
	}

	for i := range selectors {
		selectors[i].MatchPIDs = append(selectors[i].MatchPIDs, pidSelector)
	}

	return selectors
}

// AddPidFilter adds a pid filter to the kprobe and tracepoints parts of a  tracing policy
// NB: This is intended only for testing (use of the unused argument t is to ensure that it's not
// used anywhere else).
func AddPidFilter(_ *testing.T, tp *v1alpha1.TracingPolicySpec, pid int) {
	for i := range tp.KProbes {
		tp.KProbes[i].Selectors = selAddPidFilter(pid, tp.KProbes[i].Selectors)
	}
	for i := range tp.Tracepoints {
		tp.Tracepoints[i].Selectors = selAddPidFilter(pid, tp.Tracepoints[i].Selectors)
	}
}

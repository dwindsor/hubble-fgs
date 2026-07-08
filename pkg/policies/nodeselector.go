// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package policies

import (
	"log/slog"

	slimlabels "github.com/cilium/tetragon/pkg/k8s/slim/k8s/apis/labels"
	slimv1 "github.com/cilium/tetragon/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
)

// SkipTracingPolicyForNode reports whether tp's spec.nodeSelector excludes this
// host. It fails open: a nil selector, absent host labels, or an unparseable
// selector all load the policy rather than silently drop it.
func SkipTracingPolicyForNode(tp tracingpolicy.TracingPolicy, hostLabels map[string]string, log *slog.Logger) bool {
	sel := tp.TpSpec().NodeSelector
	if sel == nil || len(hostLabels) == 0 {
		return false
	}
	selector, err := slimv1.LabelSelectorAsSelector(sel)
	if err != nil {
		log.Warn("nodeSelector evaluation failed; loading policy on this node", "error", err)
		return false
	}
	return !selector.Matches(slimlabels.Set(hostLabels))
}

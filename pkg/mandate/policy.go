//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package mandate

import (
	"fmt"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
)

func tpNs(tp tracingpolicy.TracingPolicy) string {
	if tpns, ok := tp.(tracingpolicy.TracingPolicyNamespaced); ok {
		return tpns.TpNamespace()
	}
	return ""
}

//revive:disable:exported
type MandatePolicy struct {
	tp   tracingpolicy.TracingPolicy
	name string
}

func (m *manager) NewMandatePolicy(tp tracingpolicy.TracingPolicy) tracingpolicy.TracingPolicy {
	ret := MandatePolicy{
		tp:   tp,
		name: fmt.Sprintf("mandate+pol-%d-%s", m.polNextID, tp.TpName()),
	}
	m.polNextID++
	if _, ok := tp.(tracingpolicy.TracingPolicyNamespaced); ok {
		logger.GetLogger().Warn("mandate does not currently support namespaced policies")
	}

	return &ret
}

func (mp *MandatePolicy) TpName() string {
	return mp.name
}

func (mp *MandatePolicy) TpSpec() *v1alpha1.TracingPolicySpec {
	return mp.tp.TpSpec()
}

func (mp *MandatePolicy) TpInfo() string {
	return mp.tp.TpInfo()
}

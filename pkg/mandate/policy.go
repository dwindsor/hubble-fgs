// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package mandate

import (
	"fmt"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/tracingpolicy"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
)

const mandateDomain = "mandate"

//revive:disable:exported
type MandatePolicy struct {
	tp     tracingpolicy.TracingPolicy
	name   string
	domain string
}

func (m *manager) NewMandatePolicy(tp tracingpolicy.TracingPolicy) tracingpolicy.TracingPolicy {
	ret := MandatePolicy{
		tp:     tp,
		name:   tp.TpName(),
		domain: fmt.Sprintf("%s-%d", mandateDomain, m.domainID),
	}
	if tp.TpNamespace() != "" {
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

func (mp *MandatePolicy) TpNamespace() string {
	return mp.tp.TpNamespace()
}

func (mp *MandatePolicy) TpDomain() string {
	return mp.domain
}

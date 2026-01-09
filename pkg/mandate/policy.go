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
	"regexp"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/tracingpolicy"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
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

var polNameRegex = regexp.MustCompile(`^mandate\+pol-\d+-(.*)$`)

func OrigPolName(n string) (string, bool) {
	match := polNameRegex.FindStringSubmatch(n)
	if len(match) < 2 {
		return "", false
	}
	return match[1], true
}

func mandatePolName(n string, id uint) string {
	return fmt.Sprintf("mandate+pol-%d-%s", id, n)

}

var alertNameRegex = regexp.MustCompile(`^mandate\+alert-\d+-(.*)$`)

func mandateAlertName(n string, id uint) string {
	return fmt.Sprintf("mandate+alert-%d-%s", id, n)
}

func OrigAlertName(n string) (string, bool) {
	match := alertNameRegex.FindStringSubmatch(n)
	if len(match) < 2 {
		return "", false
	}
	return match[1], true
}

func (m *manager) NewMandatePolicy(tp tracingpolicy.TracingPolicy) tracingpolicy.TracingPolicy {
	ret := MandatePolicy{
		tp:   tp,
		name: mandatePolName(tp.TpName(), m.polNextID),
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

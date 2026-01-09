// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package matchLabels

import (
	"strings"

	"github.com/isovalent/hubble-fgs/pkg/endpoint"
	"github.com/isovalent/hubble-fgs/pkg/model/types"
)

type LabelSet struct {
	Labels    map[string]string
	Policy    *types.TetragonNetworkPolicy
	Source    []*endpoint.Source
	Endpoints []*endpoint.Endpoint
	Subjects  []*types.ProcessTreeKey
	Ports     []uint32
}

func (l *LabelSet) GetLabels() map[string]string {
	return l.Labels
}

func (l *LabelSet) GetPolicy() *types.TetragonNetworkPolicy {
	return l.Policy
}

func (l *LabelSet) Size() int {
	return len(l.Labels)
}

func (l *LabelSet) Subset(set map[string]string) bool {
	for k, v := range l.Labels {
		value, ok := set[k]
		if !ok {
			return false
		}

		if value != v {
			return false
		}
	}
	return true
}

func (l *LabelSet) ParseEquals(ml []string) {
	for _, s := range ml {
		e := strings.Split(s, "=")
		if len(e) != 2 {
			continue
		}
		l.Labels[e[0]] = e[1]
	}
}

func (l *LabelSet) AddEndpoint(ep *endpoint.Endpoint) {
	l.Endpoints = append(l.Endpoints, ep)
}

func (l *LabelSet) AddSubject(s *types.ProcessTreeKey) {
	l.Subjects = append(l.Subjects, s)
}

type PolicyList map[types.TetragonPolicyUniqueID]*LabelSet

func (policy PolicyList) Exists(l *LabelSet) bool {
	for _, p := range policy {
		if p.Subset(l.Labels) {
			return true
		}
	}
	return false
}

func (policy PolicyList) Collection(l *LabelSet) []*LabelSet {
	col := []*LabelSet{}

	for _, p := range policy {
		if p.Subset(l.Labels) {
			col = append(col, p)
		}
	}
	return col
}

// Rule for merging quota: Consume policy with smallest bandwidth
func (policy *PolicyList) MergedCollection(l *LabelSet) *LabelSet {
	var selectedQOS *LabelSet
	set := policy.Collection(l)

	for _, s := range set {
		if qos := s.Policy.Action.QuotaAction; qos != nil {
			if selectedQOS == nil {
				selectedQOS = s
				continue
			}
			if s.Policy.Action.QuotaAction.Quota < selectedQOS.Policy.Action.QuotaAction.Quota {
				selectedQOS = s
			}
		}
	}

	return selectedQOS
}

// Careful this is not a copy() so you can't reuse
// l after this.
func (policy PolicyList) Add(l *LabelSet) {
	policy[l.Policy.PolicyUID] = l
}

func (policy PolicyList) Flush() {
	for i := range policy {
		delete(policy, i)
	}
}

func (policy PolicyList) Remove(policyUID types.TetragonPolicyUniqueID) {
	delete(policy, policyUID)
}

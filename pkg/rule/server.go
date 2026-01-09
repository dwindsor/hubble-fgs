// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package rule

import (
	"context"
	"slices"
	"strings"

	api "github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/reader/node"
	"github.com/cilium/tetragon/pkg/sensors"
	dto "github.com/prometheus/client_model/go"

	"github.com/isovalent/hubble-fgs/pkg/metrics/alertmetrics"

	"github.com/isovalent/hubble-fgs/pkg/mandate"
)

const (
	probeRuleTagPrefix  = "isovalent/rule:"
	ruleVersionLabelKey = "isovalent/rule_version"
)

type alertRulesLister interface {
	ListAlertRules() []*v1alpha1.AlertRule
}

type tracingpolicyCollectionsLister interface {
	ListCollections(context.Context, bool) []*sensors.Collection
}

type Server struct {
	alertRulesLister  alertRulesLister
	collectionsLister tracingpolicyCollectionsLister
	api.UnimplementedRuleServiceServer
}

func New(alertLister alertRulesLister, specsLister tracingpolicyCollectionsLister) *Server {
	return &Server{
		alertRulesLister:  alertLister,
		collectionsLister: specsLister,
	}
}

func (s *Server) ListRules(ctx context.Context, req *api.ListRulesRequest) (*api.ListRulesResponse, error) {
	rules := &api.RuleSet{
		Node:  node.GetNodeName(),
		Rules: make([]*api.Rule, 0),
	}

	alertRules := s.alertRulesLister.ListAlertRules()
	collections := s.collectionsLister.ListCollections(ctx, true)

	// First pass: (kprobe/uprobe/tp/lsm/usdt + alertrule) rules
	// Since we may have (multiple probes + alertrule) rules,
	// use a map<tag,alertrule> to collapse together
	// multiple probes matching the same alertrule.
	for _, col := range collections {
		spec := col.TracingpolicySpec
		selectorLabels := make(map[string]string)
		if spec.PodSelector != nil {
			selectorLabels = spec.PodSelector.MatchLabels
		}
		tagProbes := make(map[string]*v1alpha1.AlertRule)
		for _, kprobe := range spec.KProbes {
			collectTagProbes(alertRules, tagProbes, kprobe.Tags)
		}
		for _, uprobe := range spec.UProbes {
			collectTagProbes(alertRules, tagProbes, uprobe.Tags)
		}
		for _, lsm := range spec.LsmHooks {
			collectTagProbes(alertRules, tagProbes, lsm.Tags)
		}
		for _, usdt := range spec.Usdts {
			collectTagProbes(alertRules, tagProbes, usdt.Tags)
		}
		for _, tp := range spec.Tracepoints {
			collectTagProbes(alertRules, tagProbes, tp.Tags)
		}
		collectTagProbes(alertRules, tagProbes, spec.FileMonitoring.Tags)

		// Once we collected all probes -> alertrule tags,
		// we can finally append to the return value.
		for after, rule := range tagProbes {
			var (
				mode    api.RuleMode
				polType = api.RuleType_RULE_TYPE_SHIELD
			)
			switch col.TracingpolicyMode {
			case api.TracingPolicyMode_TP_MODE_ENFORCE:
				mode = api.RuleMode_RULE_MODE_ENFORCEMENT
			case api.TracingPolicyMode_TP_MODE_MONITOR:
				mode = api.RuleMode_RULE_MODE_MONITORING
			case api.TracingPolicyMode_TP_MODE_MONITOR_ONLY:
				// external mode is MONITORING;
				// but let's also force the policy type to monitoring,
				// since no enforcement can be enabled.
				mode = api.RuleMode_RULE_MODE_MONITORING
				polType = api.RuleType_RULE_TYPE_MONITORING
			default:
				mode = api.RuleMode_RULE_MODE_UNSPEC
			}
			version := rule.Labels[ruleVersionLabelKey]
			if req.Version != "" && req.Version != version {
				continue
			}
			rules.Rules = append(rules.Rules, &api.Rule{
				Path: strings.Split(after, "-"),
				Type: polType,
				Status: &api.RuleStatus{
					Mode:    mode,
					Loaded:  col.State == sensors.EnabledState || col.State == sensors.DisabledState,
					LoadErr: col.Err,
				},
				Version:           version,
				Counter:           getCounter(rule),
				PodSelectorLabels: selectorLabels,
			})
		}
	}

	// Second pass: alertrule-only rules
	for _, rule := range alertRules {
		version := rule.Labels[ruleVersionLabelKey]
		if req.Version != "" && req.Version != version {
			continue
		}
		for _, tag := range rule.Spec.Tags {
			if after, ok := strings.CutPrefix(tag, probeRuleTagPrefix); ok {
				rules.Rules = append(rules.Rules, &api.Rule{
					Path: strings.Split(after, "-"),
					Type: api.RuleType_RULE_TYPE_MONITORING,
					Status: &api.RuleStatus{
						Mode:   api.RuleMode_RULE_MODE_MONITORING,
						Loaded: true,
					},
					Version: version,
					Counter: getCounter(rule),
				})
				break
			}
		}
	}

	// Finally sort returned rules
	slices.SortFunc(rules.Rules, func(a, b *api.Rule) int {
		pathA := strings.Join(a.Path, "-")
		pathB := strings.Join(b.Path, "-")
		return strings.Compare(pathA, pathB)
	})

	return &api.ListRulesResponse{Rules: rules}, nil
}

func collectTagProbes(alertRules []*v1alpha1.AlertRule, tagProbes map[string]*v1alpha1.AlertRule, tags []string) {
	for _, tag := range tags {
		if after, ok := strings.CutPrefix(tag, probeRuleTagPrefix); ok {
			for _, rule := range alertRules {
				// We need to discover the non-mandate name (ie: with mandate+alert... removed)
				preMandateName, ok := mandate.OrigAlertName(rule.Name)
				if !ok {
					preMandateName = rule.Name
				}
				if preMandateName == after {
					tagProbes[after] = rule
					break
				}
			}
			/* A single spec can have multiple rule tags. Do not break. */
		}
	}
}

func getCounter(rule *v1alpha1.AlertRule) uint64 {
	var m = &dto.Metric{}
	alertmetrics.AlertsTriggeredTotal.WithLabelValues(rule.GetName(), rule.Spec.Severity).Write(m)
	return uint64(m.GetCounter().GetValue())
}

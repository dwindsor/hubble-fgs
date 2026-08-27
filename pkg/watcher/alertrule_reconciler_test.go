// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

//go:build !nok8s

package watcher

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	enterpriseClient "github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/client"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
)

// ruleKey mirrors how the rule manager indexes rules: by name and domain.
type ruleKey struct {
	name   string
	domain string
}

type fakeRuleManager struct {
	added   []ruleKey
	deleted []ruleKey
	addErr  error
}

func (f *fakeRuleManager) AddAlertRule(ar *v1alpha1.AlertRule) error {
	f.added = append(f.added, ruleKey{name: ar.GetName(), domain: ar.Domain})
	return f.addErr
}

func (f *fakeRuleManager) DeleteAlertRule(name, domain string) {
	f.deleted = append(f.deleted, ruleKey{name: name, domain: domain})
}

var k8sRule1 = ruleKey{name: "rule-1", domain: v1alpha1.K8sDomain}

func alertRule(name string) *v1alpha1.AlertRule {
	return &v1alpha1.AlertRule{
		Kind: "AlertRule", APIVersion: "cilium.io/v1alpha1",
		Name: name,
	}
}

var alertRuleReq = ctrl.Request{Name: "rule-1"}

func TestAlertRuleReconcile_Found_Adds(t *testing.T) {
	rules := &fakeRuleManager{}
	cli := fake.NewClientBuilder().WithScheme(newScheme(t)).WithObjects(alertRule("rule-1")).Build()
	r := &AlertRuleReconciler{Client: cli, Rules: rules}

	res, err := r.Reconcile(context.Background(), alertRuleReq)
	require.NoError(t, err)
	require.Equal(t, ctrl.Result{}, res)
	require.Equal(t, []ruleKey{k8sRule1}, rules.added, "k8s-sourced rules carry the k8s domain")
	require.Empty(t, rules.deleted, "no delete when the rule exists")
}

func TestAlertRuleReconcile_NotFound_Deletes(t *testing.T) {
	rules := &fakeRuleManager{}
	cli := fake.NewClientBuilder().WithScheme(newScheme(t)).Build()
	r := &AlertRuleReconciler{Client: cli, Rules: rules}

	_, err := r.Reconcile(context.Background(), alertRuleReq)
	require.NoError(t, err)
	require.Equal(t, []ruleKey{k8sRule1}, rules.deleted, "delete is scoped to the k8s domain")
	require.Empty(t, rules.added, "no add on NotFound")
}

func TestAlertRuleReconcile_GetError_PropagatesAndDoesNothing(t *testing.T) {
	wantErr := errors.New("boom")
	rules := &fakeRuleManager{}
	cli := fake.NewClientBuilder().
		WithScheme(newScheme(t)).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(_ context.Context, _ client.WithWatch, _ client.ObjectKey, _ client.Object, _ ...client.GetOption) error {
				return wantErr
			},
		}).
		Build()
	r := &AlertRuleReconciler{Client: cli, Rules: rules}

	_, err := r.Reconcile(context.Background(), alertRuleReq)
	require.ErrorIs(t, err, wantErr)
	require.Empty(t, rules.added)
	require.Empty(t, rules.deleted)
}

func TestAlertRuleReconcile_AddError_IsTerminal(t *testing.T) {
	rules := &fakeRuleManager{addErr: errors.New("invalid rule")}
	cli := fake.NewClientBuilder().WithScheme(newScheme(t)).WithObjects(alertRule("rule-1")).Build()
	r := &AlertRuleReconciler{Client: cli, Rules: rules}

	_, err := r.Reconcile(context.Background(), alertRuleReq)
	require.ErrorIs(t, err, rules.addErr)
	require.Equal(t, []ruleKey{k8sRule1}, rules.added, "add was attempted")
}

func TestAlertRulePredicate_ReconcilesLabelChangesNotAnnotations(t *testing.T) {
	p := predicate.Or(
		predicate.GenerationChangedPredicate{},
		predicate.LabelChangedPredicate{},
	)

	withLabels := func(rev string) *v1alpha1.AlertRule {
		ar := alertRule("rule-1")
		ar.Labels = map[string]string{"isovalent/rule_version": rev}
		return ar
	}

	tests := []struct {
		name      string
		old, updd *v1alpha1.AlertRule
		want      bool
	}{
		{
			name: "label-only change is reconciled",
			old:  withLabels("1"),
			updd: withLabels("2"),
			want: true,
		},
		{
			name: "spec change (generation bump) is reconciled",
			old:  withLabels("1"),
			updd: func() *v1alpha1.AlertRule { ar := withLabels("1"); ar.Generation = 2; return ar }(),
			want: true,
		},
		{
			name: "annotation-only change is filtered",
			old:  withLabels("1"),
			updd: func() *v1alpha1.AlertRule {
				ar := withLabels("1")
				ar.Annotations = map[string]string{"note": "x"}
				return ar
			}(),
			want: false,
		},
		{
			name: "no-op resync is filtered",
			old:  withLabels("1"),
			updd: withLabels("1"),
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := p.Update(event.UpdateEvent{ObjectOld: tc.old, ObjectNew: tc.updd})
			require.Equal(t, tc.want, got)
		})
	}
}

func TestRegisterAlertRuleReconciler_GatesOnCorrectCRD(t *testing.T) {
	cm := &fakeControllerManager{}
	require.NoError(t, RegisterAlertRuleReconciler(cm, &fakeRuleManager{}))
	require.Equal(t, enterpriseClient.AlertRuleCRD.ResName, cm.gotCRD)
	require.NotNil(t, cm.setup, "setup callback must be wired")
}

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
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	slimv1 "github.com/cilium/tetragon/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
)

func TestSkipTracingPolicyForNode(t *testing.T) {
	hostLabels := map[string]string{
		"tetragon.io/arch":     "amd64",
		"tetragon.io/os":       "linux",
		"tetragon.io/hostname": "node-a",
	}

	tests := []struct {
		name     string
		sel      *slimv1.LabelSelector
		labels   map[string]string
		wantSkip bool
	}{
		{name: "nil selector loads", sel: nil, labels: hostLabels, wantSkip: false},
		{
			name:     "empty selector matches all",
			sel:      &slimv1.LabelSelector{},
			labels:   hostLabels,
			wantSkip: false,
		},
		{
			name:     "matchLabels hit",
			sel:      &slimv1.LabelSelector{MatchLabels: map[string]string{"tetragon.io/arch": "amd64"}},
			labels:   hostLabels,
			wantSkip: false,
		},
		{
			name:     "matchLabels miss",
			sel:      &slimv1.LabelSelector{MatchLabels: map[string]string{"tetragon.io/arch": "arm64"}},
			labels:   hostLabels,
			wantSkip: true,
		},
		{
			name: "matchExpressions In hit",
			sel: &slimv1.LabelSelector{MatchExpressions: []slimv1.LabelSelectorRequirement{
				{Key: "tetragon.io/arch", Operator: slimv1.LabelSelectorOpIn, Values: []string{"amd64", "arm64"}},
			}},
			labels:   hostLabels,
			wantSkip: false,
		},
		{
			name: "matchExpressions Exists miss",
			sel: &slimv1.LabelSelector{MatchExpressions: []slimv1.LabelSelectorRequirement{
				{Key: "tier", Operator: slimv1.LabelSelectorOpExists},
			}},
			labels:   hostLabels,
			wantSkip: true,
		},
		{
			name: "matchExpressions DoesNotExist hit",
			sel: &slimv1.LabelSelector{MatchExpressions: []slimv1.LabelSelectorRequirement{
				{Key: "tier", Operator: slimv1.LabelSelectorOpDoesNotExist},
			}},
			labels:   hostLabels,
			wantSkip: false,
		},
		{
			name:     "empty host labels fail open",
			sel:      &slimv1.LabelSelector{MatchLabels: map[string]string{"tetragon.io/arch": "arm64"}},
			labels:   nil,
			wantSkip: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tp := &tracingpolicy.GenericTracingPolicy{
				Metadata: tracingpolicy.ObjectMeta{Name: "test"},
				Spec:     v1alpha1.TracingPolicySpec{NodeSelector: tt.sel},
			}
			got := skipTracingPolicyForNode(tp, tt.labels, slog.Default())
			require.Equal(t, tt.wantSkip, got)
		})
	}
}

type fakeSensorManager struct {
	added   []string
	skipped []string
}

func (f *fakeSensorManager) AddTracingPolicy(_ context.Context, tp tracingpolicy.TracingPolicy) error {
	f.added = append(f.added, tp.TpName())
	return nil
}

func (f *fakeSensorManager) AddSkippedTracingPolicy(_ context.Context, tp tracingpolicy.TracingPolicy) error {
	f.skipped = append(f.skipped, tp.TpName())
	return nil
}

func writeArchPolicy(t *testing.T, arch string) string {
	t.Helper()
	yaml := fmt.Sprintf(`apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: %s-only
spec:
  nodeSelector:
    matchExpressions:
      - key: tetragon.io/arch
        operator: In
        values: ["%s"]
  kprobes:
    - call: tcp_connect
`, arch, arch)
	f := filepath.Join(t.TempDir(), "policy.yaml")
	require.NoError(t, os.WriteFile(f, []byte(yaml), 0o644))
	return f
}

// A non-matching nodeSelector records the policy as skipped (surfaced as
// TP_STATE_SKIPPED) rather than loading it; a matching one is loaded.
func TestOnTracingPolicyNodeSelector(t *testing.T) {
	host := map[string]string{"tetragon.io/arch": "amd64"}

	t.Run("non-matching is skipped", func(t *testing.T) {
		sm := &fakeSensorManager{}
		loader := &defaultLoader{sm: sm, log: slog.Default(), nodeSelectorLabels: host}
		require.NoError(t, loader.OnTracingPolicy(context.Background(), writeArchPolicy(t, "arm64"), nil))
		require.Equal(t, []string{"arm64-only"}, sm.skipped)
		require.Empty(t, sm.added)
	})

	t.Run("matching is loaded", func(t *testing.T) {
		sm := &fakeSensorManager{}
		loader := &defaultLoader{sm: sm, log: slog.Default(), nodeSelectorLabels: host}
		require.NoError(t, loader.OnTracingPolicy(context.Background(), writeArchPolicy(t, "amd64"), nil))
		require.Equal(t, []string{"amd64-only"}, sm.added)
		require.Empty(t, sm.skipped)
	})
}

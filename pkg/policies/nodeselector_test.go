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
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	slimv1 "github.com/cilium/tetragon/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/sensors"
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
			got := SkipTracingPolicyForNode(tp, tt.labels, slog.Default())
			require.Equal(t, tt.wantSkip, got)
		})
	}
}

func archPolicyYAML(arch string) string {
	return namedArchPolicyYAML(arch+"-only", arch)
}

// namedArchPolicyYAML renders a policy gated on one architecture. It carries no
// kprobes so the real tracing policy handler needs no kernel BTF, keeping the
// tests independent of the host kernel.
func namedArchPolicyYAML(name, arch string) string {
	return fmt.Sprintf(`apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: %s
spec:
  nodeSelector:
    matchExpressions:
      - key: tetragon.io/arch
        operator: In
        values: ["%s"]
`, name, arch)
}

func writeArchPolicy(t *testing.T, arch string) string {
	t.Helper()
	f := filepath.Join(t.TempDir(), "policy.yaml")
	require.NoError(t, os.WriteFile(f, []byte(archPolicyYAML(arch)), 0o644))
	return f
}

// A non-matching nodeSelector records the policy as skipped (surfaced as
// TP_STATE_SKIPPED) rather than loading it; a matching one is loaded.
func TestOnTracingPolicyNodeSelector(t *testing.T) {
	host := map[string]string{"tetragon.io/arch": "amd64"}

	t.Run("non-matching is skipped", func(t *testing.T) {
		mgr := startRealManager(t)
		loader := &defaultLoader{sm: mgr, log: slog.Default(), nodeSelectorLabels: host}
		require.NoError(t, loader.OnTracingPolicy(context.Background(), writeArchPolicy(t, "arm64"), nil))
		state, _ := policyStatus(t, mgr, "arm64-only")
		require.Equal(t, tetragon.TracingPolicyState_TP_STATE_SKIPPED, state)
	})

	t.Run("matching is loaded", func(t *testing.T) {
		mgr := startRealManager(t)
		loader := &defaultLoader{sm: mgr, log: slog.Default(), nodeSelectorLabels: host}
		require.NoError(t, loader.OnTracingPolicy(context.Background(), writeArchPolicy(t, "amd64"), nil))
		state, _ := policyStatus(t, mgr, "amd64-only")
		require.Equal(t, tetragon.TracingPolicyState_TP_STATE_ENABLED, state)
	})
}

type dummyPolicyHandler struct{}

func (dummyPolicyHandler) PolicyHandler(_ tracingpolicy.TracingPolicy, _ policyfilter.PolicyID) (sensors.SensorIface, error) {
	return &sensors.Sensor{Name: "nodeselector-test-sensor"}, nil
}

// registerDummyOnce guards the global handler registry, which panics on
// duplicate registration.
var registerDummyOnce sync.Once

func startRealManager(t *testing.T) *sensors.Manager {
	t.Helper()
	registerDummyOnce.Do(func() {
		sensors.RegisterPolicyHandlerAtInit("nodeselector-test-dummy", dummyPolicyHandler{})
	})
	mgr, err := sensors.StartSensorManager("")
	require.NoError(t, err)
	return mgr
}

// policyStatus returns the state and domain of policyName as reported by the
// manager, failing the test when the policy is absent.
func policyStatus(t *testing.T, mgr *sensors.Manager, policyName string) (tetragon.TracingPolicyState, string) {
	t.Helper()
	res, err := mgr.ListTracingPolicies(t.Context(), "")
	require.NoError(t, err)
	for _, pol := range res.GetPolicies() {
		if pol.GetName() == policyName {
			return pol.GetState(), pol.GetDomain()
		}
	}
	t.Fatalf("policy %q not found", policyName)
	return tetragon.TracingPolicyState_TP_STATE_UNKNOWN, ""
}

func TestNodeSelectorRealManager(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	host := map[string]string{"tetragon.io/arch": "amd64"}
	mgr := startRealManager(t)

	t.Run("file loader", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "match.yaml"),
			[]byte(archPolicyYAML("amd64")), 0o644))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "nomatch.yaml"),
			[]byte(archPolicyYAML("arm64")), 0o644))

		loader := NewDefaultLoader(nil, mgr, slog.Default(), host)
		require.NoError(t, LoadFromDir(ctx, dir, loader))

		state, domain := policyStatus(t, mgr, "amd64-only")
		require.Equal(t, tetragon.TracingPolicyState_TP_STATE_ENABLED, state)
		require.Equal(t, tracingpolicy.StaticDomain, domain)

		state, domain = policyStatus(t, mgr, "arm64-only")
		require.Equal(t, tetragon.TracingPolicyState_TP_STATE_SKIPPED, state)
		require.Equal(t, tracingpolicy.StaticDomain, domain)
	})
}

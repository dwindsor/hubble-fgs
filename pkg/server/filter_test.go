// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package server

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/rthooks"
	"github.com/cilium/tetragon/pkg/sensors"
	ossserver "github.com/cilium/tetragon/pkg/server"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
)

// fakeFGSServer records the policies the wrapped server is asked to load.
type fakeFGSServer struct {
	tetragon.UnimplementedFineGuidanceSensorsServer
	added []string
}

func (f *fakeFGSServer) AddTracingPolicy(_ context.Context, req *tetragon.AddTracingPolicyRequest) (*tetragon.AddTracingPolicyResponse, error) {
	tp, err := tracingpolicy.FromYAML(req.GetYaml())
	if err != nil {
		return nil, err
	}
	f.added = append(f.added, tp.TpName())
	return &tetragon.AddTracingPolicyResponse{}, nil
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

type dummyPolicyHandler struct{}

func (dummyPolicyHandler) PolicyHandler(_ tracingpolicy.TracingPolicy, _ policyfilter.PolicyID) (sensors.SensorIface, error) {
	return &sensors.Sensor{Name: "filter-test-sensor"}, nil
}

// registerDummyOnce guards the global handler registry, which panics on
// duplicate registration.
var registerDummyOnce sync.Once

func startRealManager(t *testing.T) *sensors.Manager {
	t.Helper()
	registerDummyOnce.Do(func() {
		sensors.RegisterPolicyHandlerAtInit("filter-test-dummy", dummyPolicyHandler{})
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

func TestFilterServer(t *testing.T) {
	host := map[string]string{"tetragon.io/arch": "amd64"}
	req := func(name, arch string) *tetragon.AddTracingPolicyRequest {
		return &tetragon.AddTracingPolicyRequest{Yaml: namedArchPolicyYAML(name, arch)}
	}

	t.Run("non-matching nodeSelector is recorded skipped", func(t *testing.T) {
		mgr, inner := startRealManager(t), &fakeFGSServer{}
		s := NewFilterServer(inner, mgr, slog.Default(), host)
		_, err := s.AddTracingPolicy(context.Background(), req("nomatch", "arm64"))
		require.NoError(t, err)
		state, _ := policyStatus(t, mgr, "nomatch")
		require.Equal(t, tetragon.TracingPolicyState_TP_STATE_SKIPPED, state)
		require.Empty(t, inner.added)
	})

	t.Run("matching nodeSelector delegates", func(t *testing.T) {
		mgr, inner := startRealManager(t), &fakeFGSServer{}
		s := NewFilterServer(inner, mgr, slog.Default(), host)
		_, err := s.AddTracingPolicy(context.Background(), req("match", "amd64"))
		require.NoError(t, err)
		require.Equal(t, []string{"match"}, inner.added)
		res, err := mgr.ListTracingPolicies(t.Context(), "")
		require.NoError(t, err)
		require.Empty(t, res.GetPolicies(), "delegated policy is not recorded by the filter")
	})

	t.Run("no host labels returns the server unwrapped", func(t *testing.T) {
		inner := &fakeFGSServer{}
		require.Same(t, inner, NewFilterServer(inner, nil, slog.Default(), nil))
		require.Same(t, inner, NewFilterServer(inner, nil, slog.Default(), map[string]string{}))
	})

	t.Run("malformed YAML falls through to the wrapped server", func(t *testing.T) {
		mgr, inner := startRealManager(t), &fakeFGSServer{}
		s := NewFilterServer(inner, mgr, slog.Default(), host)
		_, err := s.AddTracingPolicy(context.Background(), &tetragon.AddTracingPolicyRequest{Yaml: "not: [valid"})
		require.Error(t, err)
		require.Empty(t, inner.added)
	})
}

type fakeNotifier struct{}

func (fakeNotifier) AddListener(_ ossserver.Listener)                    {}
func (fakeNotifier) RemoveListener(_ ossserver.Listener)                 {}
func (fakeNotifier) NotifyListener(_ any, _ *tetragon.GetEventsResponse) {}

// TestFilterServerRealManager wraps the real OSS gRPC server around a real
// sensors.Manager, asserting the resulting policy states and grpc domain via
// ListTracingPolicies.
func TestFilterServerRealManager(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	host := map[string]string{"tetragon.io/arch": "amd64"}
	mgr := startRealManager(t)

	var wg sync.WaitGroup
	inner := ossserver.NewServer(ctx, &wg, fakeNotifier{}, mgr, rthooks.DummyHookRunner{}, nil)
	srv := NewFilterServer(inner, mgr, slog.Default(), host)

	add := func(name, arch string) {
		_, err := srv.AddTracingPolicy(ctx, &tetragon.AddTracingPolicyRequest{
			Yaml: namedArchPolicyYAML(name, arch),
		})
		require.NoError(t, err)
	}
	add("grpc-match", "amd64")
	add("grpc-nomatch", "arm64")

	state, domain := policyStatus(t, mgr, "grpc-match")
	require.Equal(t, tetragon.TracingPolicyState_TP_STATE_ENABLED, state)
	require.Equal(t, ossserver.GrpcDomain, domain)

	state, domain = policyStatus(t, mgr, "grpc-nomatch")
	require.Equal(t, tetragon.TracingPolicyState_TP_STATE_SKIPPED, state)
	require.Equal(t, ossserver.GrpcDomain, domain)
}

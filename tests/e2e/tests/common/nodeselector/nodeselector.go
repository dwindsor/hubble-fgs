// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

//go:build !windows

// Package nodeselector exercises spec.nodeSelector on a single-node cluster: a
// TracingPolicy is loaded on the agent only when the node's labels match the
// selector. Verification uses the ListTracingPolicies gRPC (the feature gates
// loading, not events): a gated-out policy is tracked as TP_STATE_SKIPPED, not
// loaded.
package nodeselector

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/tests/e2e/helpers"
	grpchelper "github.com/cilium/tetragon/tests/e2e/helpers/grpc"
	"github.com/cilium/tetragon/tests/e2e/runners"
	"github.com/cilium/tetragon/tests/e2e/state"
)

// testLabel is an arbitrary node label for the relabel case.
const testLabel = "tetragon.io/e2e-nodeselector"

const rpcTimeout = 5 * time.Second

// policyYAML renders a minimal cluster-scoped TracingPolicy gated on a single
// label. security_bprm_check with syscall:false loads on any node.
func policyYAML(name, key, value string) string {
	return fmt.Sprintf(`apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: %s
spec:
  nodeSelector:
    matchLabels:
      %s: %q
  kprobes:
    - call: security_bprm_check
      syscall: false
`, name, key, value)
}

// agentConn returns the forwarded gRPC connection to the single-node agent.
func agentConn(ctx context.Context) (*grpc.ClientConn, error) {
	conns, ok := ctx.Value(state.GrpcForwardedConns).(map[string]*grpc.ClientConn)
	if !ok || len(conns) == 0 {
		return nil, errors.New("no forwarded gRPC connections in context")
	}
	for _, conn := range conns {
		if conn != nil {
			return conn, nil
		}
	}
	return nil, errors.New("no usable gRPC connection")
}

// policyState returns policyName's state on the agent, or TP_STATE_UNKNOWN when
// it is not present.
func policyState(ctx context.Context, conn *grpc.ClientConn, policyName string) (tetragon.TracingPolicyState, error) {
	rpcCtx, cancel := context.WithTimeout(ctx, rpcTimeout)
	defer cancel()
	res, err := tetragon.NewFineGuidanceSensorsClient(conn).
		ListTracingPolicies(rpcCtx, &tetragon.ListTracingPoliciesRequest{})
	if err != nil {
		return tetragon.TracingPolicyState_TP_STATE_UNKNOWN, err
	}
	for _, pol := range res.GetPolicies() {
		if pol.GetName() == policyName {
			return pol.GetState(), nil
		}
	}
	return tetragon.TracingPolicyState_TP_STATE_UNKNOWN, nil
}

// waitPolicyState polls until policyName reaches wantState. Positive (enabled)
// waits use the OSS helper grpchelper.WaitForTracingPolicyWithTime; the skipped
// state has no equivalent there.
func waitPolicyState(ctx context.Context, conn *grpc.ClientConn, policyName string, wantState tetragon.TracingPolicyState, maxTries int) error {
	var state tetragon.TracingPolicyState
	var lastErr error
	for range maxTries {
		state, lastErr = policyState(ctx, conn, policyName)
		if lastErr == nil && state == wantState {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
	msg := fmt.Sprintf("policy %q state = %s, want %s", policyName, state, wantState)
	if lastErr != nil {
		return fmt.Errorf("%s: %w", msg, lastErr)
	}
	return errors.New(msg)
}

// firstNode returns the single node and its architecture label value.
func firstNode(ctx context.Context, c *envconf.Config) (string, string, error) {
	client, err := c.NewClient()
	if err != nil {
		return "", "", fmt.Errorf("new client: %w", err)
	}
	nodes := &corev1.NodeList{}
	if err := client.Resources().List(ctx, nodes); err != nil {
		return "", "", fmt.Errorf("list nodes: %w", err)
	}
	if len(nodes.Items) == 0 {
		return "", "", errors.New("no nodes found")
	}
	n := nodes.Items[0]
	return n.Name, n.Labels["kubernetes.io/arch"], nil
}

// labelNode sets (val != "") or removes (val == "") a label, retrying on the
// conflicts kubelet's frequent node updates cause.
func labelNode(ctx context.Context, c *envconf.Config, node, key, val string) error {
	client, err := c.NewClient()
	if err != nil {
		return fmt.Errorf("new client: %w", err)
	}
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var n corev1.Node
		if err := client.Resources().Get(ctx, node, "", &n); err != nil {
			return err
		}
		if n.Labels == nil {
			n.Labels = map[string]string{}
		}
		if val == "" {
			delete(n.Labels, key)
		} else {
			n.Labels[key] = val
		}
		return client.Resources().Update(ctx, &n)
	})
}

// Test runs the nodeSelector assessments against the single-node agent.
func Test(t *testing.T, runner *runners.Runner) {
	feat := features.New("nodeSelector").
		Assess("matching selector loads the policy", func(ctx context.Context, t *testing.T, c *envconf.Config) context.Context {
			_, arch, err := firstNode(ctx, c)
			require.NoError(t, err)
			require.NotEmpty(t, arch, "node is missing kubernetes.io/arch")

			const name = "nodeselector-match"
			yaml := policyYAML(name, "kubernetes.io/arch", arch)
			ctx, err = helpers.LoadCRDString("", yaml, false)(ctx, c)
			require.NoError(t, err)
			t.Cleanup(func() { _, _ = helpers.UnloadCRDString("", yaml, false)(context.Background(), c) })

			require.NoError(t, grpchelper.WaitForTracingPolicyWithTime(ctx, name, 30, time.Second),
				"policy with matching nodeSelector must load")
			return ctx
		}).
		Assess("non-matching selector is skipped", func(ctx context.Context, t *testing.T, c *envconf.Config) context.Context {
			conn, err := agentConn(ctx)
			require.NoError(t, err)

			const name = "nodeselector-nomatch"
			yaml := policyYAML(name, "kubernetes.io/arch", "no-such-arch")
			ctx, err = helpers.LoadCRDString("", yaml, false)(ctx, c)
			require.NoError(t, err)
			t.Cleanup(func() { _, _ = helpers.UnloadCRDString("", yaml, false)(context.Background(), c) })

			require.NoError(t, waitPolicyState(ctx, conn, name, tetragon.TracingPolicyState_TP_STATE_SKIPPED, 20),
				"policy with non-matching nodeSelector must be skipped")
			return ctx
		}).
		Assess("relabel loads then unloads the policy", func(ctx context.Context, t *testing.T, c *envconf.Config) context.Context {
			node, _, err := firstNode(ctx, c)
			require.NoError(t, err)
			conn, err := agentConn(ctx)
			require.NoError(t, err)

			const name = "nodeselector-relabel"
			yaml := policyYAML(name, testLabel, "yes")
			t.Cleanup(func() {
				_ = labelNode(context.Background(), c, node, testLabel, "")
				_, _ = helpers.UnloadCRDString("", yaml, false)(context.Background(), c)
			})

			ctx, err = helpers.LoadCRDString("", yaml, false)(ctx, c)
			require.NoError(t, err)
			require.NoError(t, waitPolicyState(ctx, conn, name, tetragon.TracingPolicyState_TP_STATE_SKIPPED, 15),
				"policy must be skipped before the node is labelled")

			require.NoError(t, labelNode(ctx, c, node, testLabel, "yes"))
			require.NoError(t, grpchelper.WaitForTracingPolicyWithTime(ctx, name, 30, time.Second),
				"labelling the node must load the policy (exercises the Node watch)")

			require.NoError(t, labelNode(ctx, c, node, testLabel, ""))
			require.NoError(t, waitPolicyState(ctx, conn, name, tetragon.TracingPolicyState_TP_STATE_SKIPPED, 30),
				"removing the label must skip the policy again")
			return ctx
		}).
		Feature()

	runner.Test(t, feat)
}

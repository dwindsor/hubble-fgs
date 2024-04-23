//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.
//

package sandboxpolicy

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/isovalent/hubble-fgs/pkg/sandboxpolicy"

	"github.com/cilium/tetragon/api/v1/tetragon"
	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/tests/e2e/checker"
	"github.com/cilium/tetragon/tests/e2e/helpers"
	"github.com/cilium/tetragon/tests/e2e/helpers/grpc"
	"github.com/cilium/tetragon/tests/e2e/runners"

	"k8s.io/klog/v2"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"
)

const (
	Namespace = "sandboxpolicy"
)

func Test(t *testing.T, runner *runners.Runner, testNamespace string) {
	runner.SetupExport(t)

	checker := sandboxChecker().WithTimeLimit(5 * time.Minute).WithEventLimit(10)
	runEventChecker := features.New("Run Event Checks").
		Assess("Run Event Checks", checker.CheckWithFilters(
			30*time.Second,
			// allow list
			[]*tetragon.Filter{{
				EventSet: []tetragon.EventType{
					tetragon.EventType_PROCESS_TRACEPOINT,
					tetragon.EventType_PROCESS_SANDBOX_SYSCALL,
				},
			}},
			// deny list
			[]*tetragon.Filter{},
		)).Feature()

	runWorkload := features.New("SandboxPolicy test").
		Assess("Install policy", func(ctx context.Context, _ *testing.T, c *envconf.Config) context.Context {
			ctx, err := helpers.LoadCRDString("", policy, false)(ctx, c)
			if err != nil {
				klog.ErrorS(err, "failed to install policy")
				t.FailNow()
			}
			t.Cleanup(func() {
				// NB: the policy is cluster-wide, so it will not be deleted when we
				// delete the namespace. Delete it here.
				helpers.UnloadCRDString("", policy, true)(ctx, c)
			})
			return ctx
		}).
		// NB(kkourt): This is buggy at the moment. We need to fix WaitForTracingPolicy in
		// OSS for this to work, so skip it for now.
		Assess("Wait for policy", func(ctx context.Context, _ *testing.T, _ *envconf.Config) context.Context {
			tpName := sandboxpolicy.TracingPolicyName("getcpu")
			if err := grpc.WaitForTracingPolicy(ctx, tpName); err != nil {
				klog.ErrorS(err, "failed to wait for policy")
				t.FailNow()
			}
			return ctx
		}).
		Assess("Start pods", func(ctx context.Context, _ *testing.T, c *envconf.Config) context.Context {
			ctx, err := helpers.LoadCRDString(testNamespace, getcpuPod, true)(ctx, c)
			if err != nil {
				klog.ErrorS(err, "failed to load pod")
				t.FailNow()
			}
			return ctx
		}).
		Assess("Wait for Checker", checker.Wait(30*time.Second)).
		Feature()

	runner.TestInParallel(t, runWorkload, runEventChecker)
}

// policy monitors getcpu() system call.
const policy = `
apiVersion: cilium.io/v1alpha1
kind: SandboxPolicy
metadata:
  name: "getcpu"
spec:
  syscalls:
    - op: "In"
      list:
      - name: "sys_getcpu"
      actions:
        - type: "Post"
`

// getcpuPod just does getcpu() systemcalls and then sleeps
const getcpuPod = `
kind: Deployment
apiVersion: apps/v1
metadata:
  name: getcpu-pod
spec:
  replicas: 1
  selector:
    matchLabels:
      app: "getcpu"
  template:
    metadata:
      labels:
        app: "getcpu"
    spec:
      containers:
      - name: getcpu
        image: ghcr.io/kkourt/getcpu:v0.3
        imagePullPolicy: Always
`

func sandboxChecker() *checker.RPCChecker {
	return checker.NewRPCChecker(&sandboxEventChecker{}, "sandboxpolicy-checker")
}

type sandboxEventChecker struct {
	matches int
}

func (c *sandboxEventChecker) NextEventCheck(event ec.Event, _ *logrus.Logger) (bool, error) {
	switch ev := event.(type) {
	case *tetragon.ProcessTracepoint:
		return true, errors.New("got an unexpected tracepoint event")
	case *tetragon.ProcessSandboxSyscall:
		if ev.Name != "getcpu" {
			return true, fmt.Errorf("got an unexpected systemcall (%s)", ev.Name)
		}
		c.matches++
	}

	// if we see 5 sandbox events, success!
	return c.matches >= 5, nil
}

func (c *sandboxEventChecker) FinalCheck(_ *logrus.Logger) error {
	if c.matches > 0 {
		return nil
	}
	return fmt.Errorf("sandbox checker failed, had %d matches", c.matches)
}

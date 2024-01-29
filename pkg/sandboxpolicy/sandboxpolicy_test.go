//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package sandboxpolicy

import (
	"context"
	"fmt"
	"syscall"
	"testing"

	// NB: we need to load these two so that the policy handlers are loaded
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/logger"
	_ "github.com/cilium/tetragon/pkg/sensors/tracing"
	"github.com/cilium/tetragon/pkg/testutils"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/exec"
	"github.com/sirupsen/logrus"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/reader/notify"
	"github.com/cilium/tetragon/pkg/sensors"
	testsensor "github.com/cilium/tetragon/pkg/sensors/test"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
	grpc "github.com/isovalent/hubble-fgs/pkg/grpc/sandbox"
	"github.com/isovalent/hubble-fgs/pkg/sensors/base"
	"github.com/isovalent/hubble-fgs/pkg/testutils/perfring"
	testprogs "github.com/isovalent/hubble-fgs/pkg/testutils/progs"

	"github.com/stretchr/testify/require"
	"sigs.k8s.io/yaml"
)

var (
	verboseMessages = false
)

type testCase struct {
	name                string
	syscallSpec         v1alpha1.SandboxSyscallsSpec
	runSyscalls         func(*testing.T, *testprogs.SyscallTester)
	expectedEventsCheck func(t *testing.T, m map[string]int)
	shouldSkip          func() string
	cmdErrorCheck       func(t *testing.T, err error)
}

//revive:disable:context-as-argument
func (tc *testCase) Run(t *testing.T, ctx context.Context) {
	testutils.CaptureLog(t, logger.GetLogger().(*logrus.Logger))
	st := testprogs.StartSyscallTester(t, ctx)
	if tc.shouldSkip != nil {
		if reason := tc.shouldSkip(); reason != "" {
			t.Skip(reason)
		}
	}

	sandboxSpec := v1alpha1.SandboxSpec{
		PodSelector: nil,
		Syscalls:    []v1alpha1.SandboxSyscallsSpec{tc.syscallSpec},
	}

	// create the tracing policy from the sandbox spec, and add a PID filter for the program
	tp, err := toTracingPolicy(tc.name, &sandboxSpec)
	require.NoError(t, err)
	// testtp.AddPidFilter(t, &tp.GenericTracingPolicy.Spec, st.Process().Pid)

	if verboseMessages { // for debugging
		out, err := yaml.Marshal(tp)
		if err != nil {
			t.Fatalf("failed to convert tp: %v", err)
		}
		t.Logf("Generated policy:\n%s\n", out)
	}

	// create the sensor from the tracing policy and load it together with the base sensor and
	// the test sensor.
	ret, err := sensors.SensorsFromPolicy(tp, policyfilter.NoFilterID)
	if err != nil {
		t.Fatalf("GetSensorsFromParserPolicy failed: %v", err)
	} else if len(ret) > 2 {
		// enforcement policies will have two sensors: the tracepoint one and the killer
		t.Fatalf("GetSensorsFromParserPolicy returned unexpected number of sensors (%d)", len(ret))
	}
	tus.LoadSensor(t, base.GetInitialSensor())
	tus.LoadSensor(t, testsensor.GetTestSensor())
	for i := range ret {
		tus.LoadSensor(t, ret[i])
	}

	// run the test
	events := perfring.RunTestFreqCount(
		t, ctx,
		func() {
			// execute syscalls
			tc.runSyscalls(t, st)
		},
		func(x notify.Message) string {
			switch msg := x.(type) {
			case *grpc.MsgRawSyscall:
				var spEvent tetragon.ProcessSandboxSyscall
				err := msg.Translate(&spEvent)
				if err != nil {
					return fmt.Sprintf("error=%v", err)
				}
				return spEvent.Name

			default:
				// ignore all other events
				return ""
			}
		},
	)
	// remove ignored events
	delete(events, "")
	tc.expectedEventsCheck(t, events)

	// stop syscall-tester
	_ = st.Stop()
	err = st.Cmd.Wait()

	if tc.cmdErrorCheck != nil {
		tc.cmdErrorCheck(t, err)
	} else {
		require.NoError(t, err)
	}
}

func TestSandboxPolicies(t *testing.T) {
	tcs := []testCase{
		{
			name: "getcpu-in",
			syscallSpec: v1alpha1.SandboxSyscallsSpec{
				List: []v1alpha1.SandboxSyscallItem{
					{Name: "sys_getcpu"},
				},
				Op: "In",
				Actions: []v1alpha1.SandboxAction{
					{Type: "Post"},
				},
			},
			runSyscalls: func(t *testing.T, st *testprogs.SyscallTester) {
				ret, err := st.GetCPU()
				require.NoError(t, err)
				require.Equal(t, ret, 0)

			},
			expectedEventsCheck: func(t *testing.T, m map[string]int) {
				require.Equal(t, m, map[string]int{"getcpu": 1})
			},
		}, {
			name: "getcpu-notin",
			syscallSpec: v1alpha1.SandboxSyscallsSpec{
				List: []v1alpha1.SandboxSyscallItem{
					{Name: "sys_getcpu"},
				},
				Op: "NotIn",
				Actions: []v1alpha1.SandboxAction{
					{Type: "Post"},
				},
			},
			runSyscalls: func(t *testing.T, st *testprogs.SyscallTester) {
				ret, err := st.GetCPU()
				require.Equal(t, ret, 0)
				require.NoError(t, err)
			},
			expectedEventsCheck: func(t *testing.T, m map[string]int) {
				require.NotContains(t, m, "getcpu")
			},
		}, {
			name: "getcpu-block",
			syscallSpec: v1alpha1.SandboxSyscallsSpec{
				List: []v1alpha1.SandboxSyscallItem{
					{Name: "sys_getcpu"},
				},
				Op: "In",
				Actions: []v1alpha1.SandboxAction{
					{Type: "Post"},
					{Type: "Block"},
				},
			},
			runSyscalls: func(t *testing.T, st *testprogs.SyscallTester) {
				ret, err := st.GetCPU()
				require.NoError(t, err)
				require.Equal(t, ret, int(syscall.EPERM))

			},
			expectedEventsCheck: func(t *testing.T, m map[string]int) {
				require.Equal(t, m, map[string]int{"getcpu": 1})
			},
			shouldSkip: func() string {
				if !bpf.HasOverrideHelper() && !bpf.HasModifyReturnSyscall() {
					return "no override support"
				}
				if !bpf.HasSignalHelper() {
					return "no signal helper"
				}
				return ""
			},
		}, {
			name: "getcpu-signal",
			syscallSpec: v1alpha1.SandboxSyscallsSpec{
				List: []v1alpha1.SandboxSyscallItem{
					{Name: "sys_getcpu"},
				},
				Op: "In",
				Actions: []v1alpha1.SandboxAction{
					{Type: "Post"},
					{Type: "Block"},
					{Type: "Signal"},
				},
			},
			runSyscalls: func(t *testing.T, st *testprogs.SyscallTester) {
				st.GetCPU()
				// NB: the program will be killed

			},
			expectedEventsCheck: func(t *testing.T, m map[string]int) {
				require.Equal(t, m, map[string]int{"getcpu": 1})
			},
			shouldSkip: func() string {
				if !bpf.HasOverrideHelper() && !bpf.HasModifyReturnSyscall() {
					return "no override support"
				}
				if !bpf.HasSignalHelper() {
					return "no signal helper"
				}
				return ""
			},
			cmdErrorCheck: func(t *testing.T, err error) {
				require.NotNil(t, err)
				require.Equal(t, err.Error(), "signal: killed")
			},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()
	for i := range tcs {
		t.Run(tcs[i].name, func(t *testing.T) {
			tcs[i].Run(t, ctx)
		})
	}
}

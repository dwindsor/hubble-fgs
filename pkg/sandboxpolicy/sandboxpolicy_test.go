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
	"testing"

	// NB: we need to load these two so that the policy handlers are loaded
	_ "github.com/cilium/tetragon/pkg/sensors/tracing"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/exec"

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
	testtp "github.com/isovalent/hubble-fgs/pkg/testutils/tracingpolicy"

	"github.com/stretchr/testify/require"
)

type testCase struct {
	name                string
	syscallSpec         v1alpha1.SandboxSyscallsSpec
	runSyscalls         func(*testing.T, *testprogs.SyscallTester)
	expectedEventsCheck func(t *testing.T, m map[string]int)
}

func (tc *testCase) Run(t *testing.T, ctx context.Context) {
	st := testprogs.StartSyscallTester(t, ctx)

	sandboxSpec := v1alpha1.SandboxSpec{
		PodSelector: nil,
		Syscalls:    []v1alpha1.SandboxSyscallsSpec{tc.syscallSpec},
	}

	// create the tracing policy from the sandbox spec, and add a PID filter for the program
	tp, err := toTracingPolicy(tc.name, &sandboxSpec)
	require.NoError(t, err)
	testtp.AddPidFilter(t, &tp.GenericTracingPolicy.Spec, st.Process().Pid)

	// create the sensor from the tracing policy and load it together with the base sensor and
	// the test sensor.
	ret, err := sensors.SensorsFromPolicy(tp, policyfilter.NoFilterID)
	if err != nil {
		t.Fatalf("GetSensorsFromParserPolicy failed: %v", err)
	} else if len(ret) != 1 {
		t.Fatalf("GetSensorsFromParserPolicy returned unexpected number of sensors (%d)", len(ret))
	}
	tpSensor := ret[0]
	tus.LoadSensor(t, base.GetInitialSensor())
	tus.LoadSensor(t, testsensor.GetTestSensor())
	tus.LoadSensor(t, tpSensor)

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
	err = st.Stop()
	require.NoError(t, err)
	err = st.Cmd.Wait()
	require.NoError(t, err)
}

func TestSandboxPolicies(t *testing.T) {
	tcs := []testCase{
		{
			name: "getcpu-in",
			syscallSpec: v1alpha1.SandboxSyscallsSpec{
				List: []v1alpha1.SandboxSyscallItem{
					{Name: "getcpu"},
				},
				Op: "In",
				Actions: []v1alpha1.SandboxAction{
					{Type: "Post"},
				},
			},
			runSyscalls: func(t *testing.T, st *testprogs.SyscallTester) {
				_, err := st.GetCPU()
				require.NoError(t, err)
			},
			expectedEventsCheck: func(t *testing.T, m map[string]int) {
				require.Equal(t, m, map[string]int{"getcpu": 1})
			},
		}, {
			name: "getcpu-notin",
			syscallSpec: v1alpha1.SandboxSyscallsSpec{
				List: []v1alpha1.SandboxSyscallItem{
					{Name: "getcpu"},
				},
				Op: "NotIn",
				Actions: []v1alpha1.SandboxAction{
					{Type: "Post"},
				},
			},
			runSyscalls: func(t *testing.T, st *testprogs.SyscallTester) {
				_, err := st.GetCPU()
				require.NoError(t, err)
			},
			expectedEventsCheck: func(t *testing.T, m map[string]int) {
				require.NotContains(t, m, "getcpu")
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

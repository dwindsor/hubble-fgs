// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.
//

//go:build sudo_tests

package layer3_test

import (
	"context"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/tetragon/pkg/jsonchecker"
	"github.com/cilium/tetragon/pkg/matchers/durationmatcher"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"

	enterpriseoth "github.com/isovalent/hubble-fgs/pkg/observer/observertesthelper"
	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"

	_ "github.com/isovalent/hubble-fgs/pkg/sensors/exec"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3"
	"github.com/isovalent/hubble-fgs/pkg/sensors/utils"

	cli "github.com/isovalent/hubble-fgs/pkg/testutils/cliswitches"
	enterprisepolicytest "github.com/isovalent/hubble-fgs/pkg/testutils/policytest"
	"github.com/isovalent/hubble-fgs/pkg/testutils/runner"
	_ "github.com/isovalent/hubble-fgs/tests/policytests"
)

const rawsockConfigWithCloseEventsWithoutEnable = `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "rawsock"
spec:
  parser:
    rawsock:
      reportClose: true
`

func TestRawsockCreateClose(t *testing.T) {
	enterprisepolicytest.DoObserverTest(t, "layer3-rawsock-create-close", nil)
}

func TestRawsockCreateCloseCLI(t *testing.T) {
	enterprisepolicytest.DoObserverTest(t, "layer3-rawsock-create-close-no-policy", nil)
}

func TestRawsockCLISwitch(t *testing.T) {
	if !utils.RawHooksAvailable() {
		t.Skipf("This test requires raw socket support, skipping")
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	require.NoError(t, cli.SetSwitches(t, []cli.SwitchSettings{
		{KeyPtr: &enterpriseOption.Config.EnableRawsock, Value: true},
		{KeyPtr: &enterpriseOption.Config.Layer3CLIEnable, Value: true},
	}))

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker("selfExec").
			WithProcess(selfChecker).
			WithParent(ec.NewProcessChecker()),
		ec.NewProcessRawsockCreateChecker("rawsockCreate").
			WithProcess(selfChecker),
		ec.NewProcessRawsockCloseChecker("rawsockClose").
			WithProcess(selfChecker).
			WithDuration(durationmatcher.Between(&durationmatcher.Duration{Duration: time.Duration(0)},
				&durationmatcher.Duration{Duration: time.Duration(20 * time.Second)})),
	)

	obs := enterpriseoth.GetNoConfigObserver(t, ctx, true)
	require.NoError(t, layer3.StartLayer3Progs(ctx, nil))
	tp, err := tracingpolicy.FromYAML(rawsockConfigWithCloseEventsWithoutEnable)
	if err != nil {
		t.Fatalf("failed to parse tracingpolicy: %s", err)
	}

	if err := observer.GetSensorManager().AddTracingPolicy(ctx, tp); err != nil {
		t.Fatalf("SensorManager.AddTracingPolicy error: %s\n", err)
	}

	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)

	readyWG.Wait()

	// syscall.Socket needs a ForkLock. See https://go.dev/src/syscall/exec_unix.go
	syscall.ForkLock.Lock()

	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, syscall.ETH_P_LOOP)
	assert.NoError(t, err)

	syscall.Close(fd)
	syscall.ForkLock.Unlock()

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestRawsockCLISwitch2(t *testing.T) {
	if !utils.RawHooksAvailable() {
		t.Skipf("This test requires raw socket support, skipping")
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	require.NoError(t, cli.SetSwitches(t, []cli.SwitchSettings{
		{KeyPtr: &enterpriseOption.Config.Layer3CLIEnable, Value: true},
		{KeyPtr: &enterpriseOption.Config.EnableRawsock, Value: true},
		{KeyPtr: &enterpriseOption.Config.RawsockReportClose, Value: true},
	}))

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker("selfExec").
			WithProcess(selfChecker).
			WithParent(ec.NewProcessChecker()),
		ec.NewProcessRawsockCreateChecker("rawsockCreate").
			WithProcess(selfChecker),
		ec.NewProcessRawsockCloseChecker("rawsockClose").
			WithProcess(selfChecker).
			WithDuration(durationmatcher.Between(&durationmatcher.Duration{Duration: time.Duration(0)},
				&durationmatcher.Duration{Duration: time.Duration(20 * time.Second)})),
	)

	obs := enterpriseoth.GetNoConfigObserver(t, ctx, true)
	require.NoError(t, layer3.StartLayer3Progs(ctx, nil))

	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)

	readyWG.Wait()

	// syscall.Socket needs a ForkLock. See https://go.dev/src/syscall/exec_unix.go
	syscall.ForkLock.Lock()

	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, syscall.ETH_P_LOOP)
	assert.NoError(t, err)

	syscall.Close(fd)
	syscall.ForkLock.Unlock()

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

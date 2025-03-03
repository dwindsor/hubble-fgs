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

package layer3_test

import (
	"context"
	"sync"
	"syscall"
	"testing"
	"time"

	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/pkg/jsonchecker"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/matchers/durationmatcher"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"
	"github.com/stretchr/testify/assert"

	_ "github.com/isovalent/hubble-fgs/pkg/sensors/exec"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3"

	"github.com/isovalent/hubble-fgs/pkg/testutils/runner"
)

const rawsockConfigWithCloseEvents = `
apiversion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "rawsock"
spec:
  parser:
    rawsock:
      enable: true
      reportClose: true
`

const rawsockConfigWithCloseEventsWithoutEnable = `
apiversion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "rawsock"
spec:
  parser:
    rawsock:
      reportClose: true
`

// NB(kkourt): Function(t *testing.T, ctx context.Context) is the reasonable
// thing to do here even if revive complains.
//
//revive:disable:context-as-argument
func getRawsockObserverWithEnable(t *testing.T, ctx context.Context) *observer.Observer {
	return getLayer3Observer(t, ctx, rawsockConfigWithCloseEvents, true)
}

func testRawsockCreateClose(t *testing.T, ty int) {
	if v := "5.4.0"; !kernels.MinKernelVersion(v) {
		t.Skipf("Minimum kernel version (%v) not met, skipping", v)
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

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
			WithDuration(durationmatcher.Between(&durationmatcher.Duration{Duration: time.Duration(1 * time.Second)},
				&durationmatcher.Duration{Duration: time.Duration(20 * time.Second)})),
	)

	obs := getRawsockObserverWithEnable(t, ctx)
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)

	readyWG.Wait()

	// syscall.Socket needs a ForkLock. See https://go.dev/src/syscall/exec_unix.go
	syscall.ForkLock.Lock()
	var fd int
	var err error

	switch ty {
	case 1:
		fd, err = syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, syscall.ETH_P_LOOP)
	case 2:
		fd, err = syscall.Socket(syscall.AF_PACKET, syscall.SOCK_DGRAM, syscall.ETH_P_IP)
	case 3:
		fd, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_UDP)
	case 4:
		fd, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	case 5:
		fd, err = syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, syscall.ETH_P_ALL)
	case 6:
		fd, err = syscall.Socket(syscall.AF_PACKET, syscall.SOCK_DGRAM, syscall.ETH_P_ALL)
	}
	assert.NoError(t, err)
	time.Sleep(1000 * time.Millisecond)

	syscall.Close(fd)
	syscall.ForkLock.Unlock()

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestRawsockCreateClose1(t *testing.T) {
	testRawsockCreateClose(t, 1)
}

func TestRawsockCreateClose2(t *testing.T) {
	testRawsockCreateClose(t, 2)
}

func TestRawsockCreateClose3(t *testing.T) {
	testRawsockCreateClose(t, 3)
}

func TestRawsockCreateClose4(t *testing.T) {
	testRawsockCreateClose(t, 4)
}

func TestRawsockCreateClose5(t *testing.T) {
	testRawsockCreateClose(t, 5)
}

func TestRawsockCreateClose6(t *testing.T) {
	testRawsockCreateClose(t, 6)
}

func TestRawsockCLISwitch(t *testing.T) {
	if v := "5.4.0"; !kernels.MinKernelVersion(v) {
		t.Skipf("Minimum kernel version (%v) not met, skipping", v)
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	oldEnableRawsockValue := enterpriseOption.Config.EnableRawsock
	enterpriseOption.Config.EnableRawsock = true
	oldLayer3CLIEnableValue := enterpriseOption.Config.Layer3CLIEnable
	enterpriseOption.Config.Layer3CLIEnable = true
	t.Cleanup(func() {
		enterpriseOption.Config.EnableRawsock = oldEnableRawsockValue
		enterpriseOption.Config.Layer3CLIEnable = oldLayer3CLIEnableValue
	})

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
			WithDuration(durationmatcher.Between(&durationmatcher.Duration{Duration: time.Duration(1 * time.Second)},
				&durationmatcher.Duration{Duration: time.Duration(20 * time.Second)})),
	)

	obs := getNoConfigObserver(t, ctx, true)
	layer3.StartLayer3Progs(ctx)
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
	time.Sleep(1000 * time.Millisecond)

	syscall.Close(fd)
	syscall.ForkLock.Unlock()

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

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

//go:build sudo_tests

package layer3_test

import (
	"context"
	"fmt"
	"sync"
	"syscall"
	"testing"
	"time"

	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/pkg/jsonchecker"
	"github.com/cilium/tetragon/pkg/matchers/durationmatcher"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"
	"github.com/stretchr/testify/assert"

	_ "github.com/isovalent/hubble-fgs/pkg/sensors/exec"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3"
	"github.com/isovalent/hubble-fgs/pkg/sensors/utils"

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

func TestRawsockBasic(t *testing.T) {
	if !utils.RawHooksAvailable() {
		t.Skipf("This test requires raw socket support, skipping")
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	obs := getRawsockObserverWithEnable(t, ctx)
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)

	for testNum := 1; testNum <= 6; testNum++ {
		t.Logf("Running test: %d", testNum)
		if !t.Run(fmt.Sprintf("Rawsock%d", testNum), func(lt *testing.T) {
			testRawsockCreateClose(t, lt, &readyWG, testNum)
		}) {
			t.Logf("Test %d failed", testNum)
			break
		}
		t.Logf("Test %d was successful", testNum)
	}
}

func testRawsockCreateClose(gt *testing.T, t *testing.T, readyWG *sync.WaitGroup, ty int) {
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

	syscall.Close(fd)
	syscall.ForkLock.Unlock()

	err = jsonchecker.JsonTestCheck(gt, checker)
	assert.NoError(t, err)
}

func TestRawsockCLISwitch(t *testing.T) {
	if !utils.RawHooksAvailable() {
		t.Skipf("This test requires raw socket support, skipping")
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
			WithDuration(durationmatcher.Between(&durationmatcher.Duration{Duration: time.Duration(0)},
				&durationmatcher.Duration{Duration: time.Duration(20 * time.Second)})),
	)

	obs := getNoConfigObserver(t, ctx, true)
	layer3.StartLayer3Progs(ctx, nil)
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

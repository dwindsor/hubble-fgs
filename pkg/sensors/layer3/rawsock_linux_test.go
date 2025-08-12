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
	"os/exec"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/tetragon/pkg/jsonchecker"
	"github.com/cilium/tetragon/pkg/matchers/durationmatcher"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	osstestutils "github.com/cilium/tetragon/pkg/testutils"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"

	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"

	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"

	_ "github.com/isovalent/hubble-fgs/pkg/sensors/exec"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3"
	"github.com/isovalent/hubble-fgs/pkg/sensors/utils"

	"github.com/isovalent/hubble-fgs/pkg/testutils"
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

type rawTests struct {
	suite.Suite
	doneWG, readyWG sync.WaitGroup
	ctx             context.Context
	cancel          context.CancelFunc
}

func TestRawsockCreateClose(t *testing.T) {
	if !utils.RawHooksAvailable() {
		t.Skipf("This test requires raw socket support, skipping")
	}
	if !utils.CGroupSKBAvailable() {
		t.Skipf("This test requires CGroup/SKB, skipping")
	}
	suite.Run(t, new(rawTests))
}

func (suite *rawTests) SetupSuite() {
	suite.ctx, suite.cancel = context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	obs := getRawsockObserverWithEnable(suite.T(), suite.ctx)
	observertesthelper.LoopEvents(suite.ctx, suite.T(), &suite.doneWG, &suite.readyWG, obs)
}

func (suite *rawTests) HandleStats(_ string, stats *suite.SuiteInformation) {
	if stats.Passed() {
		osstestutils.DoneWithExportFile(suite.T())
	}
}

func (suite *rawTests) TearDownSuite() {
	suite.cancel()
}

type rawTest int

const (
	noneNoneNone rawTest = iota
	packetRawLoop
	packetDgramIp
	inetRawUdp
	inetRawRaw
	packetRawAll
	packetDgramAll
)

// These are in alphabetical order to match the order they'll likely run in.
func (suite *rawTests) TestRawsockInetRawRaw() {
	suite.testRawsockCreateClose(inetRawRaw)
}

func (suite *rawTests) TestRawsockInetRawUdp() {
	suite.testRawsockCreateClose(inetRawUdp)
}

func (suite *rawTests) TestRawsockPacketDgramAll() {
	suite.testRawsockCreateClose(packetDgramAll)
}

func (suite *rawTests) TestRawsockPacketDgramIp() {
	suite.testRawsockCreateClose(packetDgramIp)
}

func (suite *rawTests) TestRawsockPacketRawAll() {
	suite.testRawsockCreateClose(packetRawAll)
}

func (suite *rawTests) TestRawsockPacketRawLoop() {
	suite.testRawsockCreateClose(packetRawLoop)
}

// NB(kkourt): Function(t *testing.T, ctx context.Context) is the reasonable
// thing to do here even if revive complains.
//
//revive:disable:context-as-argument
func getRawsockObserverWithEnable(t *testing.T, ctx context.Context) *observer.Observer {
	return getLayer3Observer(t, ctx, rawsockConfigWithCloseEvents, true)
}

func (suite *rawTests) testRawsockCreateClose(ty rawTest) {
	suite.readyWG.Wait()

	rawsockBinary := testutils.RepoRootPath("contrib/tester-progs/net/rawsock")
	rawTestStr := fmt.Sprintf("%d", ty)
	rawsockCmd := exec.Command(rawsockBinary, rawTestStr)
	err := rawsockCmd.Run()
	suite.Require().NoError(err, "cannot run rawsock helper")

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))
	rawsockChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix("rawsock")).
		WithArguments(sm.Full(rawTestStr))
	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker("selfExec").
			WithProcess(selfChecker).
			WithParent(ec.NewProcessChecker()),
		ec.NewProcessExecChecker("rawsockExec").
			WithProcess(rawsockChecker).
			WithParent(selfChecker),
		ec.NewProcessRawsockCreateChecker("rawsockCreate").
			WithProcess(rawsockChecker),
		ec.NewProcessRawsockCloseChecker("rawsockClose").
			WithProcess(rawsockChecker).
			WithDuration(durationmatcher.Between(&durationmatcher.Duration{Duration: time.Duration(0)},
				&durationmatcher.Duration{Duration: time.Duration(20 * time.Second)})),
	)

	err = jsonchecker.JsonTestCheck(suite.T(), checker)
	assert.NoError(suite.T(), err)
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

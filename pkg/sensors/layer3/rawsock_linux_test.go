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
	"fmt"
	"os/exec"
	"runtime"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/tetragon/pkg/jsonchecker"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/matchers/durationmatcher"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	osstestutils "github.com/cilium/tetragon/pkg/testutils"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"

	enterpriseoth "github.com/isovalent/hubble-fgs/pkg/observer/observertesthelper"
	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"

	_ "github.com/isovalent/hubble-fgs/pkg/sensors/exec"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3"
	"github.com/isovalent/hubble-fgs/pkg/sensors/utils"

	"github.com/isovalent/hubble-fgs/pkg/testutils"
	cli "github.com/isovalent/hubble-fgs/pkg/testutils/cliswitches"
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
	switches        []cli.SwitchSettings
	useCLI          bool
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

func TestRawsockCreateCloseCLI(t *testing.T) {
	if !utils.RawHooksAvailable() {
		t.Skipf("This test requires raw socket support, skipping")
	}
	if !utils.CGroupSKBAvailable() {
		t.Skipf("This test requires CGroup/SKB, skipping")
	}
	suite.Run(t, new(rawTests{useCLI: true}))
}

func (suite *rawTests) SetupSuite() {
	suite.ctx, suite.cancel = context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)

	if suite.useCLI {
		var err error
		suite.switches, err = cli.SetConfigFromSwitches([]cli.SwitchSettings{
			{KeyPtr: &enterpriseOption.Config.Layer3CLIEnable, Value: true},
			{KeyPtr: &enterpriseOption.Config.EnableNetworkEvents, Value: true},
			{KeyPtr: &enterpriseOption.Config.EnableRawsock, Value: true},
			{KeyPtr: &enterpriseOption.Config.RawsockReportClose, Value: true},
		})
		suite.Require().NoError(err)
	}

	obs := enterpriseoth.GetNoConfigObserver(suite.T(), suite.ctx, false)
	suite.Require().NoError(layer3.StartLayer3Progs(suite.ctx, nil))

	if !suite.useCLI {
		tp, err := tracingpolicy.FromYAML(rawsockConfigWithCloseEvents)
		suite.Require().NoError(err)
		err = observer.GetSensorManager().AddTracingPolicy(suite.ctx, tp)
		suite.Require().NoError(err)
	}

	observertesthelper.LoopEvents(suite.ctx, suite.T(), &suite.doneWG, &suite.readyWG, obs)
}

func (suite *rawTests) HandleStats(_ string, stats *suite.SuiteInformation) {
	if stats.Passed() {
		osstestutils.DoneWithExportFile(suite.T())
	}
}

func (suite *rawTests) TearDownSuite() {
	suite.cancel()
	cli.RevertSwitchesConfig(suite.switches)
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

func (suite *rawTests) testRawsockCreateClose(ty rawTest) {
	suite.readyWG.Wait()

	if runtime.GOARCH != "amd64" && !kernels.MinKernelVersion("5.8.0") {
		suite.T().Skip("Test requires amd64 or kernel >=5.8")
	}

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

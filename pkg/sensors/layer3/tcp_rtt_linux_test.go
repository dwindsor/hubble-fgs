// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

//go:build sudo_tests

package layer3_test

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"runtime"
	"syscall"
	"testing"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/kernels"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/sensors/config/confmap"
	osstestutils "github.com/cilium/tetragon/pkg/testutils"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
	"github.com/stretchr/testify/suite"

	"github.com/cilium/tetragon/api/v1/tetragon"
	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"

	"github.com/cilium/tetragon/pkg/jsonchecker"

	enterpriseoth "github.com/isovalent/hubble-fgs/pkg/observer/observertesthelper"
	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3"
	"github.com/isovalent/hubble-fgs/pkg/sensors/utils"
	cli "github.com/isovalent/hubble-fgs/pkg/testutils/cliswitches"
	"github.com/isovalent/hubble-fgs/pkg/testutils/runner"

	_ "github.com/isovalent/hubble-fgs/pkg/sensors/exec"
)

// Setting TCP RTT max to 1,000,000 means 1% equates to
// 10ms, which a packet across loopback should easily be
// quicker than.
const tcpBasicConfigWithRTTDetection = `
apiversion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "tcp"
spec:
  parser:
    tcp:
      enable: true
      histogram:
        enable: true
        min: 0
        max: 1000000
`

// NB(kkourt): Function(t *testing.T, ctx context.Context) is the reasonable
// thing to do here even if revive complains.
//
//revive:disable:context-as-argument
type TCPRTT struct {
	TCPCommon
}

func TestTCPRTT(t *testing.T) {
	// timing related tests are unreliable currently. In lieu of a solution, let's
	// disable these tests.
	t.Skipf("Test disabled due to unreliable timing in CI")

	if !utils.RTTHookAvailable() {
		t.Skipf("RTT hooks are unavailable, skipping")
	}

	suite.Run(t, new(TCPRTT))
}

func TestTCPRTTCLI(t *testing.T) {
	// timing related tests are unreliable currently. In lieu of a solution, let's
	// disable these tests.
	t.Skipf("Test disabled due to unreliable timing in CI")

	if !utils.RTTHookAvailable() {
		t.Skipf("RTT hooks are unavailable, skipping")
	}

	suite.Run(t, new(TCPRTT{useCLI: true}))
}

func (suite *TCPRTT) SetupSuite() {
	suite.ctx, suite.cancel = context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	if suite.useCLI {
		var err error
		suite.switches, err = cli.SetConfigFromSwitches([]cli.SwitchSettings{
			{KeyPtr: &enterpriseOption.Config.Layer3CLIEnable, Value: true},
			{KeyPtr: &enterpriseOption.Config.EnableNetworkEvents, Value: true},
			{KeyPtr: &enterpriseOption.Config.EnableTCP, Value: true},
			{KeyPtr: &enterpriseOption.Config.EnableTCPMetrics, Value: true},
			{KeyPtr: &enterpriseOption.Config.EnableTCPRTT, Value: true},
			{KeyPtr: &enterpriseOption.Config.TCPRTTHistMin, Value: uint32(0)},
			{KeyPtr: &enterpriseOption.Config.TCPRTTHistMax, Value: uint32(1000000)},
		})
		suite.Require().NoError(err)
	}
	obs := enterpriseoth.GetNoConfigObserver(suite.T(), suite.ctx, true)
	suite.Require().NoError(layer3.StartLayer3Progs(suite.ctx, nil))

	if !suite.useCLI {
		tp, err := tracingpolicy.FromYAML(tcpBasicConfigWithRTTDetection)
		suite.Require().NoError(err)
		err = observer.GetSensorManager().AddTracingPolicy(suite.ctx, tp)
		suite.Require().NoError(err)
	}

	option.Config.UsePerfRingBuffer = true
	confmap.UpdateTgRuntimeConf(bpf.MapPrefixPath(), os.Getpid())
	observertesthelper.LoopEvents(suite.ctx, suite.T(), &suite.doneWG, &suite.readyWG, obs)
}

func (suite *TCPRTT) HandleStats(_ string, stats *suite.SuiteInformation) {
	if stats.Passed() {
		osstestutils.DoneWithExportFile(suite.T())
	}
}

func (suite *TCPRTT) TearDownSuite() {
	suite.cancel()
	cli.RevertSwitchesConfig(suite.switches)
}

func (suite *TCPRTT) TestDetectRTT4() {
	// timing related tests are unreliable currently. In lieu of a solution, let's
	// disable these tests.
	suite.T().Skipf("Test disabled due to unreliable timing in CI")
	if runtime.GOARCH != "amd64" && !kernels.MinKernelVersion("5.8.0") {
		suite.T().Skip("Test requires amd64 or kernel >=5.8")
	}

	server := getNCCommand(suite.T(), "nc.openbsd")
	client := server

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	ncChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(server)).
		WithArguments(sm.Full("-nvlp 8083 -s 0.0.0.0"))

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker("selfExec").
			WithProcess(selfChecker).
			WithParent(ec.NewProcessChecker()),
		ec.NewProcessExecChecker("ncExec").
			WithProcess(ncChecker).
			WithParent(selfChecker),
		ec.NewProcessListenChecker("ncListen").
			WithProcess(ncChecker).
			WithParent(selfChecker).
			WithIp(sm.Full("0.0.0.0")).
			WithPort(8083).
			WithProtocol(tetragon.SocketProtocol_TCP),
		ec.NewProcessAcceptChecker("ncAccept").
			WithProcess(ncChecker).
			WithParent(selfChecker).
			WithSourceIp(sm.Full("127.0.0.1")).
			WithSourcePort(8083).
			WithProtocol(tetragon.SocketProtocol_TCP),
		ec.NewProcessCloseChecker("ncClose").
			WithProcess(ncChecker).
			WithParent(selfChecker).
			WithSourceIp(sm.Full("127.0.0.1")).
			WithSourcePort(8083).
			WithProtocol(tetragon.SocketProtocol_TCP).
			WithSocketType(sm.Full("accept")).
			WithStats(ec.NewSocketStatsChecker().
				WithRtt(ec.NewHistogramChecker().
					WithBuckets(ec.NewHistogramBucketListMatcher().
						WithValues(ec.NewHistogramBucketChecker().
							WithPercentile(1))))))

	suite.readyWG.Wait()
	cmdServer := exec.Command(server, "-nvlp", "8083", "-s", "0.0.0.0")
	stdout, err := cmdServer.StdoutPipe()
	suite.Assert().NoError(err)
	suite.Assert().NoError(cmdServer.Start())
	err = waitForSocketToListen(suite.T(), net.ParseIP("0.0.0.0"), 8083, syscall.IPPROTO_TCP, syscall.AF_INET)
	suite.Assert().NoError(err)

	cmdClient := exec.Command(client, "127.0.0.1", "8083")
	stdin, err := cmdClient.StdinPipe()
	suite.Assert().NoError(err)
	suite.Assert().NoError(cmdClient.Start())
	sendData(suite.T(), stdin, "hello")
	waitForData(suite.T(), stdout, "hello")

	killAndWaitCommand(suite.T(), cmdClient)
	killAndWaitCommand(suite.T(), cmdServer)

	err = jsonchecker.JsonTestCheck(suite.T(), checker)
	suite.Assert().NoError(err)
}

func (suite *TCPRTT) TestDetectSRTT4() {
	// timing related tests are unreliable currently. In lieu of a solution, let's
	// disable these tests.
	suite.T().Skipf("Test disabled due to unreliable timing in CI")
	if runtime.GOARCH != "amd64" && !kernels.MinKernelVersion("5.8.0") {
		suite.T().Skip("Test requires amd64 or kernel >=5.8")
	}

	server := getNCCommand(suite.T(), "nc.openbsd")
	client := server

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	ncChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(server)).
		WithArguments(sm.Full("-nvlp 8184 -s 0.0.0.0"))

	serverStatsChecker := ec.NewProcessSockStatsChecker("serverStats").
		WithProcess(ncChecker).
		WithParent(selfChecker).
		WithSocket(ec.NewSockInfoChecker().
			WithProtocol(tetragon.SocketProtocol_TCP).
			WithSourceIp(sm.Full("127.0.0.1")).
			WithDestinationIp(sm.Full("127.0.0.1")).
			WithSourcePort(8184))

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker("selfExec").
			WithProcess(selfChecker).
			WithParent(ec.NewProcessChecker()),
		ec.NewProcessExecChecker("ncExec").
			WithProcess(ncChecker).
			WithParent(selfChecker),
		ec.NewProcessListenChecker("ncListen").
			WithProcess(ncChecker).
			WithParent(selfChecker).
			WithIp(sm.Full("0.0.0.0")).
			WithPort(8184).
			WithProtocol(tetragon.SocketProtocol_TCP),
		ec.NewProcessAcceptChecker("ncAccept").
			WithProcess(ncChecker).
			WithParent(selfChecker).
			WithSourceIp(sm.Full("127.0.0.1")).
			WithSourcePort(8184).
			WithProtocol(tetragon.SocketProtocol_TCP),
		ec.NewProcessCloseChecker("ncClose").
			WithProcess(ncChecker).
			WithParent(selfChecker).
			WithSourceIp(sm.Full("127.0.0.1")).
			WithSourcePort(8184).
			WithProtocol(tetragon.SocketProtocol_TCP).
			WithSocketType(sm.Full("accept")))

	statsChecker := &ec.FnEventChecker{
		NextCheckFn: func(event_ ec.Event, _ *slog.Logger) (bool, error) {
			event, ok := event_.(*tetragon.ProcessSockStats)
			if !ok {
				return false, fmt.Errorf("event is not a sockstats event")
			}

			if event.Stats == nil {
				return false, fmt.Errorf("event has no stats field")
			}

			if serverStatsChecker.Check(event) == nil {
				if event.Stats.Srtt <= 0 {
					return false, fmt.Errorf("event SRTT <= 0")
				}
				if event.Stats.Srtt > 1000 {
					return false, fmt.Errorf("event SRTT > 1000us")
				}
				return false, nil
			}

			return false, fmt.Errorf("sockstats event is not from server")
		},
		FinalCheckFn: func(_ *slog.Logger) error {
			return nil
		},
	}

	suite.readyWG.Wait()
	cmdServer := exec.Command(server, "-nvlp", "8184", "-s", "0.0.0.0")
	stdout, err := cmdServer.StdoutPipe()
	suite.Assert().NoError(err)
	suite.Assert().NoError(cmdServer.Start())
	err = waitForSocketToListen(suite.T(), net.ParseIP("0.0.0.0"), 8184, syscall.IPPROTO_TCP, syscall.AF_INET)
	suite.Assert().NoError(err)

	cmdClient := exec.Command(client, "127.0.0.1", "8184")
	stdin, err := cmdClient.StdinPipe()
	suite.Assert().NoError(err)
	suite.Assert().NoError(cmdClient.Start())
	sendData(suite.T(), stdin, "hello")
	waitForData(suite.T(), stdout, "hello")

	killAndWaitCommand(suite.T(), cmdClient)
	killAndWaitCommand(suite.T(), cmdServer)

	err = jsonchecker.JsonTestCheck(suite.T(), checker)
	suite.Assert().NoError(err)

	err = jsonchecker.JsonTestCheck(suite.T(), statsChecker)
	suite.Assert().NoError(err)
}

func (suite *TCPRTT) TestDetectRTT6() {
	// timing related tests are unreliable currently. In lieu of a solution, let's
	// disable these tests.
	suite.T().Skipf("Test disabled due to unreliable timing in CI")
	if runtime.GOARCH != "amd64" && !kernels.MinKernelVersion("5.8.0") {
		suite.T().Skip("Test requires amd64 or kernel >=5.8")
	}

	server := getNCCommand(suite.T(), "nc.openbsd")
	client := server

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	ncChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(server)).
		WithArguments(sm.Full("-6nvlp 8083 -s ::"))

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker("selfExec").
			WithProcess(selfChecker).
			WithParent(ec.NewProcessChecker()),
		ec.NewProcessExecChecker("ncExec").
			WithProcess(ncChecker).
			WithParent(selfChecker),
		ec.NewProcessListenChecker("ncListen").
			WithProcess(ncChecker).
			WithParent(selfChecker).
			WithIp(sm.Full("::")).
			WithPort(8083).
			WithProtocol(tetragon.SocketProtocol_TCP),
		ec.NewProcessAcceptChecker("ncAccept").
			WithProcess(ncChecker).
			WithParent(selfChecker).
			WithSourceIp(sm.Full("::1")).
			WithSourcePort(8083).
			WithProtocol(tetragon.SocketProtocol_TCP),
		ec.NewProcessCloseChecker("ncClose").
			WithProcess(ncChecker).
			WithParent(selfChecker).
			WithSourceIp(sm.Full("::1")).
			WithSourcePort(8083).
			WithProtocol(tetragon.SocketProtocol_TCP).
			WithSocketType(sm.Full("accept")).
			WithStats(ec.NewSocketStatsChecker().
				WithRtt(ec.NewHistogramChecker().
					WithBuckets(ec.NewHistogramBucketListMatcher().
						WithValues(ec.NewHistogramBucketChecker().
							WithPercentile(1))))))

	suite.readyWG.Wait()
	cmdServer := exec.Command(server, "-6nvlp", "8083", "-s", "::")
	stdout, err := cmdServer.StdoutPipe()
	suite.Assert().NoError(err)
	suite.Assert().NoError(cmdServer.Start())
	err = waitForSocketToListen(suite.T(), net.ParseIP("::"), 8083, syscall.IPPROTO_TCP, syscall.AF_INET6)
	suite.Assert().NoError(err)

	cmdClient := exec.Command(client, "-6n", "::1", "8083")
	stdin, err := cmdClient.StdinPipe()
	suite.Assert().NoError(err)
	suite.Assert().NoError(cmdClient.Start())
	sendData(suite.T(), stdin, "hello")
	waitForData(suite.T(), stdout, "hello")

	killAndWaitCommand(suite.T(), cmdClient)
	killAndWaitCommand(suite.T(), cmdServer)

	err = jsonchecker.JsonTestCheck(suite.T(), checker)
	suite.Assert().NoError(err)
}

// FIXME: net io_uring test seems to time out on ARM.
func (suite *TCPRTT) TestDetectSRTT6() {
	// timing related tests are unreliable currently. In lieu of a solution, let's
	// disable these tests.
	suite.T().Skipf("Test disabled due to unreliable timing in CI")

	if runtime.GOARCH != "amd64" && !kernels.MinKernelVersion("5.8.0") {
		suite.T().Skip("Test requires amd64 or kernel >=5.8")
	}

	server := getNCCommand(suite.T(), "nc.openbsd")
	client := server

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	ncChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(server)).
		WithArguments(sm.Full("-6nvlp 8184 -s ::"))

	serverStatsChecker := ec.NewProcessSockStatsChecker("serverStats").
		WithProcess(ncChecker).
		WithParent(selfChecker).
		WithSocket(ec.NewSockInfoChecker().
			WithProtocol(tetragon.SocketProtocol_TCP).
			WithSourceIp(sm.Full("::1")).
			WithDestinationIp(sm.Full("::1")).
			WithSourcePort(8184))

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker("selfExec").
			WithProcess(selfChecker).
			WithParent(ec.NewProcessChecker()),
		ec.NewProcessExecChecker("ncExec").
			WithProcess(ncChecker).
			WithParent(selfChecker),
		ec.NewProcessListenChecker("ncListen").
			WithProcess(ncChecker).
			WithParent(selfChecker).
			WithIp(sm.Full("::")).
			WithPort(8184).
			WithProtocol(tetragon.SocketProtocol_TCP),
		ec.NewProcessAcceptChecker("ncAccept").
			WithProcess(ncChecker).
			WithParent(selfChecker).
			WithSourceIp(sm.Full("::1")).
			WithSourcePort(8184).
			WithProtocol(tetragon.SocketProtocol_TCP),
		ec.NewProcessCloseChecker("ncClose").
			WithProcess(ncChecker).
			WithParent(selfChecker).
			WithSourceIp(sm.Full("::1")).
			WithSourcePort(8184).
			WithProtocol(tetragon.SocketProtocol_TCP).
			WithSocketType(sm.Full("accept")))

	statsChecker := &ec.FnEventChecker{
		NextCheckFn: func(event_ ec.Event, _ *slog.Logger) (bool, error) {
			event, ok := event_.(*tetragon.ProcessSockStats)
			if !ok {
				return false, fmt.Errorf("event is not a sockstats event")
			}

			if event.Stats == nil {
				return false, fmt.Errorf("event has no stats field")
			}

			if serverStatsChecker.Check(event) == nil {
				if event.Stats.Srtt <= 0 {
					return false, fmt.Errorf("event SRTT <= 0")
				}
				if event.Stats.Srtt > 1000 {
					return false, fmt.Errorf("event SRTT > 1000us")
				}
				return false, nil
			}

			return false, fmt.Errorf("sockstats event is not from server")
		},
		FinalCheckFn: func(_ *slog.Logger) error {
			return nil
		},
	}

	suite.readyWG.Wait()
	cmdServer := exec.Command(server, "-6nvlp", "8184", "-s", "::")
	stdout, err := cmdServer.StdoutPipe()
	suite.Assert().NoError(err)
	suite.Assert().NoError(cmdServer.Start())
	err = waitForSocketToListen(suite.T(), net.ParseIP("::"), 8184, syscall.IPPROTO_TCP, syscall.AF_INET6)
	suite.Assert().NoError(err)

	cmdClient := exec.Command(client, "-6n", "::1", "8184")
	stdin, err := cmdClient.StdinPipe()
	suite.Assert().NoError(err)
	suite.Assert().NoError(cmdClient.Start())
	sendData(suite.T(), stdin, "hello")
	waitForData(suite.T(), stdout, "hello")

	killAndWaitCommand(suite.T(), cmdClient)
	killAndWaitCommand(suite.T(), cmdServer)

	err = jsonchecker.JsonTestCheck(suite.T(), checker)
	suite.Assert().NoError(err)

	err = jsonchecker.JsonTestCheck(suite.T(), statsChecker)
	suite.Assert().NoError(err)
}

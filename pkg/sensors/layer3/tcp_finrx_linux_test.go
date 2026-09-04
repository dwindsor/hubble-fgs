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
	"bufio"
	"context"
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"syscall"
	"testing"

	"github.com/cilium/tetragon/pkg/kernels"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	osstestutils "github.com/cilium/tetragon/pkg/testutils"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
	"github.com/stretchr/testify/suite"

	"github.com/cilium/tetragon/api/v1/tetragon"
	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"

	enterpriseoth "github.com/isovalent/hubble-fgs/pkg/observer/observertesthelper"
	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"
	"github.com/isovalent/hubble-fgs/pkg/testutils"
	cli "github.com/isovalent/hubble-fgs/pkg/testutils/cliswitches"
	"github.com/isovalent/hubble-fgs/pkg/testutils/runner"

	_ "github.com/isovalent/hubble-fgs/pkg/sensors/exec"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3"
	"github.com/isovalent/hubble-fgs/pkg/sensors/utils"
)

// quoteEmptyArg mirrors how sensors/exec renders an empty argv entry
// (resolveArgs in exec_linux.go), so expected argument strings built here
// match the process arguments actually reported for a "" pattern.
func quoteEmptyArg(s string) string {
	if s == "" {
		return `""`
	}
	return s
}

func waitForSocket(s *bufio.Scanner) {
	for s.Scan() {
		line := s.Text()
		if line == "Waiting..." {
			break
		}
	}
}

func (suite *TCPFinRx) testFinRx(port uint32, serverIterations, clientIterations int,
	serverPattern, clientPattern string, serverSignal, clientSignal syscall.Signal,
	serverBytes, clientBytes uint64) {
	if runtime.GOARCH != "amd64" && !kernels.MinKernelVersion("5.8.0") {
		suite.T().Skip("Test requires amd64 or kernel >=5.8")
	}

	// use different ports to avoid time wait issues upsetting the tests.
	if suite.useCLI {
		port += 1000
	}

	client := testutils.RepoRootPath("contrib/tester-progs/net/tcp_client")
	server := testutils.RepoRootPath("contrib/tester-progs/net/tcp_server")

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	srvChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(server)).
		WithArguments(sm.Full(fmt.Sprintf("%d %d %s", port, serverIterations, quoteEmptyArg(serverPattern))))

	cliChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(client)).
		WithArguments(sm.Full(fmt.Sprintf("%d %d %s", port, clientIterations, quoteEmptyArg(clientPattern))))

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker("selfExec").
			WithProcess(selfChecker).
			WithParent(ec.NewProcessChecker()),
		ec.NewProcessExecChecker("serverExec").
			WithProcess(srvChecker).
			WithParent(selfChecker),
		ec.NewProcessExecChecker("clientExec").
			WithProcess(cliChecker).
			WithParent(selfChecker),
		ec.NewProcessConnectChecker("clientConnect").
			WithProcess(cliChecker).
			WithParent(selfChecker).
			WithSourceIp(sm.Full("127.0.0.1")).
			WithDestinationPort(port).
			WithDestinationIp(sm.Full("127.0.0.1")).
			WithProtocol(tetragon.SocketProtocol_TCP),
		ec.NewProcessCloseChecker("clientClose").
			WithProcess(cliChecker).
			WithParent(selfChecker).
			WithSourceIp(sm.Full("127.0.0.1")).
			WithDestinationPort(port).
			WithDestinationIp(sm.Full("127.0.0.1")).
			WithProtocol(tetragon.SocketProtocol_TCP).
			WithSocketType(sm.Full("connect")).
			WithStats(ec.NewSocketStatsChecker().
				WithBytesSent(clientBytes).
				WithBytesReceived(serverBytes)),
		ec.NewProcessAcceptChecker("serverAccept").
			WithProcess(srvChecker).
			WithParent(selfChecker).
			WithSourceIp(sm.Full("127.0.0.1")).
			WithSourcePort(port).
			WithDestinationIp(sm.Full("127.0.0.1")).
			WithProtocol(tetragon.SocketProtocol_TCP),
		ec.NewProcessCloseChecker("serverClose").
			WithProcess(srvChecker).
			WithParent(selfChecker).
			WithSourceIp(sm.Full("127.0.0.1")).
			WithSourcePort(port).
			WithDestinationIp(sm.Full("127.0.0.1")).
			WithProtocol(tetragon.SocketProtocol_TCP).
			WithSocketType(sm.Full("accept")).
			WithStats(ec.NewSocketStatsChecker().
				WithBytesSent(serverBytes).
				WithBytesReceived(clientBytes)),
	)

	suite.readyWG.Wait()

	cmdServer := exec.Command(server, fmt.Sprintf("%d", port), fmt.Sprintf("%d", serverIterations), serverPattern)
	serverOut, err := cmdServer.StdoutPipe()
	suite.Require().NoError(err, "could not connect to server output pipe")

	err = cmdServer.Start()
	suite.Require().NoError(err, "cannot start server")
	suite.T().Logf("Started the server")

	waitForSocketToListen(suite.T(), net.ParseIP("127.0.0.1"), uint16(port), syscall.IPPROTO_TCP, syscall.AF_INET)

	serverScanner := bufio.NewScanner(serverOut)
	suite.Require().NoError(serverScanner.Err())
	for serverScanner.Scan() {
		line := serverScanner.Text()
		if line == "Ready!" {
			break
		}
	}

	cmdClient := exec.Command(client, fmt.Sprintf("%d", port), fmt.Sprintf("%d", clientIterations), clientPattern)
	clientOut, err := cmdClient.StdoutPipe()
	suite.Require().NoError(err, "could not connect to client output pipe")

	err = cmdClient.Start()
	suite.Require().NoError(err, "cannot start client")

	clientScanner := bufio.NewScanner(clientOut)

	if clientSignal == 0 {
		// No signal means expect it to end.
		err = cmdClient.Wait()
		if err != nil {
			killAndWaitCommand(suite.T(), cmdServer)
			suite.T().Fatal(err)
		}
	}

	if serverSignal == 0 {
		// No signal means expect it to end.
		err = cmdServer.Wait()
		if err != nil {
			if clientSignal != 0 {
				killAndWaitCommand(suite.T(), cmdClient)
			}
			suite.T().Fatal(err)
		}
	}

	if clientSignal != 0 {
		waitForSocket(clientScanner)
		signalAndWaitCommand(suite.T(), cmdClient, clientSignal)
	}

	if serverSignal != 0 {
		waitForSocket(serverScanner)
		signalAndWaitCommand(suite.T(), cmdServer, serverSignal)
	}

	err = waitAndCheckForSocketsToClose(suite.T(), checker, net.ParseIP("127.0.0.1"), uint16(port), syscall.IPPROTO_TCP, syscall.AF_INET)
	suite.Assert().NoError(err)
}

type TCPFinRx struct {
	TCPCommon
}

func TestTCPFinRx(t *testing.T) {
	// For reliability, we really need the sockops handlers as the kprobes can be
	// unreliable. Note, the technology should work from kernel v5.5 (it needs
	// probe_read_kernel in Cgroup/SKB programs).
	if !utils.SupportCGroupSKBProbeRead() {
		t.Skipf("This test requires CGroup/SKB, skipping")
	}
	suite.Run(t, new(TCPFinRx))
}

func TestTCPFinRxCLI(t *testing.T) {
	// For reliability, we really need the sockops handlers as the kprobes can be
	// unreliable. Note, the technology should work from kernel v5.5 (it needs
	// probe_read_kernel in Cgroup/SKB programs).
	if !utils.SupportCGroupSKBProbeRead() {
		t.Skipf("This test requires CGroup/SKB, skipping")
	}
	suite.Run(t, new(TCPFinRx{useCLI: true}))
}

func (suite *TCPFinRx) SetupSuite() {
	suite.ctx, suite.cancel = context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)

	if suite.useCLI {
		var err error
		suite.switches, err = cli.SetConfigFromSwitches([]cli.SwitchSettings{
			{KeyPtr: &enterpriseOption.Config.Layer3CLIEnable, Value: true},
			{KeyPtr: &enterpriseOption.Config.EnableNetworkEvents, Value: true},
			{KeyPtr: &enterpriseOption.Config.EnableTCP, Value: true},
			{KeyPtr: &enterpriseOption.Config.EnableTCPMetrics, Value: true},
		})
		suite.Require().NoError(err)
	}
	obs := enterpriseoth.GetNoConfigObserver(suite.T(), suite.ctx, true)
	suite.Require().NoError(layer3.StartLayer3Progs(suite.ctx, nil))

	if !suite.useCLI {
		tp, err := tracingpolicy.FromYAML(tcpBasicConfig)
		suite.Require().NoError(err)
		err = observer.GetSensorManager().AddTracingPolicy(suite.ctx, tp)
		suite.Require().NoError(err)
	}

	observertesthelper.LoopEvents(suite.ctx, suite.T(), &suite.doneWG, &suite.readyWG, obs)
}

func (suite *TCPFinRx) HandleStats(_ string, stats *suite.SuiteInformation) {
	if stats.Passed() {
		osstestutils.DoneWithExportFile(suite.T())
	}
}

func (suite *TCPFinRx) TearDownSuite() {
	suite.cancel()
	cli.RevertSwitchesConfig(suite.switches)
}

func (suite *TCPFinRx) TestRecvOnlyKillServerKillClient() {
	suite.testFinRx(3551, -1, -1, "SW", "RW", syscall.SIGKILL, syscall.SIGKILL, 5, 0)
}

func (suite *TCPFinRx) TestRecvOnlyKillServerHupClient() {
	suite.testFinRx(3552, -1, -1, "SW", "RW", syscall.SIGKILL, syscall.SIGHUP, 5, 0)
}

func (suite *TCPFinRx) TestRecvOnlyKillServerTermClient() {
	suite.testFinRx(3553, -1, -1, "SW", "RW", syscall.SIGKILL, syscall.SIGTERM, 5, 0)
}

func (suite *TCPFinRx) TestRecvOnlyKillServerExitClient() {
	suite.testFinRx(3554, -1, 1, "SW", "R", syscall.SIGKILL, 0, 5, 0)
}

func (suite *TCPFinRx) TestRecvOnlyHupServerKillClient() {
	suite.testFinRx(3555, -1, -1, "SW", "RW", syscall.SIGHUP, syscall.SIGKILL, 5, 0)
}

func (suite *TCPFinRx) TestRecvOnlyHupServerHupClient() {
	suite.testFinRx(3556, -1, -1, "SW", "RW", syscall.SIGHUP, syscall.SIGHUP, 5, 0)
}

func (suite *TCPFinRx) TestRecvOnlyHupServerTermClient() {
	suite.testFinRx(3557, -1, -1, "SW", "RW", syscall.SIGHUP, syscall.SIGTERM, 5, 0)
}

func (suite *TCPFinRx) TestRecvOnlyHupServerExitClient() {
	suite.testFinRx(3558, -1, 1, "SW", "R", syscall.SIGHUP, 0, 5, 0)
}

func (suite *TCPFinRx) TestRecvOnlyTermServerKillClient() {
	suite.testFinRx(3559, -1, -1, "SW", "RW", syscall.SIGTERM, syscall.SIGKILL, 5, 0)
}

func (suite *TCPFinRx) TestRecvOnlyTermServerHupClient() {
	suite.testFinRx(3560, -1, -1, "SW", "RW", syscall.SIGTERM, syscall.SIGHUP, 5, 0)
}

func (suite *TCPFinRx) TestRecvOnlyTermServerTermClient() {
	suite.testFinRx(3561, -1, -1, "SW", "RW", syscall.SIGTERM, syscall.SIGTERM, 5, 0)
}

func (suite *TCPFinRx) TestRecvOnlyTermServerExitClient() {
	suite.testFinRx(3562, -1, 1, "SW", "R", syscall.SIGTERM, 0, 5, 0)
}

func (suite *TCPFinRx) TestRecvOnlyExitServerKillClient() {
	suite.testFinRx(3563, 1, -1, "S", "RW", 0, syscall.SIGKILL, 5, 0)
}

func (suite *TCPFinRx) TestRecvOnlyExitServerHupClient() {
	suite.testFinRx(3564, 1, -1, "S", "RW", 0, syscall.SIGHUP, 5, 0)
}

func (suite *TCPFinRx) TestRecvOnlyExitServerTermClient() {
	suite.testFinRx(3565, 1, -1, "S", "RW", 0, syscall.SIGTERM, 5, 0)
}

func (suite *TCPFinRx) TestRecvOnlyExitServerExitClient() {
	suite.testFinRx(3566, 1, 1, "S", "R", 0, 0, 5, 0)
}

func (suite *TCPFinRx) TestSendOnlyKillServerKillClient() {
	suite.testFinRx(3567, -1, -1, "RW", "SW", syscall.SIGKILL, syscall.SIGKILL, 0, 5)
}

func (suite *TCPFinRx) TestSendOnlyKillServerHupClient() {
	suite.testFinRx(3568, -1, -1, "RW", "SW", syscall.SIGKILL, syscall.SIGHUP, 0, 5)
}

func (suite *TCPFinRx) TestSendOnlyKillServerTermClient() {
	suite.testFinRx(3569, -1, -1, "RW", "SW", syscall.SIGKILL, syscall.SIGTERM, 0, 5)
}

func (suite *TCPFinRx) TestSendOnlyKillServerExitClient() {
	suite.testFinRx(3570, -1, 1, "RW", "S", syscall.SIGKILL, 0, 0, 5)
}

func (suite *TCPFinRx) TestSendOnlyHupServerKillClient() {
	suite.testFinRx(3571, -1, -1, "RW", "SW", syscall.SIGHUP, syscall.SIGKILL, 0, 5)
}

func (suite *TCPFinRx) TestSendOnlyHupServerHupClient() {
	suite.testFinRx(3572, -1, -1, "RW", "SW", syscall.SIGHUP, syscall.SIGHUP, 0, 5)
}

func (suite *TCPFinRx) TestSendOnlyHupServerTermClient() {
	suite.testFinRx(3573, -1, -1, "RW", "SW", syscall.SIGHUP, syscall.SIGTERM, 0, 5)
}

func (suite *TCPFinRx) TestSendOnlyHupServerExitClient() {
	suite.testFinRx(3574, -1, 1, "RW", "S", syscall.SIGHUP, 0, 0, 5)
}

func (suite *TCPFinRx) TestSendOnlyTermServerKillClient() {
	suite.testFinRx(3575, -1, -1, "RW", "SW", syscall.SIGTERM, syscall.SIGKILL, 0, 5)
}

func (suite *TCPFinRx) TestSendOnlyTermServerHupClient() {
	suite.testFinRx(3576, -1, -1, "RW", "SW", syscall.SIGTERM, syscall.SIGHUP, 0, 5)
}

func (suite *TCPFinRx) TestSendOnlyTermServerTermClient() {
	suite.testFinRx(3577, -1, -1, "RW", "SW", syscall.SIGTERM, syscall.SIGTERM, 0, 5)
}

func (suite *TCPFinRx) TestSendOnlyTermServerExitClient() {
	suite.testFinRx(3578, -1, 1, "RW", "S", syscall.SIGTERM, 0, 0, 5)
}

func (suite *TCPFinRx) TestSendOnlyExitServerKillClient() {
	suite.testFinRx(3579, 1, -1, "R", "SW", 0, syscall.SIGKILL, 0, 5)
}

func (suite *TCPFinRx) TestSendOnlyExitServerHupClient() {
	suite.testFinRx(3580, 1, -1, "R", "SW", 0, syscall.SIGHUP, 0, 5)
}

func (suite *TCPFinRx) TestSendOnlyExitServerTermClient() {
	suite.testFinRx(3581, 1, -1, "R", "SW", 0, syscall.SIGTERM, 0, 5)
}

func (suite *TCPFinRx) TestSendOnlyExitServerExitClient() {
	suite.testFinRx(3582, 1, 1, "R", "S", 0, 0, 0, 5)
}

func (suite *TCPFinRx) TestSendRecvKillServerKillClient() {
	suite.testFinRx(3583, -1, -1, "RSW", "SRW", syscall.SIGKILL, syscall.SIGKILL, 5, 5)
}

func (suite *TCPFinRx) TestSendRecvKillServerHupClient() {
	suite.testFinRx(3584, -1, -1, "RSW", "SRW", syscall.SIGKILL, syscall.SIGHUP, 5, 5)
}

func (suite *TCPFinRx) TestSendRecvKillServerTermClient() {
	suite.testFinRx(3585, -1, -1, "RSW", "SRW", syscall.SIGKILL, syscall.SIGTERM, 5, 5)
}

func (suite *TCPFinRx) TestSendRecvKillServerExitClient() {
	suite.testFinRx(3586, -1, 1, "RSW", "SR", syscall.SIGKILL, 0, 5, 5)
}

func (suite *TCPFinRx) TestSendRecvHupServerKillClient() {
	suite.testFinRx(3587, -1, -1, "RSW", "SRW", syscall.SIGHUP, syscall.SIGKILL, 5, 5)
}

func (suite *TCPFinRx) TestSendRecvHupServerHupClient() {
	suite.testFinRx(3588, -1, -1, "RSW", "SRW", syscall.SIGHUP, syscall.SIGHUP, 5, 5)
}

func (suite *TCPFinRx) TestSendRecvHupServerTermClient() {
	suite.testFinRx(3589, -1, -1, "RSW", "SRW", syscall.SIGHUP, syscall.SIGTERM, 5, 5)
}

func (suite *TCPFinRx) TestSendRecvHupServerExitClient() {
	suite.testFinRx(3590, -1, 1, "RSW", "SR", syscall.SIGHUP, 0, 5, 5)
}

func (suite *TCPFinRx) TestSendRecvTermServerKillClient() {
	suite.testFinRx(3591, -1, -1, "RSW", "SRW", syscall.SIGTERM, syscall.SIGKILL, 5, 5)
}

func (suite *TCPFinRx) TestSendRecvTermServerHupClient() {
	suite.testFinRx(3592, -1, -1, "RSW", "SRW", syscall.SIGTERM, syscall.SIGHUP, 5, 5)
}

func (suite *TCPFinRx) TestSendRecvTermServerTermClient() {
	suite.testFinRx(3593, -1, -1, "RSW", "SRW", syscall.SIGTERM, syscall.SIGTERM, 5, 5)
}

func (suite *TCPFinRx) TestSendRecvTermServerExitClient() {
	suite.testFinRx(3594, -1, 1, "RSW", "SR", syscall.SIGTERM, 0, 5, 5)
}

func (suite *TCPFinRx) TestSendRecvExitServerKillClient() {
	suite.testFinRx(3595, 1, -1, "RS", "SRW", 0, syscall.SIGKILL, 5, 5)
}

func (suite *TCPFinRx) TestSendRecvExitServerHupClient() {
	suite.testFinRx(3596, 1, -1, "RS", "SRW", 0, syscall.SIGHUP, 5, 5)
}

func (suite *TCPFinRx) TestSendRecvExitServerTermClient() {
	suite.testFinRx(3597, 1, -1, "RS", "SRW", 0, syscall.SIGTERM, 5, 5)
}

func (suite *TCPFinRx) TestSendRecvExitServerExitClient() {
	suite.testFinRx(3598, 1, 1, "RS", "SR", 0, 0, 5, 5)
}

func (suite *TCPFinRx) TestRecvSendKillServerKillClient() {
	suite.testFinRx(3599, -1, -1, "SRW", "RSW", syscall.SIGKILL, syscall.SIGKILL, 5, 5)
}

func (suite *TCPFinRx) TestRecvSendKillServerHupClient() {
	suite.testFinRx(3600, -1, -1, "SRW", "RSW", syscall.SIGKILL, syscall.SIGHUP, 5, 5)
}

func (suite *TCPFinRx) TestRecvSendKillServerTermClient() {
	suite.testFinRx(3601, -1, -1, "SRW", "RSW", syscall.SIGKILL, syscall.SIGTERM, 5, 5)
}

func (suite *TCPFinRx) TestRecvSendKillServerExitClient() {
	suite.testFinRx(3602, -1, 1, "SRW", "RS", syscall.SIGKILL, 0, 5, 5)
}

func (suite *TCPFinRx) TestRecvSendHupServerKillClient() {
	suite.testFinRx(3603, -1, -1, "SRW", "RSW", syscall.SIGHUP, syscall.SIGKILL, 5, 5)
}

func (suite *TCPFinRx) TestRecvSendHupServerHupClient() {
	suite.testFinRx(3604, -1, -1, "SRW", "RSW", syscall.SIGHUP, syscall.SIGHUP, 5, 5)
}

func (suite *TCPFinRx) TestRecvSendHupServerTermClient() {
	suite.testFinRx(3605, -1, -1, "SRW", "RSW", syscall.SIGHUP, syscall.SIGTERM, 5, 5)
}

func (suite *TCPFinRx) TestRecvSendHupServerExitClient() {
	suite.testFinRx(3606, -1, 1, "SRW", "RS", syscall.SIGHUP, 0, 5, 5)
}

func (suite *TCPFinRx) TestRecvSendTermServerKillClient() {
	suite.testFinRx(3607, -1, -1, "SRW", "RSW", syscall.SIGTERM, syscall.SIGKILL, 5, 5)
}

func (suite *TCPFinRx) TestRecvSendTermServerHupClient() {
	suite.testFinRx(3608, -1, -1, "SRW", "RSW", syscall.SIGTERM, syscall.SIGHUP, 5, 5)
}

func (suite *TCPFinRx) TestRecvSendTermServerTermClient() {
	suite.testFinRx(3609, -1, -1, "SRW", "RSW", syscall.SIGTERM, syscall.SIGTERM, 5, 5)
}

func (suite *TCPFinRx) TestRecvSendTermServerExitClient() {
	suite.testFinRx(3610, -1, 1, "SRW", "RS", syscall.SIGTERM, 0, 5, 5)
}

func (suite *TCPFinRx) TestRecvSendExitServerKillClient() {
	suite.testFinRx(3611, 1, -1, "SR", "RSW", 0, syscall.SIGKILL, 5, 5)
}

func (suite *TCPFinRx) TestRecvSendExitServerHupClient() {
	suite.testFinRx(3612, 1, -1, "SR", "RSW", 0, syscall.SIGHUP, 5, 5)
}

func (suite *TCPFinRx) TestRecvSendExitServerTermClient() {
	suite.testFinRx(3613, 1, -1, "SR", "RSW", 0, syscall.SIGTERM, 5, 5)
}

func (suite *TCPFinRx) TestRecvSendExitServerExitClient() {
	suite.testFinRx(3614, 1, 1, "SR", "RS", 0, 0, 5, 5)
}

func (suite *TCPFinRx) TestSilentKillServerKillClient() {
	suite.testFinRx(3615, -1, -1, "W", "W", syscall.SIGKILL, syscall.SIGKILL, 0, 0)
}

func (suite *TCPFinRx) TestSilentKillServerHupClient() {
	suite.testFinRx(3616, -1, -1, "W", "W", syscall.SIGKILL, syscall.SIGHUP, 0, 0)
}

func (suite *TCPFinRx) TestSilentKillServerTermClient() {
	suite.testFinRx(3617, -1, -1, "W", "W", syscall.SIGKILL, syscall.SIGTERM, 0, 0)
}

func (suite *TCPFinRx) TestSilentKillServerExitClient() {
	suite.testFinRx(3618, -1, 0, "W", "", syscall.SIGKILL, 0, 0, 0)
}

func (suite *TCPFinRx) TestSilentHupServerKillClient() {
	suite.testFinRx(3619, -1, -1, "W", "W", syscall.SIGHUP, syscall.SIGKILL, 0, 0)
}

func (suite *TCPFinRx) TestSilentHupServerHupClient() {
	suite.testFinRx(3620, -1, -1, "W", "W", syscall.SIGHUP, syscall.SIGHUP, 0, 0)
}

func (suite *TCPFinRx) TestSilentHupServerTermClient() {
	suite.testFinRx(3621, -1, -1, "W", "W", syscall.SIGHUP, syscall.SIGTERM, 0, 0)
}

func (suite *TCPFinRx) TestSilentHupServerExitClient() {
	suite.testFinRx(3622, -1, 0, "W", "", syscall.SIGHUP, 0, 0, 0)
}

func (suite *TCPFinRx) TestSilentTermServerKillClient() {
	suite.testFinRx(3623, -1, -1, "W", "W", syscall.SIGTERM, syscall.SIGKILL, 0, 0)
}

func (suite *TCPFinRx) TestSilentTermServerHupClient() {
	suite.testFinRx(3624, -1, -1, "W", "W", syscall.SIGTERM, syscall.SIGHUP, 0, 0)
}

func (suite *TCPFinRx) TestSilentTermServerTermClient() {
	suite.testFinRx(3625, -1, -1, "W", "W", syscall.SIGTERM, syscall.SIGTERM, 0, 0)
}

func (suite *TCPFinRx) TestSilentTermServerExitClient() {
	suite.testFinRx(3626, -1, 0, "W", "", syscall.SIGTERM, 0, 0, 0)
}

func (suite *TCPFinRx) TestSilentExitServerKillClient() {
	suite.testFinRx(3627, 0, -1, "", "W", 0, syscall.SIGKILL, 0, 0)
}

func (suite *TCPFinRx) TestSilentExitServerHupClient() {
	suite.testFinRx(3627, 0, -1, "", "W", 0, syscall.SIGHUP, 0, 0)
}

func (suite *TCPFinRx) TestSilentExitServerTermClient() {
	suite.testFinRx(3629, 0, -1, "", "W", 0, syscall.SIGTERM, 0, 0)
}

func (suite *TCPFinRx) TestSilentExitServerExitClient() {
	suite.testFinRx(3630, 0, 0, "", "", 0, 0, 0, 0)
}

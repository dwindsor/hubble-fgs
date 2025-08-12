//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

//go:build sudo_tests

package layer3_test

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os/exec"
	"syscall"
	"testing"

	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	osstestutils "github.com/cilium/tetragon/pkg/testutils"
	"github.com/stretchr/testify/suite"

	"github.com/cilium/tetragon/api/v1/tetragon"
	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"

	"github.com/isovalent/hubble-fgs/pkg/testutils"
	"github.com/isovalent/hubble-fgs/pkg/testutils/runner"

	_ "github.com/isovalent/hubble-fgs/pkg/sensors/exec"
	"github.com/isovalent/hubble-fgs/pkg/sensors/utils"
)

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

	client := testutils.RepoRootPath("contrib/tester-progs/net/tcp_client")
	server := testutils.RepoRootPath("contrib/tester-progs/net/tcp_server")

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	srvChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(server)).
		WithArguments(sm.Full(fmt.Sprintf("%d %d %s", port, serverIterations, serverPattern)))

	cliChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(client)).
		WithArguments(sm.Full(fmt.Sprintf("%d %d %s", port, clientIterations, clientPattern)))

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

	cmdServer := exec.Command(server, fmt.Sprintf("%d", port), fmt.Sprintf("%d", serverIterations), serverPattern)
	serverOut, err := cmdServer.StdoutPipe()
	suite.Require().NoError(err, "could not connect to server output pipe")

	err = cmdServer.Start()
	suite.Require().NoError(err, "cannot start server")
	suite.T().Logf("Started the server")

	serverScanner := bufio.NewScanner(serverOut)
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

func (suite *TCPFinRx) SetupSuite() {
	suite.ctx, suite.cancel = context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	obs := getBasicTcpObserver(suite.T(), suite.ctx, false)
	observertesthelper.LoopEvents(suite.ctx, suite.T(), &suite.doneWG, &suite.readyWG, obs)
}

func (suite *TCPFinRx) HandleStats(_ string, stats *suite.SuiteInformation) {
	if stats.Passed() {
		osstestutils.DoneWithExportFile(suite.T())
	}
}

func (suite *TCPFinRx) TearDownSuite() {
	suite.cancel()
}

func (suite *TCPFinRx) RecvOnlyKillServerKillClient() {
	suite.testFinRx(3551, -1, -1, "SW", "RW", syscall.SIGKILL, syscall.SIGKILL, 5, 0)
}

func (suite *TCPFinRx) RecvOnlyKillServerHupClient() {
	suite.testFinRx(3552, -1, -1, "SW", "RW", syscall.SIGKILL, syscall.SIGHUP, 5, 0)
}

func (suite *TCPFinRx) RecvOnlyKillServerTermClient() {
	suite.testFinRx(3553, -1, -1, "SW", "RW", syscall.SIGKILL, syscall.SIGTERM, 5, 0)
}

func (suite *TCPFinRx) RecvOnlyKillServerExitClient() {
	suite.testFinRx(3554, -1, 1, "SW", "R", syscall.SIGKILL, 0, 5, 0)
}

func (suite *TCPFinRx) RecvOnlyHupServerKillClient() {
	suite.testFinRx(3555, -1, -1, "SW", "RW", syscall.SIGHUP, syscall.SIGKILL, 5, 0)
}

func (suite *TCPFinRx) RecvOnlyHupServerHupClient() {
	suite.testFinRx(3556, -1, -1, "SW", "RW", syscall.SIGHUP, syscall.SIGHUP, 5, 0)
}

func (suite *TCPFinRx) RecvOnlyHupServerTermClient() {
	suite.testFinRx(3557, -1, -1, "SW", "RW", syscall.SIGHUP, syscall.SIGTERM, 5, 0)
}

func (suite *TCPFinRx) RecvOnlyHupServerExitClient() {
	suite.testFinRx(3558, -1, 1, "SW", "R", syscall.SIGHUP, 0, 5, 0)
}

func (suite *TCPFinRx) RecvOnlyTermServerKillClient() {
	suite.testFinRx(3559, -1, -1, "SW", "RW", syscall.SIGTERM, syscall.SIGKILL, 5, 0)
}

func (suite *TCPFinRx) RecvOnlyTermServerHupClient() {
	suite.testFinRx(3560, -1, -1, "SW", "RW", syscall.SIGTERM, syscall.SIGHUP, 5, 0)
}

func (suite *TCPFinRx) RecvOnlyTermServerTermClient() {
	suite.testFinRx(3561, -1, -1, "SW", "RW", syscall.SIGTERM, syscall.SIGTERM, 5, 0)
}

func (suite *TCPFinRx) RecvOnlyTermServerExitClient() {
	suite.testFinRx(3562, -1, 1, "SW", "R", syscall.SIGTERM, 0, 5, 0)
}

func (suite *TCPFinRx) RecvOnlyExitServerKillClient() {
	suite.testFinRx(3563, 1, -1, "S", "RW", 0, syscall.SIGKILL, 5, 0)
}

func (suite *TCPFinRx) RecvOnlyExitServerHupClient() {
	suite.testFinRx(3564, 1, -1, "S", "RW", 0, syscall.SIGHUP, 5, 0)
}

func (suite *TCPFinRx) RecvOnlyExitServerTermClient() {
	suite.testFinRx(3565, 1, -1, "S", "RW", 0, syscall.SIGTERM, 5, 0)
}

func (suite *TCPFinRx) RecvOnlyExitServerExitClient() {
	suite.testFinRx(3566, 1, 1, "S", "R", 0, 0, 5, 0)
}

func (suite *TCPFinRx) SendOnlyKillServerKillClient() {
	suite.testFinRx(3567, -1, -1, "RW", "SW", syscall.SIGKILL, syscall.SIGKILL, 0, 5)
}

func (suite *TCPFinRx) SendOnlyKillServerHupClient() {
	suite.testFinRx(3568, -1, -1, "RW", "SW", syscall.SIGKILL, syscall.SIGHUP, 0, 5)
}

func (suite *TCPFinRx) SendOnlyKillServerTermClient() {
	suite.testFinRx(3569, -1, -1, "RW", "SW", syscall.SIGKILL, syscall.SIGTERM, 0, 5)
}

func (suite *TCPFinRx) SendOnlyKillServerExitClient() {
	suite.testFinRx(3570, -1, 1, "RW", "S", syscall.SIGKILL, 0, 0, 5)
}

func (suite *TCPFinRx) SendOnlyHupServerKillClient() {
	suite.testFinRx(3571, -1, -1, "RW", "SW", syscall.SIGHUP, syscall.SIGKILL, 0, 5)
}

func (suite *TCPFinRx) SendOnlyHupServerHupClient() {
	suite.testFinRx(3572, -1, -1, "RW", "SW", syscall.SIGHUP, syscall.SIGHUP, 0, 5)
}

func (suite *TCPFinRx) SendOnlyHupServerTermClient() {
	suite.testFinRx(3573, -1, -1, "RW", "SW", syscall.SIGHUP, syscall.SIGTERM, 0, 5)
}

func (suite *TCPFinRx) SendOnlyHupServerExitClient() {
	suite.testFinRx(3574, -1, 1, "RW", "S", syscall.SIGHUP, 0, 0, 5)
}

func (suite *TCPFinRx) SendOnlyTermServerKillClient() {
	suite.testFinRx(3575, -1, -1, "RW", "SW", syscall.SIGTERM, syscall.SIGKILL, 0, 5)
}

func (suite *TCPFinRx) SendOnlyTermServerHupClient() {
	suite.testFinRx(3576, -1, -1, "RW", "SW", syscall.SIGTERM, syscall.SIGHUP, 0, 5)
}

func (suite *TCPFinRx) SendOnlyTermServerTermClient() {
	suite.testFinRx(3577, -1, -1, "RW", "SW", syscall.SIGTERM, syscall.SIGTERM, 0, 5)
}

func (suite *TCPFinRx) SendOnlyTermServerExitClient() {
	suite.testFinRx(3578, -1, 1, "RW", "S", syscall.SIGTERM, 0, 0, 5)
}

func (suite *TCPFinRx) SendOnlyExitServerKillClient() {
	suite.testFinRx(3579, 1, -1, "R", "SW", 0, syscall.SIGKILL, 0, 5)
}

func (suite *TCPFinRx) SendOnlyExitServerHupClient() {
	suite.testFinRx(3580, 1, -1, "R", "SW", 0, syscall.SIGHUP, 0, 5)
}

func (suite *TCPFinRx) SendOnlyExitServerTermClient() {
	suite.testFinRx(3581, 1, -1, "R", "SW", 0, syscall.SIGTERM, 0, 5)
}

func (suite *TCPFinRx) SendOnlyExitServerExitClient() {
	suite.testFinRx(3582, 1, 1, "R", "S", 0, 0, 0, 5)
}

func (suite *TCPFinRx) SendRecvKillServerKillClient() {
	suite.testFinRx(3583, -1, -1, "RSW", "SRW", syscall.SIGKILL, syscall.SIGKILL, 5, 5)
}

func (suite *TCPFinRx) SendRecvKillServerHupClient() {
	suite.testFinRx(3584, -1, -1, "RSW", "SRW", syscall.SIGKILL, syscall.SIGHUP, 5, 5)
}

func (suite *TCPFinRx) SendRecvKillServerTermClient() {
	suite.testFinRx(3585, -1, -1, "RSW", "SRW", syscall.SIGKILL, syscall.SIGTERM, 5, 5)
}

func (suite *TCPFinRx) SendRecvKillServerExitClient() {
	suite.testFinRx(3586, -1, 1, "RSW", "SR", syscall.SIGKILL, 0, 5, 5)
}

func (suite *TCPFinRx) SendRecvHupServerKillClient() {
	suite.testFinRx(3587, -1, -1, "RSW", "SRW", syscall.SIGHUP, syscall.SIGKILL, 5, 5)
}

func (suite *TCPFinRx) SendRecvHupServerHupClient() {
	suite.testFinRx(3588, -1, -1, "RSW", "SRW", syscall.SIGHUP, syscall.SIGHUP, 5, 5)
}

func (suite *TCPFinRx) SendRecvHupServerTermClient() {
	suite.testFinRx(3589, -1, -1, "RSW", "SRW", syscall.SIGHUP, syscall.SIGTERM, 5, 5)
}

func (suite *TCPFinRx) SendRecvHupServerExitClient() {
	suite.testFinRx(3590, -1, 1, "RSW", "SR", syscall.SIGHUP, 0, 5, 5)
}

func (suite *TCPFinRx) SendRecvTermServerKillClient() {
	suite.testFinRx(3591, -1, -1, "RSW", "SRW", syscall.SIGTERM, syscall.SIGKILL, 5, 5)
}

func (suite *TCPFinRx) SendRecvTermServerHupClient() {
	suite.testFinRx(3592, -1, -1, "RSW", "SRW", syscall.SIGTERM, syscall.SIGHUP, 5, 5)
}

func (suite *TCPFinRx) SendRecvTermServerTermClient() {
	suite.testFinRx(3593, -1, -1, "RSW", "SRW", syscall.SIGTERM, syscall.SIGTERM, 5, 5)
}

func (suite *TCPFinRx) SendRecvTermServerExitClient() {
	suite.testFinRx(3594, -1, 1, "RSW", "SR", syscall.SIGTERM, 0, 5, 5)
}

func (suite *TCPFinRx) SendRecvExitServerKillClient() {
	suite.testFinRx(3595, 1, -1, "RS", "SRW", 0, syscall.SIGKILL, 5, 5)
}

func (suite *TCPFinRx) SendRecvExitServerHupClient() {
	suite.testFinRx(3596, 1, -1, "RS", "SRW", 0, syscall.SIGHUP, 5, 5)
}

func (suite *TCPFinRx) SendRecvExitServerTermClient() {
	suite.testFinRx(3597, 1, -1, "RS", "SRW", 0, syscall.SIGTERM, 5, 5)
}

func (suite *TCPFinRx) SendRecvExitServerExitClient() {
	suite.testFinRx(3598, 1, 1, "RS", "SR", 0, 0, 5, 5)
}

func (suite *TCPFinRx) RecvSendKillServerKillClient() {
	suite.testFinRx(3599, -1, -1, "SRW", "RSW", syscall.SIGKILL, syscall.SIGKILL, 5, 5)
}

func (suite *TCPFinRx) RecvSendKillServerHupClient() {
	suite.testFinRx(3600, -1, -1, "SRW", "RSW", syscall.SIGKILL, syscall.SIGHUP, 5, 5)
}

func (suite *TCPFinRx) RecvSendKillServerTermClient() {
	suite.testFinRx(3601, -1, -1, "SRW", "RSW", syscall.SIGKILL, syscall.SIGTERM, 5, 5)
}

func (suite *TCPFinRx) RecvSendKillServerExitClient() {
	suite.testFinRx(3602, -1, 1, "SRW", "RS", syscall.SIGKILL, 0, 5, 5)
}

func (suite *TCPFinRx) RecvSendHupServerKillClient() {
	suite.testFinRx(3603, -1, -1, "SRW", "RSW", syscall.SIGHUP, syscall.SIGKILL, 5, 5)
}

func (suite *TCPFinRx) RecvSendHupServerHupClient() {
	suite.testFinRx(3604, -1, -1, "SRW", "RSW", syscall.SIGHUP, syscall.SIGHUP, 5, 5)
}

func (suite *TCPFinRx) RecvSendHupServerTermClient() {
	suite.testFinRx(3605, -1, -1, "SRW", "RSW", syscall.SIGHUP, syscall.SIGTERM, 5, 5)
}

func (suite *TCPFinRx) RecvSendHupServerExitClient() {
	suite.testFinRx(3606, -1, 1, "SRW", "RS", syscall.SIGHUP, 0, 5, 5)
}

func (suite *TCPFinRx) RecvSendTermServerKillClient() {
	suite.testFinRx(3607, -1, -1, "SRW", "RSW", syscall.SIGTERM, syscall.SIGKILL, 5, 5)
}

func (suite *TCPFinRx) RecvSendTermServerHupClient() {
	suite.testFinRx(3608, -1, -1, "SRW", "RSW", syscall.SIGTERM, syscall.SIGHUP, 5, 5)
}

func (suite *TCPFinRx) RecvSendTermServerTermClient() {
	suite.testFinRx(3609, -1, -1, "SRW", "RSW", syscall.SIGTERM, syscall.SIGTERM, 5, 5)
}

func (suite *TCPFinRx) RecvSendTermServerExitClient() {
	suite.testFinRx(3610, -1, 1, "SRW", "RS", syscall.SIGTERM, 0, 5, 5)
}

func (suite *TCPFinRx) RecvSendExitServerKillClient() {
	suite.testFinRx(3611, 1, -1, "SR", "RSW", 0, syscall.SIGKILL, 5, 5)
}

func (suite *TCPFinRx) RecvSendExitServerHupClient() {
	suite.testFinRx(3612, 1, -1, "SR", "RSW", 0, syscall.SIGHUP, 5, 5)
}

func (suite *TCPFinRx) RecvSendExitServerTermClient() {
	suite.testFinRx(3613, 1, -1, "SR", "RSW", 0, syscall.SIGTERM, 5, 5)
}

func (suite *TCPFinRx) RecvSendExitServerExitClient() {
	suite.testFinRx(3614, 1, 1, "SR", "RS", 0, 0, 5, 5)
}

func (suite *TCPFinRx) SilentKillServerKillClient() {
	suite.testFinRx(3615, -1, -1, "W", "W", syscall.SIGKILL, syscall.SIGKILL, 0, 0)
}

func (suite *TCPFinRx) SilentKillServerHupClient() {
	suite.testFinRx(3616, -1, -1, "W", "W", syscall.SIGKILL, syscall.SIGHUP, 0, 0)
}

func (suite *TCPFinRx) SilentKillServerTermClient() {
	suite.testFinRx(3617, -1, -1, "W", "W", syscall.SIGKILL, syscall.SIGTERM, 0, 0)
}

func (suite *TCPFinRx) SilentKillServerExitClient() {
	suite.testFinRx(3618, -1, 0, "W", "", syscall.SIGKILL, 0, 0, 0)
}

func (suite *TCPFinRx) SilentHupServerKillClient() {
	suite.testFinRx(3619, -1, -1, "W", "W", syscall.SIGHUP, syscall.SIGKILL, 0, 0)
}

func (suite *TCPFinRx) SilentHupServerHupClient() {
	suite.testFinRx(3620, -1, -1, "W", "W", syscall.SIGHUP, syscall.SIGHUP, 0, 0)
}

func (suite *TCPFinRx) SilentHupServerTermClient() {
	suite.testFinRx(3621, -1, -1, "W", "W", syscall.SIGHUP, syscall.SIGTERM, 0, 0)
}

func (suite *TCPFinRx) SilentHupServerExitClient() {
	suite.testFinRx(3622, -1, 0, "W", "", syscall.SIGHUP, 0, 0, 0)
}

func (suite *TCPFinRx) SilentTermServerKillClient() {
	suite.testFinRx(3623, -1, -1, "W", "W", syscall.SIGTERM, syscall.SIGKILL, 0, 0)
}

func (suite *TCPFinRx) SilentTermServerHupClient() {
	suite.testFinRx(3624, -1, -1, "W", "W", syscall.SIGTERM, syscall.SIGHUP, 0, 0)
}

func (suite *TCPFinRx) SilentTermServerTermClient() {
	suite.testFinRx(3625, -1, -1, "W", "W", syscall.SIGTERM, syscall.SIGTERM, 0, 0)
}

func (suite *TCPFinRx) SilentTermServerExitClient() {
	suite.testFinRx(3626, -1, 0, "W", "", syscall.SIGTERM, 0, 0, 0)
}

func (suite *TCPFinRx) SilentExitServerKillClient() {
	suite.testFinRx(3627, 0, -1, "", "W", 0, syscall.SIGKILL, 0, 0)
}

func (suite *TCPFinRx) SilentExitServerHupClient() {
	suite.testFinRx(3627, 0, -1, "", "W", 0, syscall.SIGHUP, 0, 0)
}

func (suite *TCPFinRx) SilentExitServerTermClient() {
	suite.testFinRx(3629, 0, -1, "", "W", 0, syscall.SIGTERM, 0, 0)
}

func (suite *TCPFinRx) SilentExitServerExitClient() {
	suite.testFinRx(3630, 0, 0, "", "", 0, 0, 0, 0)
}

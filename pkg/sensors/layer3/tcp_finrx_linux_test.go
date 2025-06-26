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
	"sync"
	"syscall"
	"testing"

	"github.com/cilium/tetragon/api/v1/tetragon"
	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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

func testFinRx(gt *testing.T, t *testing.T, port uint32, serverIterations, clientIterations int,
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
	require.NoError(t, err, "could not connect to server output pipe")

	err = cmdServer.Start()
	require.NoError(t, err, "cannot start server")
	t.Logf("Started the server")

	serverScanner := bufio.NewScanner(serverOut)
	for serverScanner.Scan() {
		line := serverScanner.Text()
		if line == "Ready!" {
			break
		}
	}

	cmdClient := exec.Command(client, fmt.Sprintf("%d", port), fmt.Sprintf("%d", clientIterations), clientPattern)
	clientOut, err := cmdClient.StdoutPipe()
	require.NoError(t, err, "could not connect to client output pipe")

	err = cmdClient.Start()
	require.NoError(t, err, "cannot start client")

	clientScanner := bufio.NewScanner(clientOut)

	if clientSignal == 0 {
		// No signal means expect it to end.
		err = cmdClient.Wait()
		if err != nil {
			killAndWaitCommand(t, cmdServer)
			t.Fatal(err)
		}
	}

	if serverSignal == 0 {
		// No signal means expect it to end.
		err = cmdServer.Wait()
		if err != nil {
			if clientSignal != 0 {
				killAndWaitCommand(t, cmdClient)
			}
			t.Fatal(err)
		}
	}

	if clientSignal != 0 {
		waitForSocket(clientScanner)
		signalAndWaitCommand(t, cmdClient, clientSignal)
	}

	if serverSignal != 0 {
		waitForSocket(serverScanner)
		signalAndWaitCommand(t, cmdServer, serverSignal)
	}

	err = waitAndCheckForSocketsToClose(gt, t, checker, net.ParseIP("127.0.0.1"), uint16(port), syscall.IPPROTO_TCP, syscall.AF_INET)
	assert.NoError(t, err)
}

func TestFinRx(t *testing.T) {
	// For reliability, we really need the sockops handlers as the kprobes can be
	// unreliable. Note, the technology should work from kernel v5.5 (it needs
	// probe_read_kernel in Cgroup/SKB programs).
	if !utils.SupportCGroupSKBProbeRead() {
		t.Skipf("This test requires CGroup/SKB, skipping")
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	obs := getBasicTcpObserver(t, ctx, false)
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)

	readyWG.Wait()

	for _, test := range finRxTests {
		if !t.Run(test.name, func(lt *testing.T) {
			testFinRx(t, lt,
				test.port, test.serverIterations, test.clientIterations,
				test.serverPattern, test.clientPattern, test.serverSignal,
				test.clientSignal, test.serverBytes, test.clientBytes)
		}) {
			break // stop on first failure
		}
	}
}

type finRxTest struct {
	name             string
	port             uint32
	serverIterations int
	clientIterations int
	serverPattern    string
	clientPattern    string
	serverSignal     syscall.Signal
	clientSignal     syscall.Signal
	serverBytes      uint64
	clientBytes      uint64
}

var (
	finRxTests = []finRxTest{
		{"RecvOnlyKillServerKillClient", 3551, -1, -1, "SW", "RW", syscall.SIGKILL, syscall.SIGKILL, 5, 0},
		{"RecvOnlyKillServerHupClient", 3552, -1, -1, "SW", "RW", syscall.SIGKILL, syscall.SIGHUP, 5, 0},
		{"RecvOnlyKillServerTermClient", 3553, -1, -1, "SW", "RW", syscall.SIGKILL, syscall.SIGTERM, 5, 0},
		{"RecvOnlyKillServerExitClient", 3554, -1, 1, "SW", "R", syscall.SIGKILL, 0, 5, 0},
		{"RecvOnlyHupServerKillClient", 3555, -1, -1, "SW", "RW", syscall.SIGHUP, syscall.SIGKILL, 5, 0},
		{"RecvOnlyHupServerHupClient", 3556, -1, -1, "SW", "RW", syscall.SIGHUP, syscall.SIGHUP, 5, 0},
		{"RecvOnlyHupServerTermClient", 3557, -1, -1, "SW", "RW", syscall.SIGHUP, syscall.SIGTERM, 5, 0},
		{"RecvOnlyHupServerExitClient", 3558, -1, 1, "SW", "R", syscall.SIGHUP, 0, 5, 0},
		{"RecvOnlyTermServerKillClient", 3559, -1, -1, "SW", "RW", syscall.SIGTERM, syscall.SIGKILL, 5, 0},
		{"RecvOnlyTermServerHupClient", 3560, -1, -1, "SW", "RW", syscall.SIGTERM, syscall.SIGHUP, 5, 0},
		{"RecvOnlyTermServerTermClient", 3561, -1, -1, "SW", "RW", syscall.SIGTERM, syscall.SIGTERM, 5, 0},
		{"RecvOnlyTermServerExitClient", 3562, -1, 1, "SW", "R", syscall.SIGTERM, 0, 5, 0},
		{"RecvOnlyExitServerKillClient", 3563, 1, -1, "S", "RW", 0, syscall.SIGKILL, 5, 0},
		{"RecvOnlyExitServerHupClient", 3564, 1, -1, "S", "RW", 0, syscall.SIGHUP, 5, 0},
		{"RecvOnlyExitServerTermClient", 3565, 1, -1, "S", "RW", 0, syscall.SIGTERM, 5, 0},
		{"RecvOnlyExitServerExitClient", 3566, 1, 1, "S", "R", 0, 0, 5, 0},
		{"SendOnlyKillServerKillClient", 3567, -1, -1, "RW", "SW", syscall.SIGKILL, syscall.SIGKILL, 0, 5},
		{"SendOnlyKillServerHupClient", 3568, -1, -1, "RW", "SW", syscall.SIGKILL, syscall.SIGHUP, 0, 5},
		{"SendOnlyKillServerTermClient", 3569, -1, -1, "RW", "SW", syscall.SIGKILL, syscall.SIGTERM, 0, 5},
		{"SendOnlyKillServerExitClient", 3570, -1, 1, "RW", "S", syscall.SIGKILL, 0, 0, 5},
		{"SendOnlyHupServerKillClient", 3571, -1, -1, "RW", "SW", syscall.SIGHUP, syscall.SIGKILL, 0, 5},
		{"SendOnlyHupServerHupClient", 3572, -1, -1, "RW", "SW", syscall.SIGHUP, syscall.SIGHUP, 0, 5},
		{"SendOnlyHupServerTermClient", 3573, -1, -1, "RW", "SW", syscall.SIGHUP, syscall.SIGTERM, 0, 5},
		{"SendOnlyHupServerExitClient", 3574, -1, 1, "RW", "S", syscall.SIGHUP, 0, 0, 5},
		{"SendOnlyTermServerKillClient", 3575, -1, -1, "RW", "SW", syscall.SIGTERM, syscall.SIGKILL, 0, 5},
		{"SendOnlyTermServerHupClient", 3576, -1, -1, "RW", "SW", syscall.SIGTERM, syscall.SIGHUP, 0, 5},
		{"SendOnlyTermServerTermClient", 3577, -1, -1, "RW", "SW", syscall.SIGTERM, syscall.SIGTERM, 0, 5},
		{"SendOnlyTermServerExitClient", 3578, -1, 1, "RW", "S", syscall.SIGTERM, 0, 0, 5},
		{"SendOnlyExitServerKillClient", 3579, 1, -1, "R", "SW", 0, syscall.SIGKILL, 0, 5},
		{"SendOnlyExitServerHupClient", 3580, 1, -1, "R", "SW", 0, syscall.SIGHUP, 0, 5},
		{"SendOnlyExitServerTermClient", 3581, 1, -1, "R", "SW", 0, syscall.SIGTERM, 0, 5},
		{"SendOnlyExitServerExitClient", 3582, 1, 1, "R", "S", 0, 0, 0, 5},
		{"SendRecvKillServerKillClient", 3583, -1, -1, "RSW", "SRW", syscall.SIGKILL, syscall.SIGKILL, 5, 5},
		{"SendRecvKillServerHupClient", 3584, -1, -1, "RSW", "SRW", syscall.SIGKILL, syscall.SIGHUP, 5, 5},
		{"SendRecvKillServerTermClient", 3585, -1, -1, "RSW", "SRW", syscall.SIGKILL, syscall.SIGTERM, 5, 5},
		{"SendRecvKillServerExitClient", 3586, -1, 1, "RSW", "SR", syscall.SIGKILL, 0, 5, 5},
		{"SendRecvHupServerKillClient", 3587, -1, -1, "RSW", "SRW", syscall.SIGHUP, syscall.SIGKILL, 5, 5},
		{"SendRecvHupServerHupClient", 3588, -1, -1, "RSW", "SRW", syscall.SIGHUP, syscall.SIGHUP, 5, 5},
		{"SendRecvHupServerTermClient", 3589, -1, -1, "RSW", "SRW", syscall.SIGHUP, syscall.SIGTERM, 5, 5},
		{"SendRecvHupServerExitClient", 3590, -1, 1, "RSW", "SR", syscall.SIGHUP, 0, 5, 5},
		{"SendRecvTermServerKillClient", 3591, -1, -1, "RSW", "SRW", syscall.SIGTERM, syscall.SIGKILL, 5, 5},
		{"SendRecvTermServerHupClient", 3592, -1, -1, "RSW", "SRW", syscall.SIGTERM, syscall.SIGHUP, 5, 5},
		{"SendRecvTermServerTermClient", 3593, -1, -1, "RSW", "SRW", syscall.SIGTERM, syscall.SIGTERM, 5, 5},
		{"SendRecvTermServerExitClient", 3594, -1, 1, "RSW", "SR", syscall.SIGTERM, 0, 5, 5},
		{"SendRecvExitServerKillClient", 3595, 1, -1, "RS", "SRW", 0, syscall.SIGKILL, 5, 5},
		{"SendRecvExitServerHupClient", 3596, 1, -1, "RS", "SRW", 0, syscall.SIGHUP, 5, 5},
		{"SendRecvExitServerTermClient", 3597, 1, -1, "RS", "SRW", 0, syscall.SIGTERM, 5, 5},
		{"SendRecvExitServerExitClient", 3598, 1, 1, "RS", "SR", 0, 0, 5, 5},
		{"RecvSendKillServerKillClient", 3599, -1, -1, "SRW", "RSW", syscall.SIGKILL, syscall.SIGKILL, 5, 5},
		{"RecvSendKillServerHupClient", 3600, -1, -1, "SRW", "RSW", syscall.SIGKILL, syscall.SIGHUP, 5, 5},
		{"RecvSendKillServerTermClient", 3601, -1, -1, "SRW", "RSW", syscall.SIGKILL, syscall.SIGTERM, 5, 5},
		{"RecvSendKillServerExitClient", 3602, -1, 1, "SRW", "RS", syscall.SIGKILL, 0, 5, 5},
		{"RecvSendHupServerKillClient", 3603, -1, -1, "SRW", "RSW", syscall.SIGHUP, syscall.SIGKILL, 5, 5},
		{"RecvSendHupServerHupClient", 3604, -1, -1, "SRW", "RSW", syscall.SIGHUP, syscall.SIGHUP, 5, 5},
		{"RecvSendHupServerTermClient", 3605, -1, -1, "SRW", "RSW", syscall.SIGHUP, syscall.SIGTERM, 5, 5},
		{"RecvSendHupServerExitClient", 3606, -1, 1, "SRW", "RS", syscall.SIGHUP, 0, 5, 5},
		{"RecvSendTermServerKillClient", 3607, -1, -1, "SRW", "RSW", syscall.SIGTERM, syscall.SIGKILL, 5, 5},
		{"RecvSendTermServerHupClient", 3608, -1, -1, "SRW", "RSW", syscall.SIGTERM, syscall.SIGHUP, 5, 5},
		{"RecvSendTermServerTermClient", 3609, -1, -1, "SRW", "RSW", syscall.SIGTERM, syscall.SIGTERM, 5, 5},
		{"RecvSendTermServerExitClient", 3610, -1, 1, "SRW", "RS", syscall.SIGTERM, 0, 5, 5},
		{"RecvSendExitServerKillClient", 3611, 1, -1, "SR", "RSW", 0, syscall.SIGKILL, 5, 5},
		{"RecvSendExitServerHupClient", 3612, 1, -1, "SR", "RSW", 0, syscall.SIGHUP, 5, 5},
		{"RecvSendExitServerTermClient", 3613, 1, -1, "SR", "RSW", 0, syscall.SIGTERM, 5, 5},
		{"RecvSendExitServerExitClient", 3614, 1, 1, "SR", "RS", 0, 0, 5, 5},
		{"SilentKillServerKillClient", 3615, -1, -1, "W", "W", syscall.SIGKILL, syscall.SIGKILL, 0, 0},
		{"SilentKillServerHupClient", 3616, -1, -1, "W", "W", syscall.SIGKILL, syscall.SIGHUP, 0, 0},
		{"SilentKillServerTermClient", 3617, -1, -1, "W", "W", syscall.SIGKILL, syscall.SIGTERM, 0, 0},
		{"SilentKillServerExitClient", 3618, -1, 0, "W", "", syscall.SIGKILL, 0, 0, 0},
		{"SilentHupServerKillClient", 3619, -1, -1, "W", "W", syscall.SIGHUP, syscall.SIGKILL, 0, 0},
		{"SilentHupServerHupClient", 3620, -1, -1, "W", "W", syscall.SIGHUP, syscall.SIGHUP, 0, 0},
		{"SilentHupServerTermClient", 3621, -1, -1, "W", "W", syscall.SIGHUP, syscall.SIGTERM, 0, 0},
		{"SilentHupServerExitClient", 3622, -1, 0, "W", "", syscall.SIGHUP, 0, 0, 0},
		{"SilentTermServerKillClient", 3623, -1, -1, "W", "W", syscall.SIGTERM, syscall.SIGKILL, 0, 0},
		{"SilentTermServerHupClient", 3624, -1, -1, "W", "W", syscall.SIGTERM, syscall.SIGHUP, 0, 0},
		{"SilentTermServerTermClient", 3625, -1, -1, "W", "W", syscall.SIGTERM, syscall.SIGTERM, 0, 0},
		{"SilentTermServerExitClient", 3626, -1, 0, "W", "", syscall.SIGTERM, 0, 0, 0},
		{"SilentExitServerKillClient", 3627, 0, -1, "", "W", 0, syscall.SIGKILL, 0, 0},
		{"SilentExitServerHupClient", 3627, 0, -1, "", "W", 0, syscall.SIGHUP, 0, 0},
		{"SilentExitServerTermClient", 3629, 0, -1, "", "W", 0, syscall.SIGTERM, 0, 0},
		{"SilentExitServerExitClient", 3630, 0, 0, "", "", 0, 0, 0, 0},
	}
)

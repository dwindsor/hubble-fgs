//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package layer3_test

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/jsonchecker"
	"github.com/isovalent/hubble-fgs/pkg/testutils"
	"github.com/isovalent/hubble-fgs/pkg/testutils/runner"

	_ "github.com/isovalent/hubble-fgs/pkg/sensors/exec"
	"github.com/isovalent/hubble-fgs/pkg/sensors/utils"
)

func parsePortFromAddrPort(addrPort string) (uint32, error) {
	parts := strings.Split(addrPort, ":")
	portStr := parts[len(parts)-1]
	if len(portStr) < 1 {
		return 0, fmt.Errorf("Cannot extract port from '%s'", addrPort)
	}
	if portStr == "*" {
		return 0, nil
	}
	port, err := strconv.ParseUint(portStr, 10, 32)
	if err != nil {
		return 0, err
	}
	return uint32(port), nil
}

func countSockets(port uint32, output []byte, skip int) (int, error) {
	count := 0
	lines := strings.Split(string(output), "\n")
	for i, line := range lines {
		if i < skip {
			// skip header
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		lport, err := parsePortFromAddrPort(fields[3])
		if err != nil {
			return 0, err
		}
		rport, err := parsePortFromAddrPort(fields[4])
		if err != nil {
			return 0, err
		}
		if lport == port || rport == port {
			count++
		}
	}
	return count, nil
}

func countSocketsSs(t *testing.T, port uint32) (int, error) {
	output, err := exec.Command("/usr/bin/ss", "-latn").Output()
	if err != nil {
		t.Logf("Command 'ss' failed: '%s'", err)
		return 0, err
	}
	return countSockets(port, output, 1)
}

func countSocketsNetstat(t *testing.T, port uint32) (int, error) {
	output, err := exec.Command("/usr/bin/netstat", "-latn").Output()
	if err != nil {
		t.Logf("Command 'netstat' failed: '%s'", err)
		return 0, err
	}
	return countSockets(port, output, 2)
}

func waitForSocketsToClose(t *testing.T, port uint32) error {
	t.Log("Waiting for sockets to close")
	useSs := true
	numPorts, err := countSocketsSs(t, port)
	if err != nil {
		t.Log("Failed to count open sockets with 'ss'")
		useSs = false
		numPorts, err = countSocketsNetstat(t, port)
		if err != nil {
			t.Log("Failed to count open sockets with 'netstat'")
			return err
		}
		t.Log("Using 'netstat' to count open sockets")
	} else {
		t.Log("Using 'ss' to count open sockets")
	}
	for numPorts > 0 {
		if useSs {
			numPorts, err = countSocketsSs(t, port)
		} else {
			numPorts, err = countSocketsNetstat(t, port)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func testFinRx(gt *testing.T, t *testing.T, port uint32, serverIterations, clientIterations int,
	serverPattern, clientPattern string, serverSignal, clientSignal syscall.Signal,
	serverBytes, clientBytes uint64, delay time.Duration) {

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
	require.NoError(gt, err, "could not connect to server output pipe")

	err = cmdServer.Start()
	require.NoError(gt, err, "cannot start server")

	serverBuf := bufio.NewReader(serverOut)
	var line []byte
	for string(line) != "Ready!" {
		line, _, err = serverBuf.ReadLine()
		if err != nil {
			killAndWaitCommand(t, cmdServer)
			t.Fatal(err)
		}
		if len(line) == 0 {
			killAndWaitCommand(t, cmdServer)
			t.Fatal("received empty line from TCP server")
		}
	}

	cmdClient := exec.Command(client, fmt.Sprintf("%d", port), fmt.Sprintf("%d", clientIterations), clientPattern)
	cmdClient.Stderr = nil
	cmdClient.Stdout = nil

	err = cmdClient.Start()
	require.NoError(gt, err, "cannot start client")

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

	time.Sleep(delay)

	if clientSignal != 0 {
		signalAndWaitCommand(t, cmdClient, clientSignal)
	}

	if serverSignal != 0 {
		signalAndWaitCommand(t, cmdServer, serverSignal)
	}

	err = jsonchecker.JsonTestCheck(gt, checker)
	if err != nil {
		// Checker test failed, so maybe we need to wait for the sockets to close
		err = waitForSocketsToClose(t, port)
		if err != nil {
			t.Logf("waitForSocketsToClose failed: '%s'", err)
		}
		time.Sleep(100 * time.Millisecond)
		err = jsonchecker.JsonTestCheck(gt, checker)
	}

	assert.NoError(gt, err)
}

func TestFinRx(t *testing.T) {
	// For reliability, we really need the sockops handlers as the kprobes can be
	// unreliable. Note, the technology should work from kernel v5.5 (it needs
	// probe_read_kernel in Cgroup/SKB programs).
	if !utils.SupportCGroupSKBProbeRead() {
		t.Skipf("This test requires CGroup/SKB, skipping")
	}

	hostname, err := os.Hostname()
	if err == nil && strings.Contains(hostname, "rhel") {
		t.Skipf("This test is problematic on RHEL, skipping")
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
				test.clientSignal, test.serverBytes, test.clientBytes,
				test.delay)
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
	delay            time.Duration
}

var (
	finRxTests = []finRxTest{
		{"RecvOnlyKillServerKillClient", 3551, -1, -1, "SW", "RW", syscall.SIGKILL, syscall.SIGKILL, 5, 0, time.Second},
		{"RecvOnlyKillServerHupClient", 3552, -1, -1, "SW", "RW", syscall.SIGKILL, syscall.SIGHUP, 5, 0, time.Second},
		{"RecvOnlyKillServerTermClient", 3553, -1, -1, "SW", "RW", syscall.SIGKILL, syscall.SIGTERM, 5, 0, time.Second},
		{"RecvOnlyKillServerExitClient", 3554, -1, 1, "SW", "R", syscall.SIGKILL, 0, 5, 0, time.Second},
		{"RecvOnlyHupServerKillClient", 3555, -1, -1, "SW", "RW", syscall.SIGHUP, syscall.SIGKILL, 5, 0, time.Second},
		{"RecvOnlyHupServerHupClient", 3556, -1, -1, "SW", "RW", syscall.SIGHUP, syscall.SIGHUP, 5, 0, time.Second},
		{"RecvOnlyHupServerTermClient", 3557, -1, -1, "SW", "RW", syscall.SIGHUP, syscall.SIGTERM, 5, 0, time.Second},
		{"RecvOnlyHupServerExitClient", 3558, -1, 1, "SW", "R", syscall.SIGHUP, 0, 5, 0, time.Second},
		{"RecvOnlyTermServerKillClient", 3559, -1, -1, "SW", "RW", syscall.SIGTERM, syscall.SIGKILL, 5, 0, time.Second},
		{"RecvOnlyTermServerHupClient", 3560, -1, -1, "SW", "RW", syscall.SIGTERM, syscall.SIGHUP, 5, 0, time.Second},
		{"RecvOnlyTermServerTermClient", 3561, -1, -1, "SW", "RW", syscall.SIGTERM, syscall.SIGTERM, 5, 0, time.Second},
		{"RecvOnlyTermServerExitClient", 3562, -1, 1, "SW", "R", syscall.SIGTERM, 0, 5, 0, time.Second},
		{"RecvOnlyExitServerKillClient", 3563, 1, -1, "S", "RW", 0, syscall.SIGKILL, 5, 0, time.Second},
		{"RecvOnlyExitServerHupClient", 3564, 1, -1, "S", "RW", 0, syscall.SIGHUP, 5, 0, time.Second},
		{"RecvOnlyExitServerTermClient", 3565, 1, -1, "S", "RW", 0, syscall.SIGTERM, 5, 0, time.Second},
		{"RecvOnlyExitServerExitClient", 3566, 1, 1, "S", "R", 0, 0, 5, 0, time.Second},
		{"SendOnlyKillServerKillClient", 3567, -1, -1, "RW", "SW", syscall.SIGKILL, syscall.SIGKILL, 0, 5, time.Second},
		{"SendOnlyKillServerHupClient", 3568, -1, -1, "RW", "SW", syscall.SIGKILL, syscall.SIGHUP, 0, 5, time.Second},
		{"SendOnlyKillServerTermClient", 3569, -1, -1, "RW", "SW", syscall.SIGKILL, syscall.SIGTERM, 0, 5, time.Second},
		{"SendOnlyKillServerExitClient", 3570, -1, 1, "RW", "S", syscall.SIGKILL, 0, 0, 5, time.Second},
		{"SendOnlyHupServerKillClient", 3571, -1, -1, "RW", "SW", syscall.SIGHUP, syscall.SIGKILL, 0, 5, time.Second},
		{"SendOnlyHupServerHupClient", 3572, -1, -1, "RW", "SW", syscall.SIGHUP, syscall.SIGHUP, 0, 5, time.Second},
		{"SendOnlyHupServerTermClient", 3573, -1, -1, "RW", "SW", syscall.SIGHUP, syscall.SIGTERM, 0, 5, time.Second},
		{"SendOnlyHupServerExitClient", 3574, -1, 1, "RW", "S", syscall.SIGHUP, 0, 0, 5, time.Second},
		{"SendOnlyTermServerKillClient", 3575, -1, -1, "RW", "SW", syscall.SIGTERM, syscall.SIGKILL, 0, 5, time.Second},
		{"SendOnlyTermServerHupClient", 3576, -1, -1, "RW", "SW", syscall.SIGTERM, syscall.SIGHUP, 0, 5, time.Second},
		{"SendOnlyTermServerTermClient", 3577, -1, -1, "RW", "SW", syscall.SIGTERM, syscall.SIGTERM, 0, 5, time.Second},
		{"SendOnlyTermServerExitClient", 3578, -1, 1, "RW", "S", syscall.SIGTERM, 0, 0, 5, time.Second},
		{"SendOnlyExitServerKillClient", 3579, 1, -1, "R", "SW", 0, syscall.SIGKILL, 0, 5, time.Second},
		{"SendOnlyExitServerHupClient", 3580, 1, -1, "R", "SW", 0, syscall.SIGHUP, 0, 5, time.Second},
		{"SendOnlyExitServerTermClient", 3581, 1, -1, "R", "SW", 0, syscall.SIGTERM, 0, 5, time.Second},
		{"SendOnlyExitServerExitClient", 3582, 1, 1, "R", "S", 0, 0, 0, 5, time.Second},
		{"SendRecvKillServerKillClient", 3583, -1, -1, "RSW", "SRW", syscall.SIGKILL, syscall.SIGKILL, 5, 5, time.Second},
		{"SendRecvKillServerHupClient", 3584, -1, -1, "RSW", "SRW", syscall.SIGKILL, syscall.SIGHUP, 5, 5, time.Second},
		{"SendRecvKillServerTermClient", 3585, -1, -1, "RSW", "SRW", syscall.SIGKILL, syscall.SIGTERM, 5, 5, time.Second},
		{"SendRecvKillServerExitClient", 3586, -1, 1, "RSW", "SR", syscall.SIGKILL, 0, 5, 5, time.Second},
		{"SendRecvHupServerKillClient", 3587, -1, -1, "RSW", "SRW", syscall.SIGHUP, syscall.SIGKILL, 5, 5, time.Second},
		{"SendRecvHupServerHupClient", 3588, -1, -1, "RSW", "SRW", syscall.SIGHUP, syscall.SIGHUP, 5, 5, time.Second},
		{"SendRecvHupServerTermClient", 3589, -1, -1, "RSW", "SRW", syscall.SIGHUP, syscall.SIGTERM, 5, 5, time.Second},
		{"SendRecvHupServerExitClient", 3590, -1, 1, "RSW", "SR", syscall.SIGHUP, 0, 5, 5, time.Second},
		{"SendRecvTermServerKillClient", 3591, -1, -1, "RSW", "SRW", syscall.SIGTERM, syscall.SIGKILL, 5, 5, time.Second},
		{"SendRecvTermServerHupClient", 3592, -1, -1, "RSW", "SRW", syscall.SIGTERM, syscall.SIGHUP, 5, 5, time.Second},
		{"SendRecvTermServerTermClient", 3593, -1, -1, "RSW", "SRW", syscall.SIGTERM, syscall.SIGTERM, 5, 5, time.Second},
		{"SendRecvTermServerExitClient", 3594, -1, 1, "RSW", "SR", syscall.SIGTERM, 0, 5, 5, time.Second},
		{"SendRecvExitServerKillClient", 3595, 1, -1, "RS", "SRW", 0, syscall.SIGKILL, 5, 5, time.Second},
		{"SendRecvExitServerHupClient", 3596, 1, -1, "RS", "SRW", 0, syscall.SIGHUP, 5, 5, time.Second},
		{"SendRecvExitServerTermClient", 3597, 1, -1, "RS", "SRW", 0, syscall.SIGTERM, 5, 5, time.Second},
		{"SendRecvExitServerExitClient", 3598, 1, 1, "RS", "SR", 0, 0, 5, 5, time.Second},
		{"RecvSendKillServerKillClient", 3599, -1, -1, "SRW", "RSW", syscall.SIGKILL, syscall.SIGKILL, 5, 5, time.Second},
		{"RecvSendKillServerHupClient", 3600, -1, -1, "SRW", "RSW", syscall.SIGKILL, syscall.SIGHUP, 5, 5, time.Second},
		{"RecvSendKillServerTermClient", 3601, -1, -1, "SRW", "RSW", syscall.SIGKILL, syscall.SIGTERM, 5, 5, time.Second},
		{"RecvSendKillServerExitClient", 3602, -1, 1, "SRW", "RS", syscall.SIGKILL, 0, 5, 5, time.Second},
		{"RecvSendHupServerKillClient", 3603, -1, -1, "SRW", "RSW", syscall.SIGHUP, syscall.SIGKILL, 5, 5, time.Second},
		{"RecvSendHupServerHupClient", 3604, -1, -1, "SRW", "RSW", syscall.SIGHUP, syscall.SIGHUP, 5, 5, time.Second},
		{"RecvSendHupServerTermClient", 3605, -1, -1, "SRW", "RSW", syscall.SIGHUP, syscall.SIGTERM, 5, 5, time.Second},
		{"RecvSendHupServerExitClient", 3606, -1, 1, "SRW", "RS", syscall.SIGHUP, 0, 5, 5, time.Second},
		{"RecvSendTermServerKillClient", 3607, -1, -1, "SRW", "RSW", syscall.SIGTERM, syscall.SIGKILL, 5, 5, time.Second},
		{"RecvSendTermServerHupClient", 3608, -1, -1, "SRW", "RSW", syscall.SIGTERM, syscall.SIGHUP, 5, 5, time.Second},
		{"RecvSendTermServerTermClient", 3609, -1, -1, "SRW", "RSW", syscall.SIGTERM, syscall.SIGTERM, 5, 5, time.Second},
		{"RecvSendTermServerExitClient", 3610, -1, 1, "SRW", "RS", syscall.SIGTERM, 0, 5, 5, time.Second},
		{"RecvSendExitServerKillClient", 3611, 1, -1, "SR", "RSW", 0, syscall.SIGKILL, 5, 5, time.Second},
		{"RecvSendExitServerHupClient", 3612, 1, -1, "SR", "RSW", 0, syscall.SIGHUP, 5, 5, time.Second},
		{"RecvSendExitServerTermClient", 3613, 1, -1, "SR", "RSW", 0, syscall.SIGTERM, 5, 5, time.Second},
		{"RecvSendExitServerExitClient", 3614, 1, 1, "SR", "RS", 0, 0, 5, 5, time.Second},
		{"SilentKillServerKillClient", 3615, -1, -1, "W", "W", syscall.SIGKILL, syscall.SIGKILL, 0, 0, time.Second},
		{"SilentKillServerHupClient", 3616, -1, -1, "W", "W", syscall.SIGKILL, syscall.SIGHUP, 0, 0, time.Second},
		{"SilentKillServerTermClient", 3617, -1, -1, "W", "W", syscall.SIGKILL, syscall.SIGTERM, 0, 0, time.Second},
		{"SilentKillServerExitClient", 3618, -1, 0, "W", "", syscall.SIGKILL, 0, 0, 0, time.Second},
		{"SilentHupServerKillClient", 3619, -1, -1, "W", "W", syscall.SIGHUP, syscall.SIGKILL, 0, 0, time.Second},
		{"SilentHupServerHupClient", 3620, -1, -1, "W", "W", syscall.SIGHUP, syscall.SIGHUP, 0, 0, time.Second},
		{"SilentHupServerTermClient", 3621, -1, -1, "W", "W", syscall.SIGHUP, syscall.SIGTERM, 0, 0, time.Second},
		{"SilentHupServerExitClient", 3622, -1, 0, "W", "", syscall.SIGHUP, 0, 0, 0, time.Second},
		{"SilentTermServerKillClient", 3623, -1, -1, "W", "W", syscall.SIGTERM, syscall.SIGKILL, 0, 0, time.Second},
		{"SilentTermServerHupClient", 3624, -1, -1, "W", "W", syscall.SIGTERM, syscall.SIGHUP, 0, 0, time.Second},
		{"SilentTermServerTermClient", 3625, -1, -1, "W", "W", syscall.SIGTERM, syscall.SIGTERM, 0, 0, time.Second},
		{"SilentTermServerExitClient", 3626, -1, 0, "W", "", syscall.SIGTERM, 0, 0, 0, time.Second},
		{"SilentExitServerKillClient", 3627, 0, -1, "", "W", 0, syscall.SIGKILL, 0, 0, time.Second},
		{"SilentExitServerHupClient", 3627, 0, -1, "", "W", 0, syscall.SIGHUP, 0, 0, time.Second},
		{"SilentExitServerTermClient", 3629, 0, -1, "", "W", 0, syscall.SIGTERM, 0, 0, time.Second},
		{"SilentExitServerExitClient", 3630, 0, 0, "", "", 0, 0, 0, 0, time.Second},
	}
)

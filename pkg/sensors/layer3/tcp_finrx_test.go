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
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/pkg/kernels"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/jsonchecker"
	"github.com/isovalent/hubble-fgs/pkg/testutils"
	"github.com/isovalent/hubble-fgs/pkg/testutils/runner"

	_ "github.com/isovalent/hubble-fgs/pkg/sensors/exec"
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

func testFinRx(t *testing.T, port uint32, serverIterations, clientIterations int,
	serverPattern, clientPattern string, serverSignal, clientSignal syscall.Signal,
	serverBytes, clientBytes uint64, delay time.Duration) {

	// While investigating the flakes in the tests, let's disable them temporarily
	// to avoid making CI difficult for people.
	t.Skip("test is disabled")

	// For reliability, we really need the sockops handlers as the kprobes can be
	// unreliable. Note, the technology should work from kernel v5.4; it's just
	// flaky to test on kernels <v5.14. We specify v5.15 here because that is the
	// next LTS kernel.
	if v := "5.5.0"; !kernels.MinKernelVersion(v) {
		t.Skipf("Minimum kernel version (%v) not met, skipping", v)
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

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

	obs := getBasicTcpObserver(t, ctx, false)
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)

	readyWG.Wait()
	cmdServer := exec.Command(server, fmt.Sprintf("%d", port), fmt.Sprintf("%d", serverIterations), serverPattern)
	serverOut, err := cmdServer.StdoutPipe()
	require.NoError(t, err, "could not connect to server output pipe")

	err = cmdServer.Start()
	require.NoError(t, err, "cannot start server")

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
	require.NoError(t, err, "cannot start client")

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

	err = jsonchecker.JsonTestCheck(t, checker)
	if err != nil {
		// Checker test failed, so maybe we need to wait for the sockets to close
		err = waitForSocketsToClose(t, port)
		if err != nil {
			t.Logf("waitForSocketsToClose failed: '%s'", err)
		}
		time.Sleep(100 * time.Millisecond)
		err = jsonchecker.JsonTestCheck(t, checker)
	}

	assert.NoError(t, err)
}

// RecvOnlyKillServer
func TestFinRxRecvOnlyKillServerKillClient(t *testing.T) {
	testFinRx(t, 3551, -1, -1, "SW", "RW", syscall.SIGKILL, syscall.SIGKILL, 5, 0, time.Second)
}

func TestFinRxRecvOnlyKillServerHupClient(t *testing.T) {
	testFinRx(t, 3551, -1, -1, "SW", "RW", syscall.SIGKILL, syscall.SIGHUP, 5, 0, time.Second)
}

func TestFinRxRecvOnlyKillServerTermClient(t *testing.T) {
	testFinRx(t, 3551, -1, -1, "SW", "RW", syscall.SIGKILL, syscall.SIGTERM, 5, 0, time.Second)
}

func TestFinRxRecvOnlyKillServerExitClient(t *testing.T) {
	testFinRx(t, 3551, -1, 1, "SW", "R", syscall.SIGKILL, 0, 5, 0, time.Second)
}

// RecvOnlyHupServer
func TestFinRxRecvOnlyHupServerKillClient(t *testing.T) {
	testFinRx(t, 3551, -1, -1, "SW", "RW", syscall.SIGHUP, syscall.SIGKILL, 5, 0, time.Second)
}

func TestFinRxRecvOnlyHupServerHupClient(t *testing.T) {
	testFinRx(t, 3551, -1, -1, "SW", "RW", syscall.SIGHUP, syscall.SIGHUP, 5, 0, time.Second)
}

func TestFinRxRecvOnlyHupServerTermClient(t *testing.T) {
	testFinRx(t, 3551, -1, -1, "SW", "RW", syscall.SIGHUP, syscall.SIGTERM, 5, 0, time.Second)
}

func TestFinRxRecvOnlyHupServerExitClient(t *testing.T) {
	testFinRx(t, 3551, -1, 1, "SW", "R", syscall.SIGHUP, 0, 5, 0, time.Second)
}

// RecvOnlyTermServer
func TestFinRxRecvOnlyTermServerKillClient(t *testing.T) {
	testFinRx(t, 3551, -1, -1, "SW", "RW", syscall.SIGTERM, syscall.SIGKILL, 5, 0, time.Second)
}

func TestFinRxRecvOnlyTermServerHupClient(t *testing.T) {
	testFinRx(t, 3551, -1, -1, "SW", "RW", syscall.SIGTERM, syscall.SIGHUP, 5, 0, time.Second)
}

func TestFinRxRecvOnlyTermServerTermClient(t *testing.T) {
	testFinRx(t, 3551, -1, -1, "SW", "RW", syscall.SIGTERM, syscall.SIGTERM, 5, 0, time.Second)
}

func TestFinRxRecvOnlyTermServerExitClient(t *testing.T) {
	testFinRx(t, 3551, -1, 1, "SW", "R", syscall.SIGTERM, 0, 5, 0, time.Second)
}

// RecvOnlyExitServer
func TestFinRxRecvOnlyExitServerKillClient(t *testing.T) {
	testFinRx(t, 3551, 1, -1, "S", "RW", 0, syscall.SIGKILL, 5, 0, time.Second)
}

func TestFinRxRecvOnlyExitServerHupClient(t *testing.T) {
	testFinRx(t, 3551, 1, -1, "S", "RW", 0, syscall.SIGHUP, 5, 0, time.Second)
}

func TestFinRxRecvOnlyExitServerTermClient(t *testing.T) {
	testFinRx(t, 3551, 1, -1, "S", "RW", 0, syscall.SIGTERM, 5, 0, time.Second)
}

func TestBrokenFinRxRecvOnlyExitServerExitClient(t *testing.T) {
	testFinRx(t, 3551, 1, 1, "S", "R", 0, 0, 5, 0, time.Second)
}

// SendOnlyKillServer
func TestFinRxSendOnlyKillServerKillClient(t *testing.T) {
	testFinRx(t, 3551, -1, -1, "RW", "SW", syscall.SIGKILL, syscall.SIGKILL, 0, 5, time.Second)
}

func TestFinRxSendOnlyKillServerHupClient(t *testing.T) {
	testFinRx(t, 3551, -1, -1, "RW", "SW", syscall.SIGKILL, syscall.SIGHUP, 0, 5, time.Second)
}

func TestFinRxSendOnlyKillServerTermClient(t *testing.T) {
	testFinRx(t, 3551, -1, -1, "RW", "SW", syscall.SIGKILL, syscall.SIGTERM, 0, 5, time.Second)
}

func TestFinRxSendOnlyKillServerExitClient(t *testing.T) {
	testFinRx(t, 3551, -1, 1, "RW", "S", syscall.SIGKILL, 0, 0, 5, time.Second)
}

// SendOnlyHupServer
func TestFinRxSendOnlyHupServerKillClient(t *testing.T) {
	testFinRx(t, 3551, -1, -1, "RW", "SW", syscall.SIGHUP, syscall.SIGKILL, 0, 5, time.Second)
}

func TestFinRxSendOnlyHupServerHupClient(t *testing.T) {
	testFinRx(t, 3551, -1, -1, "RW", "SW", syscall.SIGHUP, syscall.SIGHUP, 0, 5, time.Second)
}

func TestFinRxSendOnlyHupServerTermClient(t *testing.T) {
	testFinRx(t, 3551, -1, -1, "RW", "SW", syscall.SIGHUP, syscall.SIGTERM, 0, 5, time.Second)
}

func TestFinRxSendOnlyHupServerExitClient(t *testing.T) {
	testFinRx(t, 3551, -1, 1, "RW", "S", syscall.SIGHUP, 0, 0, 5, time.Second)
}

// SendOnlyTermServer
func TestFinRxSendOnlyTermServerKillClient(t *testing.T) {
	testFinRx(t, 3551, -1, -1, "RW", "SW", syscall.SIGTERM, syscall.SIGKILL, 0, 5, time.Second)
}

func TestFinRxSendOnlyTermServerHupClient(t *testing.T) {
	testFinRx(t, 3551, -1, -1, "RW", "SW", syscall.SIGTERM, syscall.SIGHUP, 0, 5, time.Second)
}

func TestFinRxSendOnlyTermServerTermClient(t *testing.T) {
	testFinRx(t, 3551, -1, -1, "RW", "SW", syscall.SIGTERM, syscall.SIGTERM, 0, 5, time.Second)
}

func TestFinRxSendOnlyTermServerExitClient(t *testing.T) {
	testFinRx(t, 3551, -1, 1, "RW", "S", syscall.SIGTERM, 0, 0, 5, time.Second)
}

// SendOnlyExitServer
func TestFinRxSendOnlyExitServerKillClient(t *testing.T) {
	testFinRx(t, 3551, 1, -1, "R", "SW", 0, syscall.SIGKILL, 0, 5, time.Second)
}

func TestFinRxSendOnlyExitServerHupClient(t *testing.T) {
	testFinRx(t, 3551, 1, -1, "R", "SW", 0, syscall.SIGHUP, 0, 5, time.Second)
}

func TestFinRxSendOnlyExitServerTermClient(t *testing.T) {
	testFinRx(t, 3551, 1, -1, "R", "SW", 0, syscall.SIGTERM, 0, 5, time.Second)
}

func TestFinRxSendOnlyExitServerExitClient(t *testing.T) {
	testFinRx(t, 3551, 1, 1, "R", "S", 0, 0, 0, 5, time.Second)
}

// SendRecvKillServer
func TestFinRxSendRecvKillServerKillClient(t *testing.T) {
	testFinRx(t, 3551, -1, -1, "RSW", "SRW", syscall.SIGKILL, syscall.SIGKILL, 5, 5, time.Second)
}

func TestFinRxSendRecvKillServerHupClient(t *testing.T) {
	testFinRx(t, 3551, -1, -1, "RSW", "SRW", syscall.SIGKILL, syscall.SIGHUP, 5, 5, time.Second)
}

func TestFinRxSendRecvKillServerTermClient(t *testing.T) {
	testFinRx(t, 3551, -1, -1, "RSW", "SRW", syscall.SIGKILL, syscall.SIGTERM, 5, 5, time.Second)
}

func TestFinRxSendRecvKillServerExitClient(t *testing.T) {
	testFinRx(t, 3551, -1, 1, "RSW", "SR", syscall.SIGKILL, 0, 5, 5, time.Second)
}

// SendRecvHupServer
func TestFinRxSendRecvHupServerKillClient(t *testing.T) {
	testFinRx(t, 3551, -1, -1, "RSW", "SRW", syscall.SIGHUP, syscall.SIGKILL, 5, 5, time.Second)
}

func TestFinRxSendRecvHupServerHupClient(t *testing.T) {
	testFinRx(t, 3551, -1, -1, "RSW", "SRW", syscall.SIGHUP, syscall.SIGHUP, 5, 5, time.Second)
}

func TestFinRxSendRecvHupServerTermClient(t *testing.T) {
	testFinRx(t, 3551, -1, -1, "RSW", "SRW", syscall.SIGHUP, syscall.SIGTERM, 5, 5, time.Second)
}

func TestFinRxSendRecvHupServerExitClient(t *testing.T) {
	testFinRx(t, 3551, -1, 1, "RSW", "SR", syscall.SIGHUP, 0, 5, 5, time.Second)
}

// SendRecvTermServer
func TestFinRxSendRecvTermServerKillClient(t *testing.T) {
	testFinRx(t, 3551, -1, -1, "RSW", "SRW", syscall.SIGTERM, syscall.SIGKILL, 5, 5, time.Second)
}

func TestFinRxSendRecvTermServerHupClient(t *testing.T) {
	testFinRx(t, 3551, -1, -1, "RSW", "SRW", syscall.SIGTERM, syscall.SIGHUP, 5, 5, time.Second)
}

func TestFinRxSendRecvTermServerTermClient(t *testing.T) {
	testFinRx(t, 3551, -1, -1, "RSW", "SRW", syscall.SIGTERM, syscall.SIGTERM, 5, 5, time.Second)
}

func TestFinRxSendRecvTermServerExitClient(t *testing.T) {
	testFinRx(t, 3551, -1, 1, "RSW", "SR", syscall.SIGTERM, 0, 5, 5, time.Second)
}

// SendRecvExitServer
func TestFinRxSendRecvExitServerKillClient(t *testing.T) {
	testFinRx(t, 3551, 1, -1, "RS", "SRW", 0, syscall.SIGKILL, 5, 5, time.Second)
}

func TestFinRxSendRecvExitServerHupClient(t *testing.T) {
	testFinRx(t, 3551, 1, -1, "RS", "SRW", 0, syscall.SIGHUP, 5, 5, time.Second)
}

func TestFinRxSendRecvExitServerTermClient(t *testing.T) {
	testFinRx(t, 3551, 1, -1, "RS", "SRW", 0, syscall.SIGTERM, 5, 5, time.Second)
}

func TestFinRxSendRecvExitServerExitClient(t *testing.T) {
	testFinRx(t, 3551, 1, 1, "RS", "SR", 0, 0, 5, 5, time.Second)
}

// RecvSendKillServer
func TestFinRxRecvSendKillServerKillClient(t *testing.T) {
	testFinRx(t, 3551, -1, -1, "SRW", "RSW", syscall.SIGKILL, syscall.SIGKILL, 5, 5, time.Second)
}

func TestFinRxRecvSendKillServerHupClient(t *testing.T) {
	testFinRx(t, 3551, -1, -1, "SRW", "RSW", syscall.SIGKILL, syscall.SIGHUP, 5, 5, time.Second)
}

func TestFinRxRecvSendKillServerTermClient(t *testing.T) {
	testFinRx(t, 3551, -1, -1, "SRW", "RSW", syscall.SIGKILL, syscall.SIGTERM, 5, 5, time.Second)
}

func TestFinRxRecvSendKillServerExitClient(t *testing.T) {
	testFinRx(t, 3551, -1, 1, "SRW", "RS", syscall.SIGKILL, 0, 5, 5, time.Second)
}

// RecvSendHupServer
func TestFinRxRecvSendHupServerKillClient(t *testing.T) {
	testFinRx(t, 3551, -1, -1, "SRW", "RSW", syscall.SIGHUP, syscall.SIGKILL, 5, 5, time.Second)
}

func TestFinRxRecvSendHupServerHupClient(t *testing.T) {
	testFinRx(t, 3551, -1, -1, "SRW", "RSW", syscall.SIGHUP, syscall.SIGHUP, 5, 5, time.Second)
}

func TestFinRxRecvSendHupServerTermClient(t *testing.T) {
	testFinRx(t, 3551, -1, -1, "SRW", "RSW", syscall.SIGHUP, syscall.SIGTERM, 5, 5, time.Second)
}

func TestFinRxRecvSendHupServerExitClient(t *testing.T) {
	testFinRx(t, 3551, -1, 1, "SRW", "RS", syscall.SIGHUP, 0, 5, 5, time.Second)
}

// RecvSendTermServer
func TestFinRxRecvSendTermServerKillClient(t *testing.T) {
	testFinRx(t, 3551, -1, -1, "SRW", "RSW", syscall.SIGTERM, syscall.SIGKILL, 5, 5, time.Second)
}

func TestFinRxRecvSendTermServerHupClient(t *testing.T) {
	testFinRx(t, 3551, -1, -1, "SRW", "RSW", syscall.SIGTERM, syscall.SIGHUP, 5, 5, time.Second)
}

func TestFinRxRecvSendTermServerTermClient(t *testing.T) {
	testFinRx(t, 3551, -1, -1, "SRW", "RSW", syscall.SIGTERM, syscall.SIGTERM, 5, 5, time.Second)
}

func TestFinRxRecvSendTermServerExitClient(t *testing.T) {
	testFinRx(t, 3551, -1, 1, "SRW", "RS", syscall.SIGTERM, 0, 5, 5, time.Second)
}

// RecvSendExitServer
func TestFinRxRecvSendExitServerKillClient(t *testing.T) {
	testFinRx(t, 3551, 1, -1, "SR", "RSW", 0, syscall.SIGKILL, 5, 5, time.Second)
}

func TestFinRxRecvSendExitServerHupClient(t *testing.T) {
	testFinRx(t, 3551, 1, -1, "SR", "RSW", 0, syscall.SIGHUP, 5, 5, time.Second)
}

func TestFinRxRecvSendExitServerTermClient(t *testing.T) {
	testFinRx(t, 3551, 1, -1, "SR", "RSW", 0, syscall.SIGTERM, 5, 5, time.Second)
}

func TestFinRxRecvSendExitServerExitClient(t *testing.T) {
	testFinRx(t, 3551, 1, 1, "SR", "RS", 0, 0, 5, 5, time.Second)
}

// SilentKillServer
func TestFinRxSilentKillServerKillClient(t *testing.T) {
	testFinRx(t, 3551, -1, -1, "W", "W", syscall.SIGKILL, syscall.SIGKILL, 0, 0, time.Second)
}

func TestFinRxSilentKillServerHupClient(t *testing.T) {
	testFinRx(t, 3551, -1, -1, "W", "W", syscall.SIGKILL, syscall.SIGHUP, 0, 0, time.Second)
}

func TestFinRxSilentKillServerTermClient(t *testing.T) {
	testFinRx(t, 3551, -1, -1, "W", "W", syscall.SIGKILL, syscall.SIGTERM, 0, 0, time.Second)
}

func TestFinRxSilentKillServerExitClient(t *testing.T) {
	testFinRx(t, 3551, -1, 0, "W", "", syscall.SIGKILL, 0, 0, 0, time.Second)
}

// SilentHupServer
func TestFinRxSilentHupServerKillClient(t *testing.T) {
	testFinRx(t, 3551, -1, -1, "W", "W", syscall.SIGHUP, syscall.SIGKILL, 0, 0, time.Second)
}

func TestFinRxSilentHupServerHupClient(t *testing.T) {
	testFinRx(t, 3551, -1, -1, "W", "W", syscall.SIGHUP, syscall.SIGHUP, 0, 0, time.Second)
}

func TestFinRxSilentHupServerTermClient(t *testing.T) {
	testFinRx(t, 3551, -1, -1, "W", "W", syscall.SIGHUP, syscall.SIGTERM, 0, 0, time.Second)
}

func TestFinRxSilentHupServerExitClient(t *testing.T) {
	testFinRx(t, 3551, -1, 0, "W", "", syscall.SIGHUP, 0, 0, 0, time.Second)
}

// SilentTermServer
func TestFinRxSilentTermServerKillClient(t *testing.T) {
	testFinRx(t, 3551, -1, -1, "W", "W", syscall.SIGTERM, syscall.SIGKILL, 0, 0, time.Second)
}

func TestFinRxSilentTermServerHupClient(t *testing.T) {
	testFinRx(t, 3551, -1, -1, "W", "W", syscall.SIGTERM, syscall.SIGHUP, 0, 0, time.Second)
}

func TestFinRxSilentTermServerTermClient(t *testing.T) {
	testFinRx(t, 3551, -1, -1, "W", "W", syscall.SIGTERM, syscall.SIGTERM, 0, 0, time.Second)
}

func TestFinRxSilentTermServerExitClient(t *testing.T) {
	testFinRx(t, 3551, -1, 0, "W", "", syscall.SIGTERM, 0, 0, 0, time.Second)
}

// SilentKillServer
func TestFinRxSilentExitServerKillClient(t *testing.T) {
	testFinRx(t, 3551, 0, -1, "", "W", 0, syscall.SIGKILL, 0, 0, time.Second)
}

func TestFinRxSilentExitServerHupClient(t *testing.T) {
	testFinRx(t, 3551, 0, -1, "", "W", 0, syscall.SIGHUP, 0, 0, time.Second)
}

func TestFinRxSilentExitServerTermClient(t *testing.T) {
	testFinRx(t, 3551, 0, -1, "", "W", 0, syscall.SIGTERM, 0, 0, time.Second)
}

func TestFinRxSilentExitServerExitClient(t *testing.T) {
	testFinRx(t, 3551, 0, 0, "", "", 0, 0, 0, 0, time.Second)
}

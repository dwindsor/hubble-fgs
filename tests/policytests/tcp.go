// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

//go:build !windows

package tests

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/pkg/kernels"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/testutils/policytest"

	"github.com/isovalent/hubble-fgs/pkg/sensors/utils"
)

const (
	// the OpenBSD netcat is required for the -s source address flag
	netcatBin     = "nc.openbsd"
	netcatPort    = 8085
	netcatMessage = "hello"
	// LISTEN, as reported in the st column of /proc/net/tcp
	tcpStateListen = "0A"
)

// netcatListenTrigger starts a netcat server, connects a netcat client to it,
// passes a message between the two, and then tears both of them down.
type netcatListenTrigger struct{}

func (trigger *netcatListenTrigger) Trigger(ctx context.Context) error {
	port := strconv.Itoa(netcatPort)

	server := exec.CommandContext(ctx, netcatBin, "-nvlp", port, "-s", "0.0.0.0")
	serverOut, err := server.StdoutPipe()
	if err != nil {
		return err
	}
	if err := server.Start(); err != nil {
		return fmt.Errorf("failed to start netcat server: %w", err)
	}
	defer killAndWait(server)

	if err := waitForTCPListen(ctx, netcatPort); err != nil {
		return err
	}

	client := exec.CommandContext(ctx, netcatBin, "127.0.0.1", port)
	clientIn, err := client.StdinPipe()
	if err != nil {
		return err
	}
	if err := client.Start(); err != nil {
		return fmt.Errorf("failed to start netcat client: %w", err)
	}
	defer killAndWait(client)

	if _, err := io.WriteString(clientIn, netcatMessage); err != nil {
		return fmt.Errorf("failed to write to netcat client: %w", err)
	}

	rx := make([]byte, len(netcatMessage))
	if _, err := io.ReadFull(serverOut, rx); err != nil {
		return fmt.Errorf("failed to read from netcat server: %w", err)
	}
	if string(rx) != netcatMessage {
		return fmt.Errorf("netcat server read %q, expected %q", rx, netcatMessage)
	}
	return nil
}

func killAndWait(cmd *exec.Cmd) {
	if cmd.Process != nil {
		cmd.Process.Kill()
	}
	_ = cmd.Wait()
}

func waitForTCPListen(ctx context.Context, port uint16) error {
	ticker := time.NewTicker(time.Millisecond)
	// The intention of this millisleep is to allow CPU relaxing, task switching, etc
	// so that hopefully some amount of time has passed between checks, mainly just to
	// reduce churn.
	defer ticker.Stop()
	for {
		listening, err := isTCPListening(port)
		if err != nil {
			return err
		}
		if listening {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("gave up waiting for a socket listening on port %d: %w", port, ctx.Err())
		case <-ticker.C:
		}
	}
}

func isTCPListening(port uint16) (bool, error) {
	procNetTCP, err := os.ReadFile("/proc/net/tcp")
	if err != nil {
		return false, err
	}
	localAddr := fmt.Sprintf("00000000:%04X", port)
	for line := range strings.SplitSeq(string(procNetTCP), "\n") {
		// fields[1] is local address:port
		// fields[2] is remote address:port
		// fields[3] is the TCP state
		fields := strings.Fields(line)
		// A TCP socket appears in tcp as soon as it is bound, in state 07 (TCP_CLOSE),
		// not just once it is listening.
		if len(fields) > 3 && fields[1] == localAddr && fields[3] == tcpStateListen {
			return true, nil
		}
	}
	return false, nil
}

func tcpPolicySkip(_ *policytest.SkipInfo) string {
	if runtime.GOARCH != "amd64" && !kernels.MinKernelVersion("5.8.0") {
		return "test requires amd64 or kernel >=5.8"
	}
	return ""
}

func tcpFailedConnectScenario(_ *policytest.Conf) *policytest.Scenario {
	triggerPath := "/usr/bin/curl"
	selfChecker := ec.NewProcessChecker().WithBinary(sm.Suffix(filepath.Base(os.Args[0])))
	curlChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(filepath.Base(triggerPath))).
		WithArguments(sm.Full("127.0.0.1"))

	return &policytest.Scenario{
		Name:    "failed TCP connect to localhost",
		Trigger: policytest.NewCmdTrigger(triggerPath, "127.0.0.1").ExpectExitCode(7),
		EventChecker: ec.NewUnorderedEventChecker(
			ec.NewProcessExecChecker("curlExec").WithProcess(curlChecker).WithParent(selfChecker),
			ec.NewProcessConnectChecker("curlConnect").
				WithProcess(curlChecker).
				WithParent(selfChecker).
				WithDestinationIp(sm.Full("127.0.0.1")).
				WithDestinationPort(80).
				WithProtocol(tetragon.SocketProtocol_TCP),
			ec.NewProcessCloseChecker("curlClose").
				WithProcess(curlChecker).
				WithParent(selfChecker).
				WithDestinationIp(sm.Full("127.0.0.1")).
				WithDestinationPort(80).
				WithProtocol(tetragon.SocketProtocol_TCP).
				WithSocketType(sm.Full("connect reset")),
		),
	}
}

func tcpListenAcceptCloseScenario(_ *policytest.Conf) *policytest.Scenario {
	selfChecker := ec.NewProcessChecker().WithBinary(sm.Suffix(filepath.Base(os.Args[0])))
	ncChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(netcatBin)).
		WithArguments(sm.Full("-nvlp " + strconv.Itoa(netcatPort) + " -s 0.0.0.0"))

	return &policytest.Scenario{
		Name:    "TCP listen, accept, and close on localhost",
		Trigger: &netcatListenTrigger{},
		EventChecker: ec.NewUnorderedEventChecker(
			ec.NewProcessExecChecker("ncExec").
				WithProcess(ncChecker).
				WithParent(selfChecker),
			ec.NewProcessListenChecker("ncListen").
				WithProcess(ncChecker).
				WithParent(selfChecker).
				WithIp(sm.Full("0.0.0.0")).
				WithPort(netcatPort).
				WithProtocol(tetragon.SocketProtocol_TCP),
			ec.NewProcessAcceptChecker("ncAccept").
				WithProcess(ncChecker).
				WithParent(selfChecker).
				WithSourceIp(sm.Full("127.0.0.1")).
				WithSourcePort(netcatPort).
				WithProtocol(tetragon.SocketProtocol_TCP),
			ec.NewProcessCloseChecker("ncClose").
				WithProcess(ncChecker).
				WithParent(selfChecker).
				WithSourceIp(sm.Full("0.0.0.0")).
				WithSourcePort(netcatPort).
				WithProtocol(tetragon.SocketProtocol_TCP).
				WithSocketType(sm.Full("listen")),
			// TODO: it would be good if we could also check the close event on
			// the accept socket, but it goes into TIME_WAIT and then
			// eventually close and I don't want to wait for it. So we need
			// some go way to close the sockets.
		),
	}
}

// The tracing policy below implicitly enables UDP, UDP cgroup and DNS on top of
// TCP, and disables the latter two when cgroup/skb is unavailable.
var tcpCLIFlags = []policytest.CLIFlag{
	{Name: "enable-network-events", Value: true},
	{Name: "enable-tcp", Value: true},
	{Name: "enable-udp", Value: true},
	{Name: "enable-udp-cgroup", Value: utils.CGroupSKBAvailable()},
	{Name: "enable-user-dns", Value: utils.CGroupSKBAvailable()},
}

var _ = policytest.NewBuilder("layer3-tcp").
	WithLabels("layer3", "tcp").
	WithSkip(tcpPolicySkip).
	WithPolicyTemplate(`
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "tcp"
spec:
  parser:
    tcp:
      enable: true
`).
	AddScenario(tcpFailedConnectScenario).
	AddScenario(tcpListenAcceptCloseScenario).
	RegisterAtInit()

var _ = policytest.NewBuilder("layer3-tcp-no-policy").
	WithLabels("layer3", "tcp").
	WithCLIFlags(tcpCLIFlags...).
	WithSkip(tcpPolicySkip).
	WithPolicyTemplate(emptyTracingPolicy).
	AddScenario(tcpFailedConnectScenario).
	AddScenario(tcpListenAcceptCloseScenario).
	RegisterAtInit()

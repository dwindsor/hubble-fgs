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
	"log/slog"
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

const udpNetcatPort = 8081

// udpNetcatTrigger sends a message from a netcat client to a netcat server over
// UDP, and then tears both of them down.
type udpNetcatTrigger struct{}

func (trigger *udpNetcatTrigger) Trigger(ctx context.Context) error {
	port := strconv.Itoa(udpNetcatPort)

	server := exec.CommandContext(ctx, netcatBin, "-unvlp", port, "-s", "0.0.0.0")
	serverOut, err := server.StdoutPipe()
	if err != nil {
		return err
	}
	if err := server.Start(); err != nil {
		return fmt.Errorf("failed to start netcat server: %w", err)
	}
	defer killAndWait(server)

	if err := waitForUDPBind(ctx, udpNetcatPort); err != nil {
		return err
	}

	client := exec.CommandContext(ctx, netcatBin, "-u", "127.0.0.1", port)
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

func waitForUDPBind(ctx context.Context, port uint16) error {
	ticker := time.NewTicker(time.Millisecond)
	// The intention of this millisleep is to allow CPU relaxing, task switching, etc
	// so that hopefully some amount of time has passed between checks, mainly just to
	// reduce churn.
	defer ticker.Stop()
	for {
		bound, err := isUDPBound(port)
		if err != nil {
			return err
		}
		if bound {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("gave up waiting for a socket bound to UDP port %d: %w", port, ctx.Err())
		case <-ticker.C:
		}
	}
}

func isUDPBound(port uint16) (bool, error) {
	procNetUDP, err := os.ReadFile("/proc/net/udp")
	if err != nil {
		return false, err
	}
	localAddr := fmt.Sprintf("00000000:%04X", port)
	for line := range strings.SplitSeq(string(procNetUDP), "\n") {
		// fields[1] is local address:port
		fields := strings.Fields(line)
		if len(fields) > 1 && fields[1] == localAddr {
			return true, nil
		}
	}
	return false, nil
}

const udpStatsPolicy = `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "udp-stats"
spec:
  parser:
    udp:
      enable: true
      cgroup: true
      statsInterval: 2
`

var udpStatsCLIFlags = []policytest.CLIFlag{
	{Name: "enable-network-events", Value: true},
	{Name: "enable-udp", Value: true},
	// TODO: This detection runs locally. It would be better to have multiple
	// variants of the test for different configurations via skip logic
	// But, agentinfo  does not current expose what's needed to determine the
	// equivalent of utils.CGroupSKBAvailable()
	{Name: "enable-udp-cgroup", Value: utils.CGroupSKBAvailable()},
	{Name: "udp-stats-interval", Value: 2 * time.Second},
}

func udpStatsPolicySkip(_ *policytest.SkipInfo) string {
	if runtime.GOARCH != "amd64" && !kernels.MinKernelVersion("5.8.0") {
		return "test requires amd64 or kernel >=5.8"
	}
	return ""
}

type udpStatsEventChecker struct {
	lifecycle                         *ec.UnorderedEventChecker
	clientStats, serverStats          *ec.ProcessSockStatsChecker
	clientBytesSent, serverBytesRead  uint64
	clientSegmentsOut, serverSegments uint32
}

// GetChecks lets policytest remove process and parent checks when the process
// cache is disabled and those event fields are unavailable. clientStats and
// serverStats are already in lifecycle; all three fields reference the same
// checker instances, so they do not need to be returned separately.
func (checker *udpStatsEventChecker) GetChecks() []ec.EventChecker {
	return checker.lifecycle.GetChecks()
}

func (checker *udpStatsEventChecker) NextEventCheck(event ec.Event, logger *slog.Logger) (bool, error) {
	if stats, ok := event.(*tetragon.ProcessSockStats); ok && stats.Stats != nil {
		switch {
		case checker.clientStats.Check(stats) == nil:
			checker.clientBytesSent += stats.Stats.BytesSent
			checker.clientSegmentsOut += stats.Stats.SegsOut
		case checker.serverStats.Check(stats) == nil:
			checker.serverBytesRead += stats.Stats.BytesReceived
			checker.serverSegments += stats.Stats.SegsIn
		}
	}

	lifecycleDone, _ := checker.lifecycle.NextEventCheck(event, logger)
	statsDone := checker.clientBytesSent == 5 && checker.clientSegmentsOut == 1 &&
		checker.serverBytesRead == 5 && checker.serverSegments == 1
	return lifecycleDone && statsDone, nil
}

func (checker *udpStatsEventChecker) FinalCheck(logger *slog.Logger) error {
	defer func() {
		checker.clientBytesSent = 0
		checker.clientSegmentsOut = 0
		checker.serverBytesRead = 0
		checker.serverSegments = 0
	}()

	if err := checker.lifecycle.FinalCheck(logger); err != nil {
		return err
	}
	if checker.clientBytesSent != 5 || checker.clientSegmentsOut != 1 {
		return fmt.Errorf("unexpected client stats: bytes sent=%d, segments out=%d", checker.clientBytesSent, checker.clientSegmentsOut)
	}
	if checker.serverBytesRead != 5 || checker.serverSegments != 1 {
		return fmt.Errorf("unexpected server stats: bytes received=%d, segments in=%d", checker.serverBytesRead, checker.serverSegments)
	}
	return nil
}

func udpStatsScenario(_ *policytest.Conf) *policytest.Scenario {
	port := strconv.Itoa(udpNetcatPort)
	selfChecker := ec.NewProcessChecker().WithBinary(sm.Suffix(filepath.Base(os.Args[0])))
	ncSrvChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(netcatBin)).
		WithArguments(sm.Full("-unvlp " + port + " -s 0.0.0.0"))
	ncCliChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(netcatBin)).
		WithArguments(sm.Full("-u 127.0.0.1 " + port))
	clientStatsChecker := ec.NewProcessSockStatsChecker("clientStats").
		WithProcess(ncCliChecker).
		WithParent(selfChecker).
		WithSocket(ec.NewSockInfoChecker().
			WithProtocol(tetragon.SocketProtocol_UDP).
			WithDestinationIp(sm.Full("127.0.0.1")).
			WithDestinationPort(udpNetcatPort))
	serverStatsChecker := ec.NewProcessSockStatsChecker("serverStats").
		WithProcess(ncSrvChecker).
		WithParent(selfChecker).
		WithSocket(ec.NewSockInfoChecker().
			WithProtocol(tetragon.SocketProtocol_UDP).
			WithSourceIp(sm.Full("127.0.0.1")).
			WithDestinationIp(sm.Full("127.0.0.1")).
			WithSourcePort(udpNetcatPort))
	lifecycleChecker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker("serverExec").
			WithProcess(ncSrvChecker).
			WithParent(selfChecker),
		ec.NewProcessExecChecker("clientExec").
			WithProcess(ncCliChecker).
			WithParent(selfChecker),
		ec.NewProcessConnectChecker("serverConnect").
			WithProcess(ncSrvChecker).
			WithParent(selfChecker).
			WithSourceIp(sm.Full("127.0.0.1")).
			WithSourcePort(udpNetcatPort).
			WithDestinationIp(sm.Full("127.0.0.1")).
			WithProtocol(tetragon.SocketProtocol_UDP),
		ec.NewProcessCloseChecker("serverClose").
			WithProcess(ncSrvChecker).
			WithParent(selfChecker).
			WithSourceIp(sm.Full("127.0.0.1")).
			WithSourcePort(udpNetcatPort).
			WithDestinationIp(sm.Full("127.0.0.1")).
			WithProtocol(tetragon.SocketProtocol_UDP),
		ec.NewProcessCloseChecker("clientClose").
			WithProcess(ncCliChecker).
			WithParent(selfChecker).
			WithSourceIp(sm.Full("127.0.0.1")).
			WithDestinationPort(udpNetcatPort).
			WithDestinationIp(sm.Full("127.0.0.1")).
			WithProtocol(tetragon.SocketProtocol_UDP),
		clientStatsChecker,
		serverStatsChecker,
	)
	return &policytest.Scenario{
		Name:    "UDP localhost exchange emits socket stats",
		Trigger: &udpNetcatTrigger{},
		EventChecker: &udpStatsEventChecker{
			lifecycle:   lifecycleChecker,
			clientStats: clientStatsChecker,
			serverStats: serverStatsChecker,
		},
	}
}

var _ = policytest.NewBuilder("layer3-udp-sockstats").
	WithLabels("layer3", "udp").
	WithSkip(udpStatsPolicySkip).
	WithPolicyTemplate(udpStatsPolicy).
	AddScenario(udpStatsScenario).
	RegisterAtInit()

var _ = policytest.NewBuilder("layer3-udp-sockstats-no-policy").
	WithLabels("layer3", "udp").
	WithCLIFlags(udpStatsCLIFlags...).
	WithSkip(udpStatsPolicySkip).
	WithPolicyTemplate(emptyTracingPolicy).
	AddScenario(udpStatsScenario).
	RegisterAtInit()

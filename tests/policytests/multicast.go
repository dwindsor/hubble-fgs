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
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/matchers/durationmatcher"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/testutils/policytest"

	"github.com/isovalent/hubble-fgs/pkg/sensors/utils"
)

type multicastTriggerMode uint8

const (
	multicastSequenceTrigger multicastTriggerMode = iota
	multicastSampleTrigger
)

type multicastTrigger struct {
	socatPath     string
	interfaceAddr string
	groupAddr     string
	port          int
	mode          multicastTriggerMode
}

// The following values come from sample data. The second should hash to a value under our .01 threshold.
// These are to be stored in MSB in the packets in two parts: the upper 4 bytes should be written to the start of the packet;
// and the lower 4 bytes to packet offset 8.
var RTPSampleData = []uint64{
	0x80005779f5d6285e,
	0x8000577af5d6285e,
	0x8000577bf5d6285e,
	0x8000577cf5d6285e,
	0x8000577df5d6285e,
}

func defaultInterfaceAddress() (string, error) {
	defaultRoute, err := exec.Command("bash", "-c", "ip r | grep default").Output()
	if err != nil {
		return "", err
	}
	defaultRouteFields := strings.Fields(string(defaultRoute))
	ifAddr := defaultRouteFields[8]
	return ifAddr, nil
}

func (trigger *multicastTrigger) Trigger(ctx context.Context) error {
	socatArgument := fmt.Sprintf("UDP4-RECVFROM:%d,ip-add-membership=%s:%s,fork", trigger.port, trigger.groupAddr, trigger.interfaceAddr)
	server := exec.CommandContext(ctx, trigger.socatPath, "-", socatArgument)
	serverStdout, err := server.StdoutPipe()
	if err != nil {
		return err
	}
	server.Stderr = os.Stderr
	if err := server.Start(); err != nil {
		return err
	}
	defer func() {
		server.Process.Kill()
		server.Wait()
	}()

	if err := waitForSocketToListen(ctx, net.ParseIP("0.0.0.0"), uint16(trigger.port), syscall.IPPROTO_UDP, syscall.AF_INET); err != nil {
		return err
	}

	localAddr, err := net.ResolveUDPAddr("udp4", net.JoinHostPort(trigger.interfaceAddr, fmt.Sprintf("%d", trigger.port+1)))
	if err != nil {
		return err
	}
	remoteAddr, err := net.ResolveUDPAddr("udp4", net.JoinHostPort(trigger.groupAddr, fmt.Sprintf("%d", trigger.port)))
	if err != nil {
		return err
	}
	connection, err := net.DialUDP("udp4", localAddr, remoteAddr)
	if err != nil {
		return err
	}
	defer connection.Close()

	buffer := make([]byte, 1280)
	if _, err := rand.Read(buffer); err != nil {
		return err
	}
	writeSequence := func(sourceID uint32, sequence uint16) error {
		binary.BigEndian.PutUint16(buffer[2:4], sequence)
		binary.BigEndian.PutUint32(buffer[8:12], sourceID)
		_, err := connection.Write(buffer)
		time.Sleep(10 * time.Millisecond)
		return err
	}

	packetsSent := 0
	if trigger.mode == multicastSequenceTrigger {
		packets := [][2]uint32{{45, 0}, {46, 0}, {46, 1}, {46, 2}, {45, 1}, {45, 2}, {45, 4}, {45, 3}, {45, 5}, {46, 3}, {46, 5}, {46, 6}}
		for _, packet := range packets {
			if err := writeSequence(packet[0], uint16(packet[1])); err != nil {
				return err
			}
		}
		packetsSent = len(packets)
	} else {
		for _, data := range RTPSampleData {
			binary.BigEndian.PutUint32(buffer[0:4], uint32(data>>32))
			binary.BigEndian.PutUint32(buffer[8:12], uint32(data))
			if _, err := connection.Write(buffer); err != nil {
				return err
			}
			time.Sleep(10 * time.Millisecond)
		}
		packetsSent = len(RTPSampleData)
	}

	serverData := make([]byte, len(buffer))
	packetsReceived := 0
	for packetsReceived < packetsSent {
		numBytesRead, err := serverStdout.Read(serverData)
		if err != nil {
			return err
		}
		if numBytesRead > 0 {
			packetsReceived++
		}
	}
	return nil
}

func htonll(v uint64) uint64 {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, v)
	return binary.LittleEndian.Uint64(b)
}

func multicastSkip(_ *policytest.SkipInfo) string {
	if !utils.CGroupSKBAvailable() {
		return "test requires CGroup/SKB"
	}
	if !kernels.MinKernelVersion("6.12") {
		return "test requires kernel >=6.12"
	}
	return ""
}

type multicastSampleEventChecker struct {
	required  *ec.UnorderedEventChecker
	forbidden map[uint64]*ec.ProcessMulticastSampleChecker
	failure   error
}

// GetChecks exposes all nested checkers so policytest can remove process and
// parent checks, including future ones on forbidden events, when the process
// cache is disabled and those fields are unavailable.
func (checker *multicastSampleEventChecker) GetChecks() []ec.EventChecker {
	required := checker.required.GetChecks()
	checks := make([]ec.EventChecker, 0, len(required)+len(checker.forbidden))
	checks = append(checks, required...)
	for _, forbidden := range checker.forbidden {
		checks = append(checks, forbidden)
	}
	return checks
}

func (checker *multicastSampleEventChecker) NextEventCheck(event ec.Event, logger *slog.Logger) (bool, error) {
	for data, forbidden := range checker.forbidden {
		if forbidden.CheckEvent(event) == nil {
			checker.failure = fmt.Errorf("unexpected multicast sample data: %#x", data)
			return true, checker.failure
		}
	}
	return checker.required.NextEventCheck(event, logger)
}

func (checker *multicastSampleEventChecker) FinalCheck(logger *slog.Logger) error {
	requiredErr := checker.required.FinalCheck(logger)
	failure := checker.failure
	checker.failure = nil
	if failure != nil {
		return failure
	}
	return requiredErr
}

const multicastPolicy = `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "udp-multicast"
spec:
  parser:
    udp:
      enable: true
      cgroup: true
      statsInterval: 20
`

func multicastSequenceScenario(_ *policytest.Conf) *policytest.Scenario {
	triggerPath := "/usr/bin/socat"
	interfaceAddr, err := defaultInterfaceAddress()
	if err != nil {
		panic(err)
	}
	serverChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(filepath.Base(triggerPath))).
		WithArguments(sm.Full(fmt.Sprintf("- UDP4-RECVFROM:8814,ip-add-membership=225.2.2.3:%s,fork", interfaceAddr)))
	return &policytest.Scenario{
		Name: "detect RTP sequence gaps",
		Trigger: &multicastTrigger{
			socatPath: triggerPath, interfaceAddr: interfaceAddr,
			groupAddr: "225.2.2.3", port: 8814, mode: multicastSequenceTrigger,
		},
		EventChecker: ec.NewUnorderedEventChecker(
			ec.NewProcessExecChecker("serverExec").
				WithProcess(serverChecker),
			ec.NewProcessUdpSeqCheckErrorChecker("source45Gap").
				WithProcess(serverChecker).
				WithApplicationId(2).
				WithAppSpecificId(45).
				WithSocket(ec.NewSockInfoChecker().WithSourcePort(8814)).
				WithSeqNumExpected(3).
				WithSeqNumReceived(4),
			ec.NewProcessUdpSeqCheckErrorChecker("source46Gap").
				WithProcess(serverChecker).
				WithApplicationId(2).
				WithAppSpecificId(46).
				WithSocket(ec.NewSockInfoChecker().WithSourcePort(8814)).
				WithSeqNumExpected(4).
				WithSeqNumReceived(5),
			ec.NewProcessCloseChecker("serverClose").
				WithProcess(serverChecker).
				WithDuration(durationmatcher.Between(
					&durationmatcher.Duration{Duration: 0},
					&durationmatcher.Duration{Duration: 20 * time.Second})),
			ec.NewProcessExitChecker("serverExit").
				WithProcess(serverChecker),
		),
	}
}

func multicastSampleScenario(_ *policytest.Conf) *policytest.Scenario {
	triggerPath := "/usr/bin/socat"
	interfaceAddr, err := defaultInterfaceAddress()
	if err != nil {
		panic(err)
	}
	selfChecker := ec.NewProcessChecker().WithBinary(sm.Suffix(filepath.Base(os.Args[0])))
	serverChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(filepath.Base(triggerPath))).
		WithArguments(sm.Full(fmt.Sprintf("- UDP4-RECVFROM:8818,ip-add-membership=225.2.2.5:%s,fork", interfaceAddr)))
	sampledData := htonll(RTPSampleData[1])
	required := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker("serverExec").
			WithProcess(serverChecker),
		ec.NewProcessMulticastSampleChecker("clientSample").
			WithProcess(selfChecker).
			WithDestinationPort(8818).
			WithData(sampledData).
			WithDirection(tetragon.Direction_EGRESS),
		ec.NewProcessMulticastSampleChecker("serverSample").
			WithProcess(serverChecker).
			WithSourcePort(8818).
			WithData(sampledData).
			WithDirection(tetragon.Direction_INGRESS),
		ec.NewProcessCloseChecker("serverClose").
			WithProcess(serverChecker).
			WithDuration(durationmatcher.Between(
				&durationmatcher.Duration{Duration: 0},
				&durationmatcher.Duration{Duration: 20 * time.Second})),
		ec.NewProcessExitChecker("serverExit").
			WithProcess(serverChecker),
	)
	forbidden := make(map[uint64]*ec.ProcessMulticastSampleChecker, len(RTPSampleData)-1)
	for index, data := range RTPSampleData {
		if index != 1 {
			converted := htonll(data)
			forbidden[converted] = ec.NewProcessMulticastSampleChecker(fmt.Sprintf("sample%d", index)).
				WithData(converted)
		}
	}
	return &policytest.Scenario{
		Name: "sample RTP multicast packets",
		Trigger: &multicastTrigger{
			socatPath: triggerPath, interfaceAddr: interfaceAddr,
			groupAddr: "225.2.2.5", port: 8818, mode: multicastSampleTrigger,
		},
		EventChecker: &multicastSampleEventChecker{required: required, forbidden: forbidden},
	}
}

var multicastSequenceFlags = []policytest.CLIFlag{
	{Name: "enable-network-events", Value: true},
	{Name: "multicast-app", Value: "RTP"},
	{Name: "multicast-ports", Value: []int{8814}},
	{Name: "enable-multicast-seq-check", Value: true},
}

var multicastSampleFlags = []policytest.CLIFlag{
	{Name: "enable-network-events", Value: true},
	{Name: "multicast-app", Value: "RTP"},
	{Name: "multicast-ports", Value: []int{8818}},
	{Name: "multicast-sample-percent", Value: 0.01},
}

var _ = policytest.NewBuilder("layer3-udp-sequence-error").
	WithLabels("layer3", "udp", "multicast").
	WithCLIFlags(multicastSequenceFlags...).
	WithSkip(multicastSkip).
	WithPolicyTemplate(multicastPolicy).
	AddScenario(multicastSequenceScenario).
	RegisterAtInit()

var _ = policytest.NewBuilder("layer3-udp-sequence-error-no-policy").
	WithLabels("layer3", "udp", "multicast").
	WithCLIFlags(append(multicastSequenceFlags,
		policytest.CLIFlag{Name: "enable-udp", Value: true},
		policytest.CLIFlag{Name: "enable-udp-cgroup", Value: true},
		policytest.CLIFlag{Name: "udp-stats-interval", Value: 20 * time.Second},
		policytest.CLIFlag{Name: "udp-idle-socket-timeout", Value: time.Minute},
	)...).
	WithSkip(multicastSkip).
	WithPolicyTemplate(emptyTracingPolicy).
	AddScenario(multicastSequenceScenario).
	RegisterAtInit()

var _ = policytest.NewBuilder("layer3-multicast-sample").
	WithLabels("layer3", "udp", "multicast").
	WithCLIFlags(multicastSampleFlags...).
	WithSkip(multicastSkip).
	WithPolicyTemplate(multicastPolicy).
	AddScenario(multicastSampleScenario).
	RegisterAtInit()

var _ = policytest.NewBuilder("layer3-multicast-sample-no-policy").
	WithLabels("layer3", "udp", "multicast").
	WithCLIFlags(append(multicastSampleFlags,
		policytest.CLIFlag{Name: "enable-udp", Value: true},
		policytest.CLIFlag{Name: "enable-udp-cgroup", Value: true},
		policytest.CLIFlag{Name: "udp-stats-interval", Value: 20 * time.Second},
		policytest.CLIFlag{Name: "udp-idle-socket-timeout", Value: time.Minute},
	)...).
	WithSkip(multicastSkip).
	WithPolicyTemplate(emptyTracingPolicy).
	AddScenario(multicastSampleScenario).
	RegisterAtInit()

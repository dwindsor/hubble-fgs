//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.
//

//go:build sudo_tests

package layer3_test

import (
	"context"
	"os/exec"
	"sync"
	"testing"

	"github.com/cilium/tetragon/api/v1/tetragon"
	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/pkg/jsonchecker"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	"github.com/stretchr/testify/assert"

	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/exec"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3"
	"github.com/isovalent/hubble-fgs/pkg/sensors/utils"
	"github.com/isovalent/hubble-fgs/pkg/testutils/runner"
)

const icmpBasicConfig = `
apiversion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "icmp"
spec:
  parser:
    icmp:
      enable: true
`

const icmpAndUdpBasicConfig = `
apiversion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "icmp"
spec:
  parser:
    udp:
      enable: true
      cgroup: true
    icmp:
      enable: true
`

// NB(kkourt): Function(t *testing.T, ctx context.Context) is the reasonable
// thing to do here even if revive complains.
//
//revive:disable:context-as-argument
func getBasicIcmpObserver(t *testing.T, ctx context.Context, filtered bool) *observer.Observer {
	return getLayer3Observer(t, ctx, icmpBasicConfig, filtered)
}

func getIcmpAndUdpObserver(t *testing.T, ctx context.Context, filtered bool) *observer.Observer {
	return getLayer3Observer(t, ctx, icmpAndUdpBasicConfig, filtered)
}

func TestICMPBasic(t *testing.T) {
	if !utils.CGroupSKBAvailable() {
		t.Skipf("This test requires CGroup/SKB, skipping")
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	obs := getBasicIcmpObserver(t, ctx, false)
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)

	for _, test := range basicICMPTests {
		t.Logf("Running test: %s", test.name)
		if !t.Run(test.name, func(lt *testing.T) {
			test.f(t, lt, &readyWG)
		}) {
			t.Logf("Test %s failed", test.name)
			break
		}
		t.Logf("Test %s was successful", test.name)
	}
}

func TestICMPUDP(t *testing.T) {
	if !utils.CGroupSKBAvailable() {
		t.Skipf("This test requires CGroup/SKB, skipping")
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	oldEnableIcmpTrackingValue := enterpriseOption.Config.EnableIcmpTracking
	enterpriseOption.Config.EnableIcmpTracking = true
	t.Cleanup(func() {
		enterpriseOption.Config.EnableIcmpTracking = oldEnableIcmpTrackingValue
	})

	obs := getIcmpAndUdpObserver(t, ctx, false)
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)

	for _, test := range UDPICMPTests {
		t.Logf("Running test: %s", test.name)
		if !t.Run(test.name, func(lt *testing.T) {
			test.f(t, lt, &readyWG)
		}) {
			t.Logf("Test %s failed", test.name)
			break
		}
		t.Logf("Test %s was successful", test.name)
	}
}

var basicICMPTests = []basicTest{
	{"testPingOutbound4", testPingOutbound4},
	{"testPingInAndOutbound4", testPingInAndOutbound4},
	{"testPingOutbound6", testPingOutbound6},
	{"testPingInAndOutbound6", testPingInAndOutbound6},
}

var UDPICMPTests = []basicTest{
	{"testInboundDestUnreach4", testInboundDestUnreach4},
	{"testInboundDestUnreach6", testInboundDestUnreach6},
}

func testPingOutbound4(gt *testing.T, t *testing.T, readyWG *sync.WaitGroup) {
	cmd := "ping"

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	pingChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(cmd)).
		WithArguments(sm.Full("-c1 127.0.0.1"))

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker("selfExec").
			WithProcess(selfChecker).
			WithParent(ec.NewProcessChecker()),
		ec.NewProcessExecChecker("pingExec").
			WithProcess(pingChecker).
			WithParent(selfChecker),
		ec.NewProcessIcmpChecker("pingEcho").
			WithProcess(pingChecker).
			WithParent(selfChecker).
			WithSourceIp(sm.Full("127.0.0.1")).
			WithDestinationIp(sm.Full("127.0.0.1")).
			WithProtocol(tetragon.SocketProtocol_ICMP).
			WithIcmpType(sm.Full("Echo")).
			WithSequenceNumber(1).
			WithIcmpDataLen(56).
			WithDirection(sm.Full("egress")),
		ec.NewProcessIcmpChecker("pingEchoReply").
			WithProcess(pingChecker).
			WithParent(selfChecker).
			WithSourceIp(sm.Full("127.0.0.1")).
			WithDestinationIp(sm.Full("127.0.0.1")).
			WithProtocol(tetragon.SocketProtocol_ICMP).
			WithIcmpType(sm.Full("Echo Reply")).
			WithSequenceNumber(1).
			WithIcmpDataLen(56).
			WithDirection(sm.Full("ingress")),
	)

	readyWG.Wait()
	cmdServer := exec.Command(cmd, "-c1", "127.0.0.1")
	assert.NoError(t, cmdServer.Run())

	err := jsonchecker.JsonTestCheck(gt, checker)
	assert.NoError(t, err)
}

func TestICMPCLISwitch(t *testing.T) {
	if !utils.CGroupSKBAvailable() {
		t.Skipf("This test requires CGroup/SKB, skipping")
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	oldEnableICMPValue := enterpriseOption.Config.EnableICMP
	enterpriseOption.Config.EnableICMP = true
	oldLayer3CLIEnableValue := enterpriseOption.Config.Layer3CLIEnable
	enterpriseOption.Config.Layer3CLIEnable = true
	t.Cleanup(func() {
		enterpriseOption.Config.EnableICMP = oldEnableICMPValue
		enterpriseOption.Config.Layer3CLIEnable = oldLayer3CLIEnableValue
	})

	cmd := "ping"

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	pingChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(cmd)).
		WithArguments(sm.Full("-c1 127.0.0.1"))

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker("selfExec").
			WithProcess(selfChecker).
			WithParent(ec.NewProcessChecker()),
		ec.NewProcessExecChecker("pingExec").
			WithProcess(pingChecker).
			WithParent(selfChecker),
		ec.NewProcessIcmpChecker("pingEcho").
			WithProcess(pingChecker).
			WithParent(selfChecker).
			WithSourceIp(sm.Full("127.0.0.1")).
			WithDestinationIp(sm.Full("127.0.0.1")).
			WithProtocol(tetragon.SocketProtocol_ICMP).
			WithIcmpType(sm.Full("Echo")).
			WithSequenceNumber(1).
			WithIcmpDataLen(56).
			WithDirection(sm.Full("egress")),
		ec.NewProcessIcmpChecker("pingEchoReply").
			WithProcess(pingChecker).
			WithParent(selfChecker).
			WithSourceIp(sm.Full("127.0.0.1")).
			WithDestinationIp(sm.Full("127.0.0.1")).
			WithProtocol(tetragon.SocketProtocol_ICMP).
			WithIcmpType(sm.Full("Echo Reply")).
			WithSequenceNumber(1).
			WithIcmpDataLen(56).
			WithDirection(sm.Full("ingress")),
	)

	obs := getNoConfigObserver(t, ctx, false)
	layer3.StartLayer3Progs(ctx)
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)

	readyWG.Wait()
	cmdServer := exec.Command(cmd, "-c1", "127.0.0.1")
	assert.NoError(t, cmdServer.Run())

	err := jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func testPingInAndOutbound4(gt *testing.T, t *testing.T, readyWG *sync.WaitGroup) {
	cmd := "ping"

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	pingChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(cmd)).
		WithArguments(sm.Full("-c1 127.0.0.1"))

	kernelChecker := ec.NewProcessChecker().
		WithBinary(sm.Full("<kernel>"))

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker("selfExec").
			WithProcess(selfChecker).
			WithParent(ec.NewProcessChecker()),
		ec.NewProcessExecChecker("pingExec").
			WithProcess(pingChecker).
			WithParent(selfChecker),
		ec.NewProcessIcmpChecker("pingEchoOutbound").
			WithProcess(pingChecker).
			WithParent(selfChecker).
			WithSourceIp(sm.Full("127.0.0.1")).
			WithDestinationIp(sm.Full("127.0.0.1")).
			WithProtocol(tetragon.SocketProtocol_ICMP).
			WithIcmpType(sm.Full("Echo")).
			WithSequenceNumber(1).
			WithIcmpDataLen(56).
			WithDirection(sm.Full("egress")),
		ec.NewProcessIcmpChecker("pingEchoInbound").
			WithProcess(kernelChecker).
			WithSourceIp(sm.Full("127.0.0.1")).
			WithDestinationIp(sm.Full("127.0.0.1")).
			WithProtocol(tetragon.SocketProtocol_ICMP).
			WithIcmpType(sm.Full("Echo")).
			WithSequenceNumber(1).
			WithIcmpDataLen(56).
			WithDirection(sm.Full("ingress")),
		ec.NewProcessIcmpChecker("pingEchoReplyOutbound").
			WithProcess(kernelChecker).
			WithSourceIp(sm.Full("127.0.0.1")).
			WithDestinationIp(sm.Full("127.0.0.1")).
			WithProtocol(tetragon.SocketProtocol_ICMP).
			WithIcmpType(sm.Full("Echo Reply")).
			WithSequenceNumber(1).
			WithIcmpDataLen(56).
			WithDirection(sm.Full("egress")),
		ec.NewProcessIcmpChecker("pingEchoReplyInbound").
			WithProcess(pingChecker).
			WithParent(selfChecker).
			WithSourceIp(sm.Full("127.0.0.1")).
			WithDestinationIp(sm.Full("127.0.0.1")).
			WithProtocol(tetragon.SocketProtocol_ICMP).
			WithIcmpType(sm.Full("Echo Reply")).
			WithSequenceNumber(1).
			WithIcmpDataLen(56).
			WithDirection(sm.Full("ingress")),
	)

	readyWG.Wait()
	cmdServer := exec.Command(cmd, "-c1", "127.0.0.1")
	assert.NoError(t, cmdServer.Run())

	err := jsonchecker.JsonTestCheck(gt, checker)
	assert.NoError(t, err)
}

func testInboundDestUnreach4(gt *testing.T, t *testing.T, readyWG *sync.WaitGroup) {
	cmd := "nc"

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	ncChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(cmd)).
		WithArguments(sm.Full("-u 127.0.0.1 10043"))

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker("selfExec").
			WithProcess(selfChecker).
			WithParent(ec.NewProcessChecker()),
		ec.NewProcessExecChecker("ncExec").
			WithProcess(ncChecker).
			WithParent(selfChecker),
		ec.NewProcessConnectChecker("ncConnect").
			WithProcess(ncChecker).
			WithParent(selfChecker).
			WithSourceIp(sm.Full("127.0.0.1")).
			WithDestinationIp(sm.Full("127.0.0.1")).
			WithProtocol(tetragon.SocketProtocol_UDP).
			WithDestinationPort(10043),
		ec.NewProcessIcmpChecker("destUnreach").
			WithProcess(ncChecker).
			WithParent(selfChecker).
			WithSourceIp(sm.Full("127.0.0.1")).
			WithDestinationIp(sm.Full("127.0.0.1")).
			WithProtocol(tetragon.SocketProtocol_ICMP).
			WithIcmpType(sm.Full("Destination Unreachable")).
			WithIcmpCode(sm.Full("port unreachable")).
			WithIcmpIpProtocol(tetragon.SocketProtocol_UDP).
			WithIcmpIpPort(10043).
			WithDirection(sm.Full("ingress")),
		ec.NewProcessExitChecker("ncExit").
			WithProcess(ncChecker).
			WithParent(selfChecker),
	)

	readyWG.Wait()
	cmdClient := exec.Command(cmd, "-u", "127.0.0.1", "10043")
	stdin, err := cmdClient.StdinPipe()
	assert.NoError(t, err)
	assert.NoError(t, cmdClient.Start())
	_, err = stdin.Write([]byte("hello"))
	assert.NoError(t, err)
	assert.NoError(t, cmdClient.Wait())

	err = jsonchecker.JsonTestCheck(gt, checker)
	assert.NoError(t, err)
}

func testPingOutbound6(gt *testing.T, t *testing.T, readyWG *sync.WaitGroup) {
	cmd := "ping"

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	pingChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(cmd)).
		WithArguments(sm.Full("-6c1 ::1"))

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker("selfExec").
			WithProcess(selfChecker).
			WithParent(ec.NewProcessChecker()),
		ec.NewProcessExecChecker("pingExec").
			WithProcess(pingChecker).
			WithParent(selfChecker),
		ec.NewProcessIcmpChecker("pingEcho").
			WithProcess(pingChecker).
			WithParent(selfChecker).
			WithSourceIp(sm.Full("::1")).
			WithDestinationIp(sm.Full("::1")).
			WithProtocol(tetragon.SocketProtocol_ICMP).
			WithIcmpType(sm.Full("Echo Request")).
			WithSequenceNumber(1).
			WithIcmpDataLen(56).
			WithDirection(sm.Full("egress")),
		ec.NewProcessIcmpChecker("pingEchoReply").
			WithProcess(pingChecker).
			WithParent(selfChecker).
			WithSourceIp(sm.Full("::1")).
			WithDestinationIp(sm.Full("::1")).
			WithProtocol(tetragon.SocketProtocol_ICMP).
			WithIcmpType(sm.Full("Echo Reply")).
			WithSequenceNumber(1).
			WithIcmpDataLen(56).
			WithDirection(sm.Full("ingress")),
	)

	readyWG.Wait()
	cmdServer := exec.Command(cmd, "-6c1", "::1")
	assert.NoError(t, cmdServer.Run())

	err := jsonchecker.JsonTestCheck(gt, checker)
	assert.NoError(t, err)
}

func testPingInAndOutbound6(gt *testing.T, t *testing.T, readyWG *sync.WaitGroup) {
	cmd := "ping"

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	pingChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(cmd)).
		WithArguments(sm.Full("-6c1 ::1"))

	kernelChecker := ec.NewProcessChecker().
		WithBinary(sm.Full("<kernel>"))

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker("selfExec").
			WithProcess(selfChecker).
			WithParent(ec.NewProcessChecker()),
		ec.NewProcessExecChecker("pingExec").
			WithProcess(pingChecker).
			WithParent(selfChecker),
		ec.NewProcessIcmpChecker("pingEchoOutbound").
			WithProcess(pingChecker).
			WithParent(selfChecker).
			WithSourceIp(sm.Full("::1")).
			WithDestinationIp(sm.Full("::1")).
			WithProtocol(tetragon.SocketProtocol_ICMP).
			WithIcmpType(sm.Full("Echo Request")).
			WithSequenceNumber(1).
			WithIcmpDataLen(56).
			WithDirection(sm.Full("egress")),
		ec.NewProcessIcmpChecker("pingEchoInbound").
			WithProcess(kernelChecker).
			WithSourceIp(sm.Full("::1")).
			WithDestinationIp(sm.Full("::1")).
			WithProtocol(tetragon.SocketProtocol_ICMP).
			WithIcmpType(sm.Full("Echo Request")).
			WithSequenceNumber(1).
			WithIcmpDataLen(56).
			WithDirection(sm.Full("ingress")),
		ec.NewProcessIcmpChecker("pingEchoReplyOutbound").
			WithProcess(kernelChecker).
			WithSourceIp(sm.Full("::1")).
			WithDestinationIp(sm.Full("::1")).
			WithProtocol(tetragon.SocketProtocol_ICMP).
			WithIcmpType(sm.Full("Echo Reply")).
			WithSequenceNumber(1).
			WithIcmpDataLen(56).
			WithDirection(sm.Full("egress")),
		ec.NewProcessIcmpChecker("pingEchoReplyInbound").
			WithProcess(pingChecker).
			WithParent(selfChecker).
			WithSourceIp(sm.Full("::1")).
			WithDestinationIp(sm.Full("::1")).
			WithProtocol(tetragon.SocketProtocol_ICMP).
			WithIcmpType(sm.Full("Echo Reply")).
			WithSequenceNumber(1).
			WithIcmpDataLen(56).
			WithDirection(sm.Full("ingress")),
	)

	readyWG.Wait()
	cmdServer := exec.Command(cmd, "-6c1", "::1")
	assert.NoError(t, cmdServer.Run())

	err := jsonchecker.JsonTestCheck(gt, checker)
	assert.NoError(t, err)
}

func testInboundDestUnreach6(gt *testing.T, t *testing.T, readyWG *sync.WaitGroup) {
	cmd := "nc"

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	ncChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(cmd)).
		WithArguments(sm.Full("-6u ::1 10043"))

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker("selfExec").
			WithProcess(selfChecker).
			WithParent(ec.NewProcessChecker()),
		ec.NewProcessExecChecker("ncExec").
			WithProcess(ncChecker).
			WithParent(selfChecker),
		ec.NewProcessConnectChecker("ncConnect").
			WithProcess(ncChecker).
			WithParent(selfChecker).
			WithSourceIp(sm.Full("::1")).
			WithDestinationIp(sm.Full("::1")).
			WithProtocol(tetragon.SocketProtocol_UDP).
			WithDestinationPort(10043),
		ec.NewProcessIcmpChecker("destUnreach").
			WithProcess(ncChecker).
			WithParent(selfChecker).
			WithSourceIp(sm.Full("::1")).
			WithDestinationIp(sm.Full("::1")).
			WithProtocol(tetragon.SocketProtocol_ICMP).
			WithIcmpType(sm.Full("Destination unreachable")).
			WithIcmpCode(sm.Full("port unreachable")).
			WithIcmpIpProtocol(tetragon.SocketProtocol_UDP).
			WithIcmpIpPort(10043).
			WithDirection(sm.Full("ingress")),
		ec.NewProcessExitChecker("ncExit").
			WithProcess(ncChecker).
			WithParent(selfChecker),
	)

	readyWG.Wait()
	cmdClient := exec.Command(cmd, "-6u", "::1", "10043")
	stdin, err := cmdClient.StdinPipe()
	assert.NoError(t, err)
	assert.NoError(t, cmdClient.Start())
	_, err = stdin.Write([]byte("hello"))
	assert.NoError(t, err)
	assert.NoError(t, cmdClient.Wait())

	err = jsonchecker.JsonTestCheck(gt, checker)
	assert.NoError(t, err)
}

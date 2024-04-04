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

package layer3

import (
	"context"
	"os/exec"
	"sync"
	"testing"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/jsonchecker"
	"github.com/cilium/tetragon/pkg/kernels"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	"github.com/stretchr/testify/assert"

	enterpriseoth "github.com/isovalent/hubble-fgs/pkg/observer/observertesthelper"
	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"
	"github.com/isovalent/hubble-fgs/pkg/sensors/base"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/exec"
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
func getIcmpObserver(t *testing.T, ctx context.Context, config string, filtered bool) *observer.Observer {
	if err := observertesthelper.WriteConfigFile(testConfigFile, config); err != nil {
		t.Fatalf("WriteFile(%s): err %s", testConfigFile, err)
	}

	base := base.GetInitialSensor()
	var obs *observer.Observer
	var err error
	if filtered {
		obs, err = enterpriseoth.GetDefaultObserverWithBase(t, ctx, base, testConfigFile, runner.Conf().TetragonLib, observertesthelper.WithMyPid())
	} else {
		obs, err = enterpriseoth.GetDefaultObserverWithBase(t, ctx, base, testConfigFile, runner.Conf().TetragonLib)
	}
	if err != nil {
		t.Fatalf("GetDefaultObserver error: %s", err)
	}
	return obs
}

func getBasicIcmpObserver(t *testing.T, ctx context.Context, filtered bool) *observer.Observer {
	return getIcmpObserver(t, ctx, icmpBasicConfig, filtered)
}

func getIcmpAndUdpObserver(t *testing.T, ctx context.Context, filtered bool) *observer.Observer {
	return getIcmpObserver(t, ctx, icmpAndUdpBasicConfig, filtered)
}

func TestPingOutbound4(t *testing.T) {
	if v := "5.4.0"; !kernels.MinKernelVersion(v) {
		t.Skipf("Minimum kernel version (%v) not met, skipping", v)
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

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

	obs := getBasicIcmpObserver(t, ctx, true)
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)

	readyWG.Wait()
	cmdServer := exec.Command(cmd, "-c1", "127.0.0.1")
	assert.NoError(t, cmdServer.Start())
	time.Sleep(1000 * time.Millisecond)

	err := jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestPingInAndOutbound4(t *testing.T) {
	if v := "5.4.0"; !kernels.MinKernelVersion(v) {
		t.Skipf("Minimum kernel version (%v) not met, skipping", v)
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

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

	obs := getBasicIcmpObserver(t, ctx, false)
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)

	readyWG.Wait()
	cmdServer := exec.Command(cmd, "-c1", "127.0.0.1")
	assert.NoError(t, cmdServer.Start())
	time.Sleep(1000 * time.Millisecond)

	err := jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestInboundDestUnreach4(t *testing.T) {
	if v := "5.4.0"; !kernels.MinKernelVersion(v) {
		t.Skipf("Minimum kernel version (%v) not met, skipping", v)
	}

	bpf.CheckOrMountCgroup2()

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	oldEnableIcmpTrackingValue := enterpriseOption.Config.EnableIcmpTracking
	enterpriseOption.Config.EnableIcmpTracking = true
	t.Cleanup(func() {
		enterpriseOption.Config.EnableIcmpTracking = oldEnableIcmpTrackingValue
	})

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

	obs := getIcmpAndUdpObserver(t, ctx, false)
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)

	readyWG.Wait()
	cmdClient := exec.Command(cmd, "-u", "127.0.0.1", "10043")
	stdin, err := cmdClient.StdinPipe()
	assert.NoError(t, err)
	assert.NoError(t, cmdClient.Start())
	time.Sleep(100 * time.Millisecond)
	_, err = stdin.Write([]byte("hello"))
	assert.NoError(t, err)
	time.Sleep(1000 * time.Millisecond)

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestPingOutbound6(t *testing.T) {
	if v := "5.4.0"; !kernels.MinKernelVersion(v) {
		t.Skipf("Minimum kernel version (%v) not met, skipping", v)
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

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

	obs := getBasicIcmpObserver(t, ctx, true)
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)

	readyWG.Wait()
	cmdServer := exec.Command(cmd, "-6c1", "::1")
	assert.NoError(t, cmdServer.Start())
	time.Sleep(1000 * time.Millisecond)

	err := jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestPingInAndOutbound6(t *testing.T) {
	if v := "5.4.0"; !kernels.MinKernelVersion(v) {
		t.Skipf("Minimum kernel version (%v) not met, skipping", v)
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

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

	obs := getBasicIcmpObserver(t, ctx, false)
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)

	readyWG.Wait()
	cmdServer := exec.Command(cmd, "-6c1", "::1")
	assert.NoError(t, cmdServer.Start())
	time.Sleep(1000 * time.Millisecond)

	err := jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestInboundDestUnreach6(t *testing.T) {
	if v := "5.4.0"; !kernels.MinKernelVersion(v) {
		t.Skipf("Minimum kernel version (%v) not met, skipping", v)
	}

	bpf.CheckOrMountCgroup2()

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	oldEnableIcmpTrackingValue := enterpriseOption.Config.EnableIcmpTracking
	enterpriseOption.Config.EnableIcmpTracking = true
	t.Cleanup(func() {
		enterpriseOption.Config.EnableIcmpTracking = oldEnableIcmpTrackingValue
	})

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

	obs := getIcmpAndUdpObserver(t, ctx, false)
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)

	readyWG.Wait()
	cmdClient := exec.Command(cmd, "-6u", "::1", "10043")
	stdin, err := cmdClient.StdinPipe()
	assert.NoError(t, err)
	assert.NoError(t, cmdClient.Start())
	time.Sleep(100 * time.Millisecond)
	_, err = stdin.Write([]byte("hello"))
	assert.NoError(t, err)
	time.Sleep(1000 * time.Millisecond)

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

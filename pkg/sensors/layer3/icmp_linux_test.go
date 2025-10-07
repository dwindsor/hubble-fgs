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
	"encoding/binary"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/jsonchecker"
	"github.com/cilium/tetragon/pkg/logger"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/sensors/config/confmap"
	testsensor "github.com/cilium/tetragon/pkg/sensors/test"
	"github.com/cilium/tetragon/pkg/testutils"
	tuo "github.com/cilium/tetragon/pkg/testutils/observer"
	"github.com/cilium/tetragon/pkg/testutils/perfring"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"

	"github.com/cilium/tetragon/api/v1/tetragon"
	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	"github.com/isovalent/hubble-fgs/pkg/constants"
	execapi "github.com/isovalent/hubble-fgs/pkg/grpc/exec"
	"github.com/isovalent/hubble-fgs/pkg/grpc/icmp"
	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"
	"github.com/isovalent/hubble-fgs/pkg/sensors/base"
	"github.com/isovalent/hubble-fgs/pkg/sensors/exec/procevents"
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

type ICMPBasic struct {
	suite.Suite
	doneWG, readyWG sync.WaitGroup
	ctx             context.Context
	cancel          context.CancelFunc
}

func TestICMPBasic(t *testing.T) {
	if !utils.CGroupSKBAvailable() {
		t.Skipf("This test requires CGroup/SKB, skipping")
	}
	suite.Run(t, new(ICMPBasic))
}

func (suite *ICMPBasic) SetupSuite() {
	suite.ctx, suite.cancel = context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	obs := getBasicIcmpObserver(suite.T(), suite.ctx, false)
	observertesthelper.LoopEvents(suite.ctx, suite.T(), &suite.doneWG, &suite.readyWG, obs)
}

func (suite *ICMPBasic) HandleStats(_ string, stats *suite.SuiteInformation) {
	if stats.Passed() {
		testutils.DoneWithExportFile(suite.T())
	}
}

func (suite *ICMPBasic) TearDownSuite() {
	suite.cancel()
}

type ICMPUDP struct {
	suite.Suite
	doneWG, readyWG            sync.WaitGroup
	ctx                        context.Context
	cancel                     context.CancelFunc
	oldEnableIcmpTrackingValue bool
}

func TestICMPUDP(t *testing.T) {
	if !utils.CGroupSKBAvailable() {
		t.Skipf("This test requires CGroup/SKB, skipping")
	}
	suite.Run(t, new(ICMPUDP))
}

func (suite *ICMPUDP) SetupSuite() {
	suite.ctx, suite.cancel = context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)

	suite.oldEnableIcmpTrackingValue = enterpriseOption.Config.EnableIcmpTracking
	enterpriseOption.Config.EnableIcmpTracking = true

	obs := getIcmpAndUdpObserver(suite.T(), suite.ctx, false)
	observertesthelper.LoopEvents(suite.ctx, suite.T(), &suite.doneWG, &suite.readyWG, obs)
}

func (suite *ICMPUDP) HandleStats(_ string, stats *suite.SuiteInformation) {
	if stats.Passed() {
		testutils.DoneWithExportFile(suite.T())
	}
}

func (suite *ICMPUDP) TearDownSuite() {
	enterpriseOption.Config.EnableIcmpTracking = suite.oldEnableIcmpTrackingValue
	suite.cancel()
}

func (suite *ICMPBasic) TestPingOutbound4() {
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

	suite.readyWG.Wait()
	cmdServer := exec.Command(cmd, "-c1", "127.0.0.1")
	assert.NoError(suite.T(), cmdServer.Run())

	err := jsonchecker.JsonTestCheckExpectWithKeep(suite.T(), checker, false, true)
	assert.NoError(suite.T(), err)
}

func parseArgs(a string) string {
	b := []byte(a)
	for i, c := range b {
		if c == '\x00' {
			b[i] = ' '
		}
	}
	return string(b)
}

func TestICMPCLISwitchPerfRing(t *testing.T) {
	if !utils.CGroupSKBAvailable() {
		t.Skipf("This test requires CGroup/SKB, skipping")
	}

	testutils.CaptureLog(t, logger.GetLogger())
	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	oldEnableICMPValue := enterpriseOption.Config.EnableICMP
	enterpriseOption.Config.EnableICMP = true
	oldLayer3CLIEnableValue := enterpriseOption.Config.Layer3CLIEnable
	enterpriseOption.Config.Layer3CLIEnable = true
	t.Cleanup(func() {
		enterpriseOption.Config.EnableICMP = oldEnableICMPValue
		enterpriseOption.Config.Layer3CLIEnable = oldLayer3CLIEnableValue
	})

	if err := observer.InitDataCache(1024); err != nil {
		t.Fatalf("observertesthelper.InitDataCache: %s", err)
	}

	option.Config.HubbleLib = tus.Conf().TetragonLib
	option.Config.BpfDir = bpf.MapPrefixPath()
	option.Config.UsePerfRingBuffer = true
	confmap.UpdateTgRuntimeConf(bpf.MapPrefixPath(), os.Getpid())
	tus.LoadSensor(t, base.GetInitialSensorTest(t))

	if err := procevents.GetRunningProcs(); err != nil {
		t.Fatalf("procevents.GetRunningProcs: %s", err)
	}

	tus.LoadSensor(t, testsensor.GetTestSensor())
	sm := tuo.GetTestSensorManager(t)
	err := layer3.StartLayer3Progs(ctx, sm.Manager)
	require.NoError(t, err)

	t.Cleanup(func() {
		sm.Manager.DeleteTracingPolicy(ctx, "__base_layer3__", "")
		os.RemoveAll(option.Config.BpfDir)
	})

	cmd := "ping"
	pingPid := -1

	ops := func() {
		cmdServer := exec.Command(cmd, "-c1", "127.0.0.1")
		require.NoError(t, cmdServer.Start())
		pingPid = cmdServer.Process.Pid
		require.NoError(t, cmdServer.Wait())
	}

	events := perfring.RunTestEvents(t, ctx, ops)

	detectExec := false
	detectPing := false
	detectPingReply := false

	for _, event := range events {
		t.Logf("event = '%#v'", event)
		switch e := event.(type) {
		case *execapi.MsgExecveEventUnix:
			if strings.HasSuffix(e.Unix.Process.Filename, cmd) && strings.HasPrefix(parseArgs(e.Unix.Process.Args), "-c1 127.0.0.1") &&
				e.Unix.Process.PID == uint32(pingPid) && e.Unix.Msg.Parent.Pid == uint32(os.Getpid()) {
				t.Logf("Matched pingExec")
				detectExec = true
			}
		case *icmp.MsgICMPEventUnix:
			saddr := networkapi.GetIP(e.Msg.Tuple.SAddr, e.Msg.Common.Op, e.Msg.Tuple.IPv6 == 1)
			daddr := networkapi.GetIP(e.Msg.Tuple.DAddr, e.Msg.Common.Op, e.Msg.Tuple.IPv6 == 1)
			localhost := net.ParseIP("127.0.0.1")
			seqNum := binary.BigEndian.Uint16(e.Msg.IcmpData.IcmpData[2:4])

			if e.Msg.ProcessKey.Pid == uint32(pingPid) && saddr.Equal(localhost) && daddr.Equal(localhost) &&
				e.Msg.Tuple.Proto == constants.IPPROTO_ICMP && e.Msg.IcmpData.IcmpLen == 56 && seqNum == 1 {
				if e.Msg.IcmpData.IcmpType == 8 && e.Msg.Tuple.Send == 1 {
					detectPing = true
					t.Logf("Matched ping")
					continue
				}
				if e.Msg.IcmpData.IcmpType == 0 && e.Msg.Tuple.Send == 0 {
					detectPingReply = true
					t.Logf("Matched pingreply")
					continue
				}
			}
		}
	}

	assert.True(t, detectExec)
	assert.True(t, detectPing)
	assert.True(t, detectPingReply)
}

func TestICMPCLISwitchTetragon(t *testing.T) {
	t.Skipf("This test is unreliable in CI")
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
	layer3.StartLayer3Progs(ctx, nil)
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)

	readyWG.Wait()
	cmdServer := exec.Command(cmd, "-c1", "127.0.0.1")
	assert.NoError(t, cmdServer.Run())

	err := jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func (suite *ICMPBasic) TestPingInAndOutbound4() {
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

	suite.readyWG.Wait()
	cmdServer := exec.Command(cmd, "-c1", "127.0.0.1")
	assert.NoError(suite.T(), cmdServer.Run())

	err := jsonchecker.JsonTestCheckExpectWithKeep(suite.T(), checker, false, true)
	assert.NoError(suite.T(), err)
}

func (suite *ICMPUDP) TestInboundDestUnreach4() {
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

	suite.readyWG.Wait()
	cmdClient := exec.Command(cmd, "-u", "127.0.0.1", "10043")
	stdin, err := cmdClient.StdinPipe()
	assert.NoError(suite.T(), err)
	assert.NoError(suite.T(), cmdClient.Start())
	_, err = stdin.Write([]byte("hello"))
	assert.NoError(suite.T(), err)
	assert.NoError(suite.T(), cmdClient.Wait())

	err = jsonchecker.JsonTestCheck(suite.T(), checker)
	assert.NoError(suite.T(), err)
}

func (suite *ICMPBasic) TestPingOutbound6() {
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

	suite.readyWG.Wait()
	cmdServer := exec.Command(cmd, "-6c1", "::1")
	assert.NoError(suite.T(), cmdServer.Run())

	err := jsonchecker.JsonTestCheckExpectWithKeep(suite.T(), checker, false, true)
	assert.NoError(suite.T(), err)
}

func (suite *ICMPBasic) TestPingInAndOutbound6() {
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

	suite.readyWG.Wait()
	cmdServer := exec.Command(cmd, "-6c1", "::1")
	assert.NoError(suite.T(), cmdServer.Run())

	err := jsonchecker.JsonTestCheckExpectWithKeep(suite.T(), checker, false, true)
	assert.NoError(suite.T(), err)
}

func (suite *ICMPUDP) TestInboundDestUnreach6() {
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

	suite.readyWG.Wait()
	cmdClient := exec.Command(cmd, "-6u", "::1", "10043")
	stdin, err := cmdClient.StdinPipe()
	assert.NoError(suite.T(), err)
	assert.NoError(suite.T(), cmdClient.Start())
	_, err = stdin.Write([]byte("hello"))
	assert.NoError(suite.T(), err)
	assert.NoError(suite.T(), cmdClient.Wait())

	err = jsonchecker.JsonTestCheck(suite.T(), checker)
	assert.NoError(suite.T(), err)
}

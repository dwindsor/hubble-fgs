// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

//go:build sudo_tests

package layer3_test

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/jsonchecker"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/matchers/durationmatcher"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/sensors/config/confmap"
	"github.com/cilium/tetragon/pkg/tracingpolicy"

	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3"
	"github.com/isovalent/hubble-fgs/pkg/sensors/utils"
	cli "github.com/isovalent/hubble-fgs/pkg/testutils/cliswitches"
	"github.com/isovalent/hubble-fgs/pkg/testutils/runner"

	"github.com/stretchr/testify/require"
)

type l3TestDest struct {
	ip   string
	port int
}

const (
	numRTPSeqPackets    = 12
	numRTPSamplePackets = 5
)

var (
	// The following values come from sample data. The second should hash to a value under our .01 threshold.
	// These are to be stored in MSB in the packets in two parts: the upper 4 bytes should be written to the start of the packet;
	// and the lower 4 bytes to packet offset 8.
	RTPSampleData      = []uint64{0x80005779f5d6285e, 0x8000577af5d6285e, 0x8000577bf5d6285e, 0x8000577cf5d6285e, 0x8000577df5d6285e}
	udpMulticastRTPIP4 = map[multicastTest]l3TestDest{
		multicastTestRTPConnID:    {"225.2.2.1", 8810},
		multicastTestRTPConnIDCLI: {"225.2.2.2", 8812},
		multicastTestRTPSeq:       {"225.2.2.3", 8814},
		multicastTestRTPSeqCLI:    {"225.2.2.4", 8816},
		multicastTestRTPSample:    {"225.2.2.5", 8818},
		multicastTestRTPSampleCLI: {"225.2.2.6", 8820},
	}
)

func storeMSB(buf []byte, index uint, size uint, value uint64) {
	if size == 0 {
		return
	}
	for i := range size {
		buf[index+i] = byte((value >> ((size - i - 1) * 8)) & 0xff)
	}
}

func getDefaultInterfaceAddress() (string, error) {
	defaultRoute, err := exec.Command("bash", "-c", "ip r | grep default").Output()
	if err != nil {
		return "", err
	}
	defaultRouteFields := strings.Fields(string(defaultRoute))
	ifAddr := defaultRouteFields[8]
	return ifAddr, nil
}

func htonll(v uint64) uint64 {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, v)
	return binary.LittleEndian.Uint64(b)
}

func testUdpMulticastRTPConnID(t *testing.T, CLISwitches bool) {
	if !utils.CGroupSKBAvailable() {
		t.Skipf("This test requires CGroup/SKB, skipping")
	}

	if !kernels.MinKernelVersion("5.15.0") {
		t.Skip("Test requires kernel >=5.15 as it requires loopback multicast")
	}

	rtpconnParam := "rtpconn"
	dest, ok := udpMulticastRTPIP4[multicastTestRTPConnID]
	if CLISwitches {
		rtpconnParam = "rtpconncli"
		dest, ok = udpMulticastRTPIP4[multicastTestRTPConnIDCLI]
	}
	require.True(t, ok)

	switches := []cli.SwitchSettings{
		{KeyPtr: &enterpriseOption.Config.EnableNetworkEvents, Value: true},
		{KeyPtr: &enterpriseOption.Config.MulticastAppID, Value: enterpriseOption.MulticastAppRTP},
		{KeyPtr: &enterpriseOption.Config.MulticastPorts, Value: []int{dest.port}},
		{KeyPtr: &enterpriseOption.Config.MulticastSeqCheck, Value: true},
		{KeyPtr: &option.Config.Debug, Value: true},
		{KeyPtr: &option.Config.Verbosity, Value: 4},
	}
	if CLISwitches {
		switches = append(switches, []cli.SwitchSettings{
			{KeyPtr: &enterpriseOption.Config.Layer3CLIEnable, Value: true},
			{KeyPtr: &enterpriseOption.Config.EnableUDP, Value: true},
			{KeyPtr: &enterpriseOption.Config.EnableUDPCGroup, Value: true},
			{KeyPtr: &enterpriseOption.Config.UDPStatsInterval, Value: 20 * time.Second},
			{KeyPtr: &enterpriseOption.Config.UDPIdleSocketTimeout, Value: 60 * time.Second},
		}...)
	}
	require.NoError(t, cli.SetSwitches(t, switches))

	server := getSocatCommand(t, "socat")
	ifAddr, err := getDefaultInterfaceAddress()
	require.NoError(t, err)

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	socatArg1 := "-"
	socatArg2 := fmt.Sprintf("UDP4-RECVFROM:%d,ip-add-membership=%s:%s,fork", dest.port, dest.ip, ifAddr)
	socatArgs := fmt.Sprintf("%s %s", socatArg1, socatArg2)
	socatSrvChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(server)).
		WithArguments(sm.Full(socatArgs))

	clientProcess := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary)).
		WithArguments(sm.Full(fmt.Sprintf("-udpMulticastClient %s", rtpconnParam)))

	clientStatsChecker := ec.NewProcessSockStatsChecker("clientStats").
		WithProcess(clientProcess).
		WithParent(selfChecker).
		WithSocket(ec.NewSockInfoChecker().
			WithProtocol(tetragon.SocketProtocol_UDP).
			WithDestinationIp(sm.Full(dest.ip)).
			WithDestinationPort(uint32(dest.port))).
		WithConnectionId(42)

	serverStatsChecker := ec.NewProcessSockStatsChecker("serverStats").
		WithProcess(socatSrvChecker).
		WithParent(selfChecker).
		WithSocket(ec.NewSockInfoChecker().
			WithProtocol(tetragon.SocketProtocol_UDP).
			WithSourceIp(sm.Full(dest.ip)).
			WithSourcePort(uint32(dest.port))).
		WithConnectionId(42)

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker("selfExec").
			WithProcess(selfChecker).
			WithParent(ec.NewProcessChecker()),
		ec.NewProcessExecChecker("serverExec").
			WithProcess(socatSrvChecker).
			WithParent(selfChecker),
		ec.NewProcessExecChecker("clientExec").
			WithProcess(clientProcess).
			WithParent(selfChecker),
		ec.NewProcessConnectChecker("serverConnect").
			WithProcess(socatSrvChecker).
			WithParent(selfChecker).
			WithSourceIp(sm.Full(dest.ip)).
			WithSourcePort(uint32(dest.port)).
			WithProtocol(tetragon.SocketProtocol_UDP).
			WithConnectionId(42),
		ec.NewProcessConnectChecker("clientConnect").
			WithProcess(clientProcess).
			WithParent(selfChecker).
			WithDestinationIp(sm.Full(dest.ip)).
			WithDestinationPort(uint32(dest.port)).
			WithProtocol(tetragon.SocketProtocol_UDP).
			WithConnectionId(42),
		clientStatsChecker,
		serverStatsChecker,
		ec.NewProcessCloseChecker("serverClose").
			WithProcess(socatSrvChecker).
			WithParent(selfChecker).
			WithSourceIp(sm.Full(dest.ip)).
			WithSourcePort(uint32(dest.port)).
			WithProtocol(tetragon.SocketProtocol_UDP).
			WithConnectionId(42),
		ec.NewProcessCloseChecker("clientClose").
			WithProcess(clientProcess).
			WithParent(selfChecker).
			WithDestinationIp(sm.Full(dest.ip)).
			WithDestinationPort(uint32(dest.port)).
			WithProtocol(tetragon.SocketProtocol_UDP).
			WithConnectionId(42),
	)

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	obs := getNoConfigObserver(t, ctx, true)
	require.NoError(t, layer3.StartLayer3Progs(ctx, nil))
	if !CLISwitches {
		tp, err := tracingpolicy.FromYAML(udpBasicConfig)
		require.NoError(t, err)
		err = observer.GetSensorManager().AddTracingPolicy(ctx, tp)
		require.NoError(t, err)
	}

	option.Config.UsePerfRingBuffer = true
	confmap.UpdateTgRuntimeConf(bpf.MapPrefixPath(), os.Getpid())
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	cmdServer := exec.Command(server, socatArg1, socatArg2)
	serverStdout, err := cmdServer.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, cmdServer.Start())
	err = waitForSocketToListen(t, net.ParseIP("0.0.0.0"), uint16(dest.port), syscall.IPPROTO_UDP, syscall.AF_INET)
	require.NoError(t, err)

	clientCmd := exec.Command(os.Args[0], "-udpMulticastClient", rtpconnParam)
	clientCmd.Stdout = os.Stderr
	clientCmd.Stderr = os.Stderr
	err = clientCmd.Run()
	require.NoError(t, err, "cannot start client")

	// Wait for some data to arrive.
	serverData := make([]byte, 16)
	numBytesRead := 0
	for numBytesRead == 0 {
		numBytesRead, err = serverStdout.Read(serverData)
		require.NoError(t, err, "cannot read from server stdout")
	}

	killAndWaitCommand(t, cmdServer)

	err = jsonchecker.JsonTestCheck(t, checker)
	require.NoError(t, err)
}

func TestUdpMulticastRTPConnID(t *testing.T) {
	testUdpMulticastRTPConnID(t, false)
}

func TestUdpMulticastRTPConnIDCLI(t *testing.T) {
	testUdpMulticastRTPConnID(t, true)
}

func testUdpMulticastRTPSeqCheck(t *testing.T, CLISwitches bool) {
	if !utils.CGroupSKBAvailable() {
		t.Skipf("This test requires CGroup/SKB, skipping")
	}

	if !kernels.MinKernelVersion("6.12") {
		t.Skip("Test requires kernel >=6.12 as it requires multicast sequence checking")
	}

	rtpseqParam := "rtpseq"
	dest, ok := udpMulticastRTPIP4[multicastTestRTPSeq]
	if CLISwitches {
		rtpseqParam = "rtpseqcli"
		dest, ok = udpMulticastRTPIP4[multicastTestRTPSeqCLI]
	}
	require.True(t, ok)

	switches := []cli.SwitchSettings{
		{KeyPtr: &enterpriseOption.Config.EnableNetworkEvents, Value: true},
		{KeyPtr: &enterpriseOption.Config.MulticastAppID, Value: enterpriseOption.MulticastAppRTP},
		{KeyPtr: &enterpriseOption.Config.MulticastPorts, Value: []int{dest.port}},
		{KeyPtr: &enterpriseOption.Config.MulticastSeqCheck, Value: true},
	}
	if CLISwitches {
		switches = append(switches, []cli.SwitchSettings{
			{KeyPtr: &enterpriseOption.Config.Layer3CLIEnable, Value: true},
			{KeyPtr: &enterpriseOption.Config.EnableUDP, Value: true},
			{KeyPtr: &enterpriseOption.Config.EnableUDPCGroup, Value: true},
			{KeyPtr: &enterpriseOption.Config.UDPStatsInterval, Value: 20 * time.Second},
			{KeyPtr: &enterpriseOption.Config.UDPIdleSocketTimeout, Value: 60 * time.Second},
		}...)
	}
	require.NoError(t, cli.SetSwitches(t, switches))

	server := getSocatCommand(t, "socat")
	ifAddr, err := getDefaultInterfaceAddress()
	require.NoError(t, err)

	socatArg1 := "-"
	socatArg2 := fmt.Sprintf("UDP4-RECVFROM:%d,ip-add-membership=%s:%s,fork", dest.port, dest.ip, ifAddr)
	socatArgs := fmt.Sprintf("%s %s", socatArg1, socatArg2)
	socatSrvChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(server)).
		WithArguments(sm.Full(socatArgs))

	clientProcess := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary)).
		WithArguments(sm.Full(fmt.Sprintf("-udpMulticastClient %s", rtpseqParam)))

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker("clientExec").
			WithProcess(clientProcess),
		ec.NewProcessExecChecker("serverExec").
			WithProcess(socatSrvChecker),
		ec.NewProcessUdpSeqCheckErrorChecker("lineId5Seq3Got4").
			WithProcess(socatSrvChecker).
			WithApplicationId(2).
			WithAppSpecificId(45).
			WithSocket(ec.NewSockInfoChecker().WithSourcePort(uint32(dest.port))).
			WithSeqNumExpected(3).
			WithSeqNumReceived(4),
		ec.NewProcessUdpSeqCheckErrorChecker("lineId6Seq4Got5").
			WithProcess(socatSrvChecker).
			WithApplicationId(2).
			WithAppSpecificId(46).
			WithSocket(ec.NewSockInfoChecker().WithSourcePort(uint32(dest.port))).
			WithSeqNumExpected(4).
			WithSeqNumReceived(5),
		ec.NewProcessCloseChecker("serverClose").
			WithProcess(socatSrvChecker).
			WithDuration(durationmatcher.Between(&durationmatcher.Duration{Duration: time.Duration(0 * time.Second)},
				&durationmatcher.Duration{Duration: time.Duration(20 * time.Second)})),
		ec.NewProcessExitChecker("serverExit").
			WithProcess(socatSrvChecker),
	)

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	obs := getNoConfigObserver(t, ctx, true)
	require.NoError(t, layer3.StartLayer3Progs(ctx, nil))
	if !CLISwitches {
		tp, err := tracingpolicy.FromYAML(udpBasicConfig)
		require.NoError(t, err)
		err = observer.GetSensorManager().AddTracingPolicy(ctx, tp)
		require.NoError(t, err)
	}

	option.Config.UsePerfRingBuffer = true
	confmap.UpdateTgRuntimeConf(bpf.MapPrefixPath(), os.Getpid())
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	cmdServer := exec.Command(server, socatArg1, socatArg2)
	serverStdout, err := cmdServer.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, cmdServer.Start())
	err = waitForSocketToListen(t, net.ParseIP("0.0.0.0"), uint16(dest.port), syscall.IPPROTO_UDP, syscall.AF_INET)
	require.NoError(t, err)

	clientCmd := exec.Command(os.Args[0], "-udpMulticastClient", rtpseqParam)
	clientCmd.Stdout = os.Stderr
	clientCmd.Stderr = os.Stderr
	err = clientCmd.Run()
	require.NoError(t, err, "cannot start client")

	// Wait for the data to arrive.
	serverData := make([]byte, UDPBUFSIZE+UDPBUFVAR)
	packetsReceived := 0
	for packetsReceived < numRTPSeqPackets {
		numBytesRead, err := serverStdout.Read(serverData)
		require.NoError(t, err, "cannot read from server stdout")
		if numBytesRead > 0 {
			packetsReceived++
		}
	}

	killAndWaitCommand(t, cmdServer)

	err = jsonchecker.JsonTestCheck(t, checker)
	require.NoError(t, err)
}

func TestUdpMulticastRTPSeqCheck(t *testing.T) {
	testUdpMulticastRTPSeqCheck(t, false)
}

func TestUdpMulticastRTPSeqCheckCLI(t *testing.T) {
	testUdpMulticastRTPSeqCheck(t, true)
}

func testUdpMulticastRTPSampling(t *testing.T, CLISwitches bool) {
	if !utils.CGroupSKBAvailable() {
		t.Skipf("This test requires CGroup/SKB, skipping")
	}

	if !kernels.MinKernelVersion("6.12") {
		t.Skip("Test requires kernel >=6.12 as it requires packet sampling")
	}

	rtpsampleParam := "rtpsample"
	dest, ok := udpMulticastRTPIP4[multicastTestRTPSample]
	if CLISwitches {
		rtpsampleParam = "rtpsamplecli"
		dest, ok = udpMulticastRTPIP4[multicastTestRTPSampleCLI]
	}
	require.True(t, ok)

	switches := []cli.SwitchSettings{
		{KeyPtr: &enterpriseOption.Config.EnableNetworkEvents, Value: true},
		{KeyPtr: &enterpriseOption.Config.MulticastAppID, Value: enterpriseOption.MulticastAppRTP},
		{KeyPtr: &enterpriseOption.Config.MulticastPorts, Value: []int{dest.port}},
		{KeyPtr: &enterpriseOption.Config.MulticastSamplePercent, Value: .01},
	}
	if CLISwitches {
		switches = append(switches, []cli.SwitchSettings{
			{KeyPtr: &enterpriseOption.Config.Layer3CLIEnable, Value: true},
			{KeyPtr: &enterpriseOption.Config.EnableUDP, Value: true},
			{KeyPtr: &enterpriseOption.Config.EnableUDPCGroup, Value: true},
			{KeyPtr: &enterpriseOption.Config.UDPStatsInterval, Value: 20 * time.Second},
			{KeyPtr: &enterpriseOption.Config.UDPIdleSocketTimeout, Value: 60 * time.Second},
		}...)
	}
	require.NoError(t, cli.SetSwitches(t, switches))

	server := getSocatCommand(t, "socat")
	ifAddr, err := getDefaultInterfaceAddress()
	require.NoError(t, err)

	socatArg1 := "-"
	socatArg2 := fmt.Sprintf("UDP4-RECVFROM:%d,ip-add-membership=%s:%s,fork", dest.port, dest.ip, ifAddr)
	socatArgs := fmt.Sprintf("%s %s", socatArg1, socatArg2)
	socatSrvChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(server)).
		WithArguments(sm.Full(socatArgs))

	clientProcess := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary)).
		WithArguments(sm.Full(fmt.Sprintf("-udpMulticastClient %s", rtpsampleParam)))

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker("clientExec").
			WithProcess(clientProcess),
		ec.NewProcessExecChecker("serverExec").
			WithProcess(socatSrvChecker),
		ec.NewProcessMulticastSampleChecker("clientSample").
			WithProcess(clientProcess).
			WithDestinationPort(uint32(dest.port)).
			WithData(htonll(RTPSampleData[1])).
			WithDirection(tetragon.Direction_EGRESS),
		ec.NewProcessMulticastSampleChecker("serverSample").
			WithProcess(socatSrvChecker).
			WithSourcePort(uint32(dest.port)).
			WithData(htonll(RTPSampleData[1])).
			WithDirection(tetragon.Direction_INGRESS),
		ec.NewProcessCloseChecker("serverClose").
			WithProcess(socatSrvChecker).
			WithDuration(durationmatcher.Between(&durationmatcher.Duration{Duration: time.Duration(0 * time.Second)},
				&durationmatcher.Duration{Duration: time.Duration(20 * time.Second)})),
		ec.NewProcessExitChecker("serverExit").
			WithProcess(socatSrvChecker),
	)

	unexpectedSamplesCheckers := []*ec.UnorderedEventChecker{
		ec.NewUnorderedEventChecker(
			ec.NewProcessMulticastSampleChecker("sample0").
				WithData(htonll(RTPSampleData[0]))),
		ec.NewUnorderedEventChecker(
			ec.NewProcessMulticastSampleChecker("sample2").
				WithData(htonll(RTPSampleData[2]))),
		ec.NewUnorderedEventChecker(
			ec.NewProcessMulticastSampleChecker("sample3").
				WithData(htonll(RTPSampleData[3]))),
		ec.NewUnorderedEventChecker(
			ec.NewProcessMulticastSampleChecker("sample4").
				WithData(htonll(RTPSampleData[4]))),
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	obs := getNoConfigObserver(t, ctx, true)
	require.NoError(t, layer3.StartLayer3Progs(ctx, nil))
	if !CLISwitches {
		tp, err := tracingpolicy.FromYAML(udpBasicConfig)
		require.NoError(t, err)
		err = observer.GetSensorManager().AddTracingPolicy(ctx, tp)
		require.NoError(t, err)
	}

	option.Config.UsePerfRingBuffer = true
	confmap.UpdateTgRuntimeConf(bpf.MapPrefixPath(), os.Getpid())
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	cmdServer := exec.Command(server, socatArg1, socatArg2)
	serverStdout, err := cmdServer.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, cmdServer.Start())
	err = waitForSocketToListen(t, net.ParseIP("0.0.0.0"), uint16(dest.port), syscall.IPPROTO_UDP, syscall.AF_INET)
	require.NoError(t, err)

	clientCmd := exec.Command(os.Args[0], "-udpMulticastClient", rtpsampleParam)
	clientCmd.Stdout = os.Stderr
	clientCmd.Stderr = os.Stderr
	err = clientCmd.Run()
	require.NoError(t, err, "cannot start client")

	// Wait for the data to arrive.
	serverData := make([]byte, UDPBUFSIZE+UDPBUFVAR)
	packetsReceived := 0
	for packetsReceived < numRTPSamplePackets {
		numBytesRead, err := serverStdout.Read(serverData)
		require.NoError(t, err, "cannot read from server stdout")
		if numBytesRead > 0 {
			packetsReceived++
		}
	}

	killAndWaitCommand(t, cmdServer)

	err = jsonchecker.JsonTestCheck(t, checker)
	require.NoError(t, err)

	// Check we didn't receive samples for the other packets.
	for _, c := range unexpectedSamplesCheckers {
		err = jsonchecker.JsonTestCheckExpect(t, c, true)
		require.NoError(t, err)
	}
}

func TestUdpMulticastRTPSampling(t *testing.T) {
	testUdpMulticastRTPSampling(t, false)
}

func TestUdpMulticastRTPSamplingCLI(t *testing.T) {
	testUdpMulticastRTPSampling(t, true)
}

func sendRTPSeqData(socket net.Conn, buf []byte, ssrc uint, seqNum uint) {
	storeMSB(buf, 2, 2, uint64(seqNum))
	storeMSB(buf, 8, 4, uint64(ssrc))
	_, err := socket.Write(buf)
	if err != nil {
		fmt.Printf("ERROR writing to socket\n")
		panic(err)
	}
	time.Sleep(10 * time.Millisecond)
}

func sendRTPSampleData(socket net.Conn, buf []byte, data uint64) {
	storeMSB(buf, 0, 4, data>>32)        // upper u32
	storeMSB(buf, 8, 4, data&0xFFFFFFFF) // lower u32
	_, err := socket.Write(buf)
	if err != nil {
		fmt.Printf("ERROR writing to socket\n")
		panic(err)
	}
	time.Sleep(10 * time.Millisecond)
}

func runUdpMulticastRTPClient(ty multicastTest) {
	dest, ok := udpMulticastRTPIP4[ty]
	if !ok {
		fmt.Printf("ERROR invalid test")
		panic("ERROR invalid test")
	}

	ifAddr, err := getDefaultInterfaceAddress()
	if err != nil {
		fmt.Printf("ERROR getting default interface address")
		panic(err)
	}

	randFile, err := os.Open("/dev/urandom")
	if err != nil {
		fmt.Printf("ERROR opening urandom\n")
		panic(err)
	}

	buf := make([]byte, UDPBUFSIZE+UDPBUFVAR)
	randReader := bufio.NewReader(randFile)
	_, err = randReader.Read(buf)
	if err != nil {
		fmt.Printf("ERROR reading urandom\n")
		panic(err)
	}
	randFile.Close()

	laddr, err := net.ResolveUDPAddr(udpProtocol, net.JoinHostPort(ifAddr, fmt.Sprintf("%d", dest.port+1)))
	if err != nil {
		fmt.Printf("ERROR resolving localhost IP address\n")
		panic(err)
	}
	raddr, err := net.ResolveUDPAddr(udpProtocol, net.JoinHostPort(dest.ip, fmt.Sprintf("%d", dest.port)))
	if err != nil {
		fmt.Printf("ERROR resolving multicast IP address and port\n")
		panic(err)
	}
	socket, err := net.DialUDP(udpProtocol, laddr, raddr)
	if err != nil {
		fmt.Printf("ERROR dialing socket\n")
		panic(err)
	}

	switch ty {
	case multicastTestRTPConnID, multicastTestRTPConnIDCLI:
		sendRTPSeqData(socket, buf, 42, 15)
	case multicastTestRTPSeq, multicastTestRTPSeqCLI:
		sendRTPSeqData(socket, buf, 45, 0)
		sendRTPSeqData(socket, buf, 46, 0)
		sendRTPSeqData(socket, buf, 46, 1)
		sendRTPSeqData(socket, buf, 46, 2)
		sendRTPSeqData(socket, buf, 45, 1)
		sendRTPSeqData(socket, buf, 45, 2)
		sendRTPSeqData(socket, buf, 45, 4)
		sendRTPSeqData(socket, buf, 45, 3)
		sendRTPSeqData(socket, buf, 45, 5)
		sendRTPSeqData(socket, buf, 46, 3)
		sendRTPSeqData(socket, buf, 46, 5)
		sendRTPSeqData(socket, buf, 46, 6)
	case multicastTestRTPSample, multicastTestRTPSampleCLI:
		for _, d := range RTPSampleData {
			sendRTPSampleData(socket, buf, d)
		}
	}
}

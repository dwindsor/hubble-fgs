// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

//go:build sudo_tests && lseg

package layer3_test

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/matchers/durationmatcher"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/sensors/config/confmap"
	"github.com/cilium/tetragon/pkg/tracingpolicy"

	"github.com/cilium/tetragon/api/v1/tetragon"
	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"

	"github.com/cilium/tetragon/pkg/jsonchecker"

	enterpriseoth "github.com/isovalent/hubble-fgs/pkg/observer/observertesthelper"
	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3"
	"github.com/isovalent/hubble-fgs/pkg/sensors/utils"
	cli "github.com/isovalent/hubble-fgs/pkg/testutils/cliswitches"
	"github.com/isovalent/hubble-fgs/pkg/testutils/runner"

	"github.com/stretchr/testify/require"
)

func htonll(v uint64) uint64 {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, v)
	return binary.LittleEndian.Uint64(b)
}

const (
	numLSEGSeqPackets    = 33
	numLSEGSamplePackets = 5
)

var (
	// The following values come from sample data. The second should hash to a value under our .01 threshold.
	// These are to be stored in MSB in the packets.
	LSEGSampleData      = []uint64{0x4ae42904b1251302, 0x4aa42915e5c60100, 0x4a4422c867541503, 0x0a4422c867550000, 0x4aa42915dc1a0501}
	udpMulticastLSEGIP4 = map[multicastTest]l3TestDest{
		multicastTestLSEGConnID:    {"225.1.1.1", 7810},
		multicastTestLSEGConnIDCLI: {"225.1.1.2", 7812},
		multicastTestLSEGSeq:       {"225.1.1.3", 7814},
		multicastTestLSEGSeqCLI:    {"225.1.1.4", 7816},
		multicastTestLSEGSample:    {"225.1.1.5", 7818},
		multicastTestLSEGSampleCLI: {"225.1.1.6", 7820},
	}
)

func testUdpMulticastLSEGConnID(t *testing.T, CLISwitches bool) {
	if !utils.CGroupSKBAvailable() {
		t.Skipf("This test requires CGroup/SKB, skipping")
	}

	if !kernels.MinKernelVersion("5.15.0") {
		t.Skip("Test requires kernel >=5.15 as it requires loopback multicast")
	}

	lsegconnParam := "lsegconn"
	dest, ok := udpMulticastLSEGIP4[multicastTestLSEGConnID]
	if CLISwitches {
		lsegconnParam = "lsegconncli"
		dest, ok = udpMulticastLSEGIP4[multicastTestLSEGConnIDCLI]
	}
	require.True(t, ok)

	switches := []cli.SwitchSettings{
		{KeyPtr: &enterpriseOption.Config.EnableNetworkEvents, Value: true},
		{KeyPtr: &enterpriseOption.Config.MulticastAppID, Value: enterpriseOption.MulticastAppLSEGMTP},
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
		WithArguments(sm.Full(fmt.Sprintf("-udpMulticastClient %s", lsegconnParam)))

	clientStatsChecker := ec.NewProcessSockStatsChecker("clientStats").
		WithProcess(clientProcess).
		WithParent(selfChecker).
		WithSocket(ec.NewSockInfoChecker().
			WithProtocol(tetragon.SocketProtocol_UDP).
			WithDestinationIp(sm.Full(dest.ip)).
			WithDestinationPort(uint32(dest.port))).
		WithConnectionId(7)

	serverStatsChecker := ec.NewProcessSockStatsChecker("serverStats").
		WithProcess(socatSrvChecker).
		WithParent(selfChecker).
		WithSocket(ec.NewSockInfoChecker().
			WithProtocol(tetragon.SocketProtocol_UDP).
			WithSourceIp(sm.Full(dest.ip)).
			WithSourcePort(uint32(dest.port))).
		WithConnectionId(7)

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
			WithConnectionId(7),
		ec.NewProcessConnectChecker("clientConnect").
			WithProcess(clientProcess).
			WithParent(selfChecker).
			WithDestinationIp(sm.Full(dest.ip)).
			WithDestinationPort(uint32(dest.port)).
			WithProtocol(tetragon.SocketProtocol_UDP).
			WithConnectionId(7),
		clientStatsChecker,
		serverStatsChecker,
		ec.NewProcessCloseChecker("serverClose").
			WithProcess(socatSrvChecker).
			WithParent(selfChecker).
			WithSourceIp(sm.Full(dest.ip)).
			WithSourcePort(uint32(dest.port)).
			WithProtocol(tetragon.SocketProtocol_UDP).
			WithConnectionId(7),
		ec.NewProcessCloseChecker("clientClose").
			WithProcess(clientProcess).
			WithParent(selfChecker).
			WithDestinationIp(sm.Full(dest.ip)).
			WithDestinationPort(uint32(dest.port)).
			WithProtocol(tetragon.SocketProtocol_UDP).
			WithConnectionId(7),
	)

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	obs := enterpriseoth.GetNoConfigObserver(t, ctx, true)
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

	clientCmd := exec.Command(os.Args[0], "-udpMulticastClient", lsegconnParam)
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

func TestUdpMulticastLSEGConnIDCLI(t *testing.T) {
	testUdpMulticastLSEGConnID(t, true)
}

func TestUdpMulticastLSEGConnID(t *testing.T) {
	testUdpMulticastLSEGConnID(t, false)
}

func testUdpMulticastLSEGSeqCheck(t *testing.T, CLISwitches bool) {
	if !utils.CGroupSKBAvailable() {
		t.Skipf("This test requires CGroup/SKB, skipping")
	}

	if !kernels.MinKernelVersion("6.12") {
		t.Skip("Test requires kernel >=6.12 as it requires multicast sequence checking")
	}

	lsegseqParam := "lsegseq"
	dest, ok := udpMulticastLSEGIP4[multicastTestLSEGSeq]
	if CLISwitches {
		lsegseqParam = "lsegseqcli"
		dest, ok = udpMulticastLSEGIP4[multicastTestLSEGSeqCLI]
	}
	require.True(t, ok)

	switches := []cli.SwitchSettings{
		{KeyPtr: &enterpriseOption.Config.EnableNetworkEvents, Value: true},
		{KeyPtr: &enterpriseOption.Config.MulticastAppID, Value: enterpriseOption.MulticastAppLSEGMTP},
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
		WithArguments(sm.Full(fmt.Sprintf("-udpMulticastClient %s", lsegseqParam)))

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker("clientExec").
			WithProcess(clientProcess),
		ec.NewProcessExecChecker("serverExec").
			WithProcess(socatSrvChecker),
		ec.NewProcessUdpSeqCheckErrorChecker("lineId5Seq3Got4").
			WithProcess(socatSrvChecker).
			WithApplicationId(1).
			WithAppSpecificId(5).
			WithSocket(ec.NewSockInfoChecker().WithSourcePort(uint32(dest.port))).
			WithSeqNumExpected(3).
			WithSeqNumReceived(4),
		ec.NewProcessUdpSeqCheckErrorChecker("lineId6Seq4Got5").
			WithProcess(socatSrvChecker).
			WithApplicationId(1).
			WithAppSpecificId(6).
			WithSocket(ec.NewSockInfoChecker().WithSourcePort(uint32(dest.port))).
			WithSeqNumExpected(4).
			WithSeqNumReceived(5),
		ec.NewProcessUdpSeqCheckErrorChecker("lineId8Seq3Got4").
			WithProcess(socatSrvChecker).
			WithApplicationId(1).
			WithAppSpecificId(8).
			WithSocket(ec.NewSockInfoChecker().WithSourcePort(uint32(dest.port))).
			WithSeqNumExpected(3).
			WithSeqNumReceived(4),
		ec.NewProcessUdpSeqCheckErrorChecker("lineId65536Seq0Got5").
			WithProcess(socatSrvChecker).
			WithApplicationId(1).
			WithAppSpecificId(65536).
			WithSocket(ec.NewSockInfoChecker().WithSourcePort(uint32(dest.port))).
			WithSeqNumExpected(0).
			WithSeqNumReceived(5),
		ec.NewProcessUdpSeqCheckErrorChecker("lineId65536Seq8Got9").
			WithProcess(socatSrvChecker).
			WithApplicationId(1).
			WithAppSpecificId(65536).
			WithSocket(ec.NewSockInfoChecker().WithSourcePort(uint32(dest.port))).
			WithSeqNumExpected(8).
			WithSeqNumReceived(9),
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

	obs := enterpriseoth.GetNoConfigObserver(t, ctx, true)
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

	clientCmd := exec.Command(os.Args[0], "-udpMulticastClient", lsegseqParam)
	clientCmd.Stdout = os.Stderr
	clientCmd.Stderr = os.Stderr
	err = clientCmd.Run()
	require.NoError(t, err, "cannot start client")

	// Wait for the data to arrive.
	serverData := make([]byte, UDPBUFSIZE+UDPBUFVAR)
	packetsReceived := 0
	for packetsReceived < numLSEGSeqPackets {
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

func TestUdpMulticastLSEGSeqCheckCLI(t *testing.T) {
	testUdpMulticastLSEGSeqCheck(t, true)
}

func TestUdpMulticastLSEGSeqCheck(t *testing.T) {
	testUdpMulticastLSEGSeqCheck(t, false)
}

func testUdpMulticastLSEGSampling(t *testing.T, CLISwitches bool) {
	if !utils.CGroupSKBAvailable() {
		t.Skipf("This test requires CGroup/SKB, skipping")
	}

	if !kernels.MinKernelVersion("6.12") {
		t.Skip("Test requires kernel >=6.12 as it requires packet sampling")
	}

	lsegsampleParam := "lsegsample"
	dest, ok := udpMulticastLSEGIP4[multicastTestLSEGSample]
	if CLISwitches {
		lsegsampleParam = "lsegsamplecli"
		dest, ok = udpMulticastLSEGIP4[multicastTestLSEGSampleCLI]
	}
	require.True(t, ok)

	switches := []cli.SwitchSettings{
		{KeyPtr: &enterpriseOption.Config.EnableNetworkEvents, Value: true},
		{KeyPtr: &enterpriseOption.Config.MulticastAppID, Value: enterpriseOption.MulticastAppLSEGMTP},
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
		WithArguments(sm.Full(fmt.Sprintf("-udpMulticastClient %s", lsegsampleParam)))

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker("clientExec").
			WithProcess(clientProcess),
		ec.NewProcessExecChecker("serverExec").
			WithProcess(socatSrvChecker),
		ec.NewProcessMulticastSampleChecker("clientSample").
			WithProcess(clientProcess).
			WithDestinationPort(uint32(dest.port)).
			WithData(htonll(LSEGSampleData[1])).
			WithDirection(tetragon.Direction_EGRESS),
		ec.NewProcessMulticastSampleChecker("serverSample").
			WithProcess(socatSrvChecker).
			WithSourcePort(uint32(dest.port)).
			WithData(htonll(LSEGSampleData[1])).
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
				WithData(htonll(LSEGSampleData[0]))),
		ec.NewUnorderedEventChecker(
			ec.NewProcessMulticastSampleChecker("sample2").
				WithData(htonll(LSEGSampleData[2]))),
		ec.NewUnorderedEventChecker(
			ec.NewProcessMulticastSampleChecker("sample3").
				WithData(htonll(LSEGSampleData[3]))),
		ec.NewUnorderedEventChecker(
			ec.NewProcessMulticastSampleChecker("sample4").
				WithData(htonll(LSEGSampleData[4]))),
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	obs := enterpriseoth.GetNoConfigObserver(t, ctx, true)
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

	clientCmd := exec.Command(os.Args[0], "-udpMulticastClient", lsegsampleParam)
	clientCmd.Stdout = os.Stderr
	clientCmd.Stderr = os.Stderr
	err = clientCmd.Run()
	require.NoError(t, err, "cannot start client")

	// Wait for the data to arrive.
	serverData := make([]byte, UDPBUFSIZE+UDPBUFVAR)
	packetsReceived := 0
	for packetsReceived < numLSEGSamplePackets {
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

func TestUdpMulticastLSEGSamplingCLI(t *testing.T) {
	testUdpMulticastLSEGSampling(t, true)
}

func TestUdpMulticastLSEGSampling(t *testing.T) {
	testUdpMulticastLSEGSampling(t, false)
}

func sendLSEGSeqData(socket net.Conn, buf []byte, lineIdSize uint, lineId uint, seqNumSize uint, seqNum uint) {
	if lineIdSize > 2 || seqNumSize < 2 || seqNumSize > 3 {
		return
	}

	flags := byte(0) | (byte(lineIdSize&0x3) << 2) | (byte(seqNumSize-2) << 1)
	buf[0] = flags
	storeMSB(buf, 1, lineIdSize, uint64(lineId))
	storeMSB(buf, 1+lineIdSize, seqNumSize, uint64(seqNum))
	_, err := socket.Write(buf)
	if err != nil {
		fmt.Printf("ERROR writing to socket\n")
		panic(err)
	}
	time.Sleep(10 * time.Millisecond)
}

func sendLSEGSampleData(socket net.Conn, buf []byte, data uint64) {
	storeMSB(buf, 0, 8, data)
	_, err := socket.Write(buf)
	if err != nil {
		fmt.Printf("ERROR writing to socket\n")
		panic(err)
	}
	time.Sleep(10 * time.Millisecond)
}

func runUdpMulticastLSEGClient(ty multicastTest) {
	dest, ok := udpMulticastLSEGIP4[ty]
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
	case multicastTestLSEGConnID, multicastTestLSEGConnIDCLI:
		sendLSEGSeqData(socket, buf, 2, 7, 2, 3)
	case multicastTestLSEGSeq, multicastTestLSEGSeqCLI:
		sendLSEGSeqData(socket, buf, 1, 5, 2, 0)
		sendLSEGSeqData(socket, buf, 1, 6, 2, 0)
		sendLSEGSeqData(socket, buf, 1, 6, 2, 1)
		sendLSEGSeqData(socket, buf, 1, 6, 2, 2)
		sendLSEGSeqData(socket, buf, 1, 5, 2, 1)
		sendLSEGSeqData(socket, buf, 1, 5, 2, 2)
		sendLSEGSeqData(socket, buf, 1, 5, 2, 4)
		sendLSEGSeqData(socket, buf, 1, 5, 2, 3)
		sendLSEGSeqData(socket, buf, 1, 5, 2, 5)
		sendLSEGSeqData(socket, buf, 1, 6, 2, 3)
		sendLSEGSeqData(socket, buf, 1, 6, 2, 5)
		sendLSEGSeqData(socket, buf, 1, 6, 2, 6)
		sendLSEGSeqData(socket, buf, 2, 7, 2, 0)
		sendLSEGSeqData(socket, buf, 2, 8, 3, 0)
		sendLSEGSeqData(socket, buf, 2, 7, 2, 1)
		sendLSEGSeqData(socket, buf, 2, 8, 3, 1)
		sendLSEGSeqData(socket, buf, 2, 7, 2, 2)
		sendLSEGSeqData(socket, buf, 2, 8, 3, 2)
		sendLSEGSeqData(socket, buf, 2, 7, 2, 3)
		sendLSEGSeqData(socket, buf, 2, 8, 3, 4)
		sendLSEGSeqData(socket, buf, 2, 7, 2, 4)
		sendLSEGSeqData(socket, buf, 2, 8, 3, 3)
		sendLSEGSeqData(socket, buf, 2, 7, 2, 5)
		sendLSEGSeqData(socket, buf, 2, 8, 3, 5)
		sendLSEGSeqData(socket, buf, 2, 7, 2, 6)
		sendLSEGSeqData(socket, buf, 2, 8, 3, 6)
		sendLSEGSeqData(socket, buf, 0, 0, 3, 5)
		sendLSEGSeqData(socket, buf, 0, 0, 3, 6)
		sendLSEGSeqData(socket, buf, 0, 0, 3, 7)
		sendLSEGSeqData(socket, buf, 0, 0, 3, 9)
		sendLSEGSeqData(socket, buf, 0, 0, 3, 10)
		sendLSEGSeqData(socket, buf, 0, 0, 3, 11)
		sendLSEGSeqData(socket, buf, 0, 0, 3, 12)
	case multicastTestLSEGSample, multicastTestLSEGSampleCLI:
		for _, d := range LSEGSampleData {
			sendLSEGSampleData(socket, buf, d)
		}
	}
}

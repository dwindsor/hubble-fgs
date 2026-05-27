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
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/sensors/config/confmap"

	enterpriseoth "github.com/isovalent/hubble-fgs/pkg/observer/observertesthelper"
	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"
	"github.com/isovalent/hubble-fgs/pkg/sensors/base"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3"
	"github.com/isovalent/hubble-fgs/pkg/sensors/utils"
	"github.com/isovalent/hubble-fgs/pkg/testutils/runner"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type ipAndPort struct {
	IP   string
	port int
}

const (
	numRTPSeqPackets = 12
)

var (
	udpMulticastRTPIP4 = map[multicastTest]ipAndPort{
		multicastTestRTPConnID: {"225.3.3.3", 8858},
		multicastTestRTPSeq:    {"225.4.4.4", 9858},
		multicastTestRTPSample: {"225.6.6.6", 8058},
	}
)

func storeMSB(buf []byte, index uint, size uint, value uint64) {
	if size == 0 {
		return
	}
	for i := uint(0); i < size; i++ {
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

func TestUdpMulticastRTPConnID(t *testing.T) {
	if !utils.CGroupSKBAvailable() {
		t.Skipf("This test requires CGroup/SKB, skipping")
	}

	if !kernels.MinKernelVersion("5.15.0") {
		t.Skip("Test requires kernel >=5.15 as it requires loopback multicast")
	}

	ipAndPort, ok := udpMulticastRTPIP4[multicastTestRTPConnID]
	require.True(t, ok)

	udpMulticastIP4 := ipAndPort.IP
	udpMulticastPort := ipAndPort.port

	oldEnableNetworkEventsValue := enterpriseOption.Config.EnableNetworkEvents
	enterpriseOption.Config.EnableNetworkEvents = true
	oldMulticastAppID := enterpriseOption.Config.MulticastAppID
	enterpriseOption.Config.MulticastAppID = enterpriseOption.MulticastAppRTP
	oldMulticastPorts := enterpriseOption.Config.MulticastPorts
	enterpriseOption.Config.MulticastPorts = []int{udpMulticastPort}
	oldMulticastSeqCheck := enterpriseOption.Config.MulticastSeqCheck
	enterpriseOption.Config.MulticastSeqCheck = true
	t.Cleanup(func() {
		enterpriseOption.Config.EnableNetworkEvents = oldEnableNetworkEventsValue
		enterpriseOption.Config.MulticastAppID = oldMulticastAppID
		enterpriseOption.Config.MulticastPorts = oldMulticastPorts
		enterpriseOption.Config.MulticastSeqCheck = oldMulticastSeqCheck
	})

	server := getSocatCommand(t, "socat")
	ifAddr, err := getDefaultInterfaceAddress()
	require.NoError(t, err)

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	socatArg1 := "-"
	socatArg2 := fmt.Sprintf("UDP4-RECVFROM:%d,ip-add-membership=%s:%s,fork", udpMulticastPort, udpMulticastIP4, ifAddr)
	socatArgs := fmt.Sprintf("%s %s", socatArg1, socatArg2)
	socatSrvChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(server)).
		WithArguments(sm.Full(socatArgs))

	clientProcess := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary)).
		WithArguments(sm.Full("-udpMulticastClient rtpconn"))

	clientStatsChecker := ec.NewProcessSockStatsChecker("clientStats").
		WithProcess(clientProcess).
		WithParent(selfChecker).
		WithSocket(ec.NewSockInfoChecker().
			WithProtocol(tetragon.SocketProtocol_UDP).
			WithDestinationIp(sm.Full(udpMulticastIP4)).
			WithDestinationPort(uint32(udpMulticastPort))).
		WithConnectionId(42)

	serverStatsChecker := ec.NewProcessSockStatsChecker("serverStats").
		WithProcess(socatSrvChecker).
		WithParent(selfChecker).
		WithSocket(ec.NewSockInfoChecker().
			WithProtocol(tetragon.SocketProtocol_UDP).
			WithSourceIp(sm.Full(udpMulticastIP4)).
			WithSourcePort(uint32(udpMulticastPort))).
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
			WithSourceIp(sm.Full(udpMulticastIP4)).
			WithSourcePort(uint32(udpMulticastPort)).
			WithProtocol(tetragon.SocketProtocol_UDP).
			WithConnectionId(42),
		ec.NewProcessConnectChecker("clientConnect").
			WithProcess(clientProcess).
			WithParent(selfChecker).
			WithDestinationIp(sm.Full(udpMulticastIP4)).
			WithDestinationPort(uint32(udpMulticastPort)).
			WithProtocol(tetragon.SocketProtocol_UDP).
			WithConnectionId(42),
		clientStatsChecker,
		serverStatsChecker,
		ec.NewProcessCloseChecker("serverClose").
			WithProcess(socatSrvChecker).
			WithParent(selfChecker).
			WithSourceIp(sm.Full(udpMulticastIP4)).
			WithSourcePort(uint32(udpMulticastPort)).
			WithProtocol(tetragon.SocketProtocol_UDP).
			WithConnectionId(42),
		ec.NewProcessCloseChecker("clientClose").
			WithProcess(clientProcess).
			WithParent(selfChecker).
			WithDestinationIp(sm.Full(udpMulticastIP4)).
			WithDestinationPort(uint32(udpMulticastPort)).
			WithProtocol(tetragon.SocketProtocol_UDP).
			WithConnectionId(42),
	)

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	if err := observertesthelper.WriteConfigFile(testConfigFile, udpConfig); err != nil {
		t.Fatalf("WriteFile(%s): err %s", testConfigFile, err)
	}

	base := base.GetInitialSensorTest(t)
	obs, err := enterpriseoth.GetDefaultObserverWithBase(t, ctx, base, testConfigFile, runner.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserver error: %s", err)
	}

	layer3.StartLayer3Progs(ctx, nil)
	option.Config.UsePerfRingBuffer = true
	confmap.UpdateTgRuntimeConf(bpf.MapPrefixPath(), os.Getpid())
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	cmdServer := exec.Command(server, socatArg1, socatArg2)
	serverStdout, err := cmdServer.StdoutPipe()
	assert.NoError(t, err)
	assert.NoError(t, cmdServer.Start())
	err = waitForSocketToListen(t, net.ParseIP("0.0.0.0"), uint16(udpMulticastPort), syscall.IPPROTO_UDP, syscall.AF_INET)
	assert.NoError(t, err)
	serverPid := uint32(cmdServer.Process.Pid)

	clientCmd := exec.Command(os.Args[0], "-udpMulticastClient", "rtpconn")
	clientCmd.Stdout = os.Stderr
	clientCmd.Stderr = os.Stderr
	err = clientCmd.Run()
	assert.NoError(t, err, "cannot start client")

	// Wait for some data to arrive.
	serverData := make([]byte, 16)
	numBytesRead := 0
	for numBytesRead == 0 {
		numBytesRead, err = serverStdout.Read(serverData)
		require.NoError(t, err, "cannot read from server stdout")
	}

	killAndWaitCommand(t, cmdServer)

	quit := false
	for !quit {
		_, err = os.Stat(fmt.Sprintf("/proc/%d", serverPid))
		if err != nil {
			quit = true
		}
		time.Sleep(10 * time.Millisecond)
	}

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestUdpMulticastRTPSeqCheck(t *testing.T) {
	if !utils.CGroupSKBAvailable() {
		t.Skipf("This test requires CGroup/SKB, skipping")
	}

	if !kernels.MinKernelVersion("5.15.0") {
		t.Skip("Test requires kernel >=5.15 as it requires loopback multicast")
	}

	ipAndPort, ok := udpMulticastRTPIP4[multicastTestRTPSeq]
	require.True(t, ok)

	udpMulticastIP4 := ipAndPort.IP
	udpMulticastPort := ipAndPort.port

	oldEnableNetworkEventsValue := enterpriseOption.Config.EnableNetworkEvents
	enterpriseOption.Config.EnableNetworkEvents = true
	oldMulticastAppID := enterpriseOption.Config.MulticastAppID
	enterpriseOption.Config.MulticastAppID = enterpriseOption.MulticastAppRTP
	oldMulticastPorts := enterpriseOption.Config.MulticastPorts
	enterpriseOption.Config.MulticastPorts = []int{udpMulticastPort}
	oldMulticastSeqCheck := enterpriseOption.Config.MulticastSeqCheck
	enterpriseOption.Config.MulticastSeqCheck = true
	t.Cleanup(func() {
		enterpriseOption.Config.EnableNetworkEvents = oldEnableNetworkEventsValue
		enterpriseOption.Config.MulticastAppID = oldMulticastAppID
		enterpriseOption.Config.MulticastPorts = oldMulticastPorts
		enterpriseOption.Config.MulticastSeqCheck = oldMulticastSeqCheck
	})

	server := getSocatCommand(t, "socat")
	ifAddr, err := getDefaultInterfaceAddress()
	require.NoError(t, err)

	socatArg1 := "-"
	socatArg2 := fmt.Sprintf("UDP4-RECVFROM:%d,ip-add-membership=%s:%s,fork", udpMulticastPort, udpMulticastIP4, ifAddr)
	socatArgs := fmt.Sprintf("%s %s", socatArg1, socatArg2)
	socatSrvChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(server)).
		WithArguments(sm.Full(socatArgs))

	clientProcess := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary)).
		WithArguments(sm.Full("-udpMulticastClient rtpseq"))

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker("clientExec").
			WithProcess(clientProcess),
		ec.NewProcessExecChecker("serverExec").
			WithProcess(socatSrvChecker),
		ec.NewProcessUdpSeqCheckErrorChecker("lineId5Seq3Got4").
			WithProcess(socatSrvChecker).
			WithApplicationId(2).
			WithAppSpecificId(45).
			WithSocket(ec.NewSockInfoChecker().WithSourcePort(uint32(udpMulticastPort))).
			WithSeqNumExpected(3).
			WithSeqNumReceived(4),
		ec.NewProcessUdpSeqCheckErrorChecker("lineId6Seq4Got5").
			WithProcess(socatSrvChecker).
			WithApplicationId(2).
			WithAppSpecificId(46).
			WithSocket(ec.NewSockInfoChecker().WithSourcePort(uint32(udpMulticastPort))).
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

	if err := observertesthelper.WriteConfigFile(testConfigFile, udpConfigBasic); err != nil {
		t.Fatalf("WriteFile(%s): err %s", testConfigFile, err)
	}

	base := base.GetInitialSensorTest(t)
	obs, err := enterpriseoth.GetDefaultObserverWithBase(t, ctx, base, testConfigFile, runner.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserver error: %s", err)
	}
	layer3.StartLayer3Progs(ctx, nil)
	option.Config.UsePerfRingBuffer = true
	confmap.UpdateTgRuntimeConf(bpf.MapPrefixPath(), os.Getpid())
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	cmdServer := exec.Command(server, socatArg1, socatArg2)
	serverStdout, err := cmdServer.StdoutPipe()
	assert.NoError(t, err)
	assert.NoError(t, cmdServer.Start())
	err = waitForSocketToListen(t, net.ParseIP("0.0.0.0"), uint16(udpMulticastPort), syscall.IPPROTO_UDP, syscall.AF_INET)
	assert.NoError(t, err)
	serverPid := uint32(cmdServer.Process.Pid)

	clientCmd := exec.Command(os.Args[0], "-udpMulticastClient", "rtpseq")
	clientCmd.Stdout = os.Stderr
	clientCmd.Stderr = os.Stderr
	err = clientCmd.Run()
	assert.NoError(t, err, "cannot start client")

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

	quit := false
	for !quit {
		_, err = os.Stat(fmt.Sprintf("/proc/%d", serverPid))
		if err != nil {
			quit = true
		}
		time.Sleep(10 * time.Millisecond)
	}
	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
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

func runUdpMulticastRTPClient(ty multicastTest) {
	ipAndPort, ok := udpMulticastRTPIP4[ty]
	if !ok {
		fmt.Printf("ERROR invalid test")
		panic("ERROR invalid test")
	}

	udpMulticastIP4 := ipAndPort.IP
	udpMulticastPort := ipAndPort.port

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

	laddr, err := net.ResolveUDPAddr(udpProtocol, net.JoinHostPort(ifAddr, fmt.Sprintf("%d", udpMulticastPort+1)))
	if err != nil {
		fmt.Printf("ERROR resolving localhost IP address\n")
		panic(err)
	}
	raddr, err := net.ResolveUDPAddr(udpProtocol, net.JoinHostPort(udpMulticastIP4, fmt.Sprintf("%d", udpMulticastPort)))
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
	case multicastTestRTPConnID:
		sendRTPSeqData(socket, buf, 42, 15)
	case multicastTestRTPSeq:
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
	}
}

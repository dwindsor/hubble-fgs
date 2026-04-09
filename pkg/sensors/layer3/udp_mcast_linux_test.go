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
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/matchers/durationmatcher"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/sensors/config/confmap"

	"github.com/cilium/tetragon/api/v1/tetragon"
	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"

	"github.com/cilium/tetragon/pkg/jsonchecker"

	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"
	"github.com/isovalent/hubble-fgs/pkg/sensors/base"
	"github.com/isovalent/hubble-fgs/pkg/sensors/utils"
	"github.com/isovalent/hubble-fgs/pkg/testutils/runner"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	enterpriseoth "github.com/isovalent/hubble-fgs/pkg/observer/observertesthelper"
)

const (
	udpMulticastIP4  = "239.1.1.1"
	udpMulticastPort = 6858
	localhostIP4     = "127.0.0.1"
	numSeqPackets    = 33
)

func TestUdpMulticastLSEGConnID(t *testing.T) {
	if !utils.CGroupSKBAvailable() {
		t.Skipf("This test requires CGroup/SKB, skipping")
	}

	if !kernels.MinKernelVersion("5.15.0") {
		t.Skip("Test requires kernel >=5.15 as it requires loopback multicast")
	}

	oldEnableNetworkEventsValue := enterpriseOption.Config.EnableNetworkEvents
	enterpriseOption.Config.EnableNetworkEvents = true
	oldMulticastAppID := enterpriseOption.Config.MulticastAppID
	enterpriseOption.Config.MulticastAppID = enterpriseOption.MulticastAppLSEGMTP
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

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	socatArg1 := "-"
	socatArg2 := fmt.Sprintf("UDP4-LISTEN:%d,ip-add-membership=%s:%s,fork", udpMulticastPort, udpMulticastIP4, localhostIP4)
	socatArgs := fmt.Sprintf("%s %s", socatArg1, socatArg2)
	socatSrvChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(server)).
		WithArguments(sm.Full(socatArgs))

	clientProcess := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary)).
		WithArguments(sm.Full("-udpMulticastClient conn"))

	clientStatsChecker := ec.NewProcessSockStatsChecker("clientStats").
		WithProcess(clientProcess).
		WithParent(selfChecker).
		WithSocket(ec.NewSockInfoChecker().
			WithProtocol(tetragon.SocketProtocol_UDP).
			WithDestinationIp(sm.Full(udpMulticastIP4)).
			WithDestinationPort(udpMulticastPort)).
		WithConnectionId(7)

	serverStatsChecker := ec.NewProcessSockStatsChecker("serverStats").
		WithProcess(socatSrvChecker).
		WithParent(selfChecker).
		WithSocket(ec.NewSockInfoChecker().
			WithProtocol(tetragon.SocketProtocol_UDP).
			WithSourceIp(sm.Full(udpMulticastIP4)).
			WithSourcePort(udpMulticastPort)).
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
			WithSourceIp(sm.Full(udpMulticastIP4)).
			WithSourcePort(udpMulticastPort).
			WithProtocol(tetragon.SocketProtocol_UDP).
			WithConnectionId(7),
		ec.NewProcessConnectChecker("clientConnect").
			WithProcess(clientProcess).
			WithParent(selfChecker).
			WithDestinationIp(sm.Full(udpMulticastIP4)).
			WithDestinationPort(udpMulticastPort).
			WithProtocol(tetragon.SocketProtocol_UDP).
			WithConnectionId(7),
		clientStatsChecker,
		serverStatsChecker,
		ec.NewProcessCloseChecker("serverClose").
			WithProcess(socatSrvChecker).
			WithParent(selfChecker).
			WithSourceIp(sm.Full(udpMulticastIP4)).
			WithSourcePort(udpMulticastPort).
			WithProtocol(tetragon.SocketProtocol_UDP).
			WithConnectionId(7),
		ec.NewProcessCloseChecker("clientClose").
			WithProcess(clientProcess).
			WithParent(selfChecker).
			WithDestinationIp(sm.Full(udpMulticastIP4)).
			WithDestinationPort(udpMulticastPort).
			WithProtocol(tetragon.SocketProtocol_UDP).
			WithConnectionId(7),
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

	option.Config.UsePerfRingBuffer = true
	confmap.UpdateTgRuntimeConf(bpf.MapPrefixPath(), os.Getpid())
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	cmdServer := exec.Command(server, socatArg1, socatArg2)
	serverStdout, err := cmdServer.StdoutPipe()
	assert.NoError(t, err)
	assert.NoError(t, cmdServer.Start())
	err = waitForSocketToListen(t, net.ParseIP("0.0.0.0"), udpMulticastPort, syscall.IPPROTO_UDP, syscall.AF_INET)
	assert.NoError(t, err)
	serverPid := uint32(cmdServer.Process.Pid)

	clientCmd := exec.Command(os.Args[0], "-udpMulticastClient", "conn")
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

func TestUdpMulticastSeqCheck(t *testing.T) {
	if !utils.CGroupSKBAvailable() {
		t.Skipf("This test requires CGroup/SKB, skipping")
	}

	if !kernels.MinKernelVersion("5.15.0") {
		t.Skip("Test requires kernel >=5.15 as it requires loopback multicast")
	}

	oldEnableNetworkEventsValue := enterpriseOption.Config.EnableNetworkEvents
	enterpriseOption.Config.EnableNetworkEvents = true
	oldMulticastAppID := enterpriseOption.Config.MulticastAppID
	enterpriseOption.Config.MulticastAppID = enterpriseOption.MulticastAppLSEGMTP
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

	socatArg1 := "-"
	socatArg2 := fmt.Sprintf("UDP4-LISTEN:%d,ip-add-membership=%s:%s,fork", udpMulticastPort, udpMulticastIP4, localhostIP4)
	socatArgs := fmt.Sprintf("%s %s", socatArg1, socatArg2)
	socatSrvChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(server)).
		WithArguments(sm.Full(socatArgs))

	clientProcess := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary)).
		WithArguments(sm.Full("-udpMulticastClient seq"))

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker("clientExec").
			WithProcess(clientProcess),
		ec.NewProcessExecChecker("serverExec").
			WithProcess(socatSrvChecker),
		ec.NewProcessUdpSeqCheckErrorChecker("lineId5Seq3Got4").
			WithProcess(socatSrvChecker).
			WithApplicationId(1).
			WithAppSpecificId(5).
			WithSocket(ec.NewSockInfoChecker().WithSourcePort(udpMulticastPort)).
			WithSeqNumExpected(3).
			WithSeqNumReceived(4),
		ec.NewProcessUdpSeqCheckErrorChecker("lineId6Seq4Got5").
			WithProcess(socatSrvChecker).
			WithApplicationId(1).
			WithAppSpecificId(6).
			WithSocket(ec.NewSockInfoChecker().WithSourcePort(udpMulticastPort)).
			WithSeqNumExpected(4).
			WithSeqNumReceived(5),
		ec.NewProcessUdpSeqCheckErrorChecker("lineId8Seq3Got4").
			WithProcess(socatSrvChecker).
			WithApplicationId(1).
			WithAppSpecificId(8).
			WithSocket(ec.NewSockInfoChecker().WithSourcePort(udpMulticastPort)).
			WithSeqNumExpected(3).
			WithSeqNumReceived(4),
		ec.NewProcessUdpSeqCheckErrorChecker("lineId65536Seq0Got5").
			WithProcess(socatSrvChecker).
			WithApplicationId(1).
			WithAppSpecificId(65536).
			WithSocket(ec.NewSockInfoChecker().WithSourcePort(udpMulticastPort)).
			WithSeqNumExpected(0).
			WithSeqNumReceived(5),
		ec.NewProcessUdpSeqCheckErrorChecker("lineId65536Seq8Got9").
			WithProcess(socatSrvChecker).
			WithApplicationId(1).
			WithAppSpecificId(65536).
			WithSocket(ec.NewSockInfoChecker().WithSourcePort(udpMulticastPort)).
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

	if err := observertesthelper.WriteConfigFile(testConfigFile, udpConfigBasic); err != nil {
		t.Fatalf("WriteFile(%s): err %s", testConfigFile, err)
	}

	base := base.GetInitialSensorTest(t)
	obs, err := enterpriseoth.GetDefaultObserverWithBase(t, ctx, base, testConfigFile, runner.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserver error: %s", err)
	}
	option.Config.UsePerfRingBuffer = true
	confmap.UpdateTgRuntimeConf(bpf.MapPrefixPath(), os.Getpid())
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	cmdServer := exec.Command(server, socatArg1, socatArg2)
	serverStdout, err := cmdServer.StdoutPipe()
	assert.NoError(t, err)
	assert.NoError(t, cmdServer.Start())
	err = waitForSocketToListen(t, net.ParseIP("0.0.0.0"), udpMulticastPort, syscall.IPPROTO_UDP, syscall.AF_INET)
	assert.NoError(t, err)
	serverPid := uint32(cmdServer.Process.Pid)

	clientCmd := exec.Command(os.Args[0], "-udpMulticastClient", "seq")
	clientCmd.Stdout = os.Stderr
	clientCmd.Stderr = os.Stderr
	err = clientCmd.Run()
	assert.NoError(t, err, "cannot start client")

	// Wait for some data to arrive.
	serverScanner := bufio.NewScanner(serverStdout)
	serverPackets := 0
	for serverScanner.Scan() {
		serverData := serverScanner.Bytes()
		if len(serverData) > 0 {
			serverPackets++
			if serverPackets >= numSeqPackets {
				break
			}
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

func runUdpMulticastServer() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM)
	go func() {
		sig := <-sigs
		if sig == syscall.SIGTERM {
			os.Exit(0)
		}
	}()

	addr, err := net.ResolveUDPAddr(udpProtocol, fmt.Sprintf("%s:%d", udpMulticastIP4, udpMulticastPort))

	conn, err := net.ListenMulticastUDP(udpProtocol, nil, addr)
	if err != nil {
		fmt.Printf("NotReady: %s", err)
		panic(err)
	}
	buf := make([]byte, 2*UDPBUFSIZE)
	fmt.Printf("Ready\n")
	for {
		_, _, err = conn.ReadFrom(buf)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR reading from socket\n")
			panic(err)
		}
	}
}

func storeMSB(buf []byte, index uint, size uint, value uint) {
	if size == 0 {
		return
	}
	for i := uint(0); i < size; i++ {
		buf[index+i] = byte((value >> ((size - i - 1) * 8)) & 0xff)
	}
}

func sendSeqData(socket net.Conn, buf []byte, lineIdSize uint, lineId uint, seqNumSize uint, seqNum uint) {
	if lineIdSize > 2 || seqNumSize < 2 || seqNumSize > 3 {
		return
	}

	flags := byte(0) | (byte(lineIdSize&0x3) << 2) | (byte(seqNumSize-2) << 1)
	buf[0] = flags
	storeMSB(buf, 1, lineIdSize, lineId)
	storeMSB(buf, 1+lineIdSize, seqNumSize, seqNum)
	udpSendData(socket, buf)
	time.Sleep(10 * time.Millisecond)
}

func runUdpMulticastClient(ty multicastTest) {
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

	laddr, err := net.ResolveUDPAddr(udpProtocol, net.JoinHostPort(localhostIP4, fmt.Sprintf("%d", udpMulticastPort+1)))
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
	case multicastTestLSEGConnID:
		sendSeqData(socket, buf, 2, 7, 2, 3)
	case multicastTestLSEGSeq:
		sendSeqData(socket, buf, 1, 5, 2, 0)
		sendSeqData(socket, buf, 1, 6, 2, 0)
		sendSeqData(socket, buf, 1, 6, 2, 1)
		sendSeqData(socket, buf, 1, 6, 2, 2)
		sendSeqData(socket, buf, 1, 5, 2, 1)
		sendSeqData(socket, buf, 1, 5, 2, 2)
		sendSeqData(socket, buf, 1, 5, 2, 4)
		sendSeqData(socket, buf, 1, 5, 2, 3)
		sendSeqData(socket, buf, 1, 5, 2, 5)
		sendSeqData(socket, buf, 1, 6, 2, 3)
		sendSeqData(socket, buf, 1, 6, 2, 5)
		sendSeqData(socket, buf, 1, 6, 2, 6)
		sendSeqData(socket, buf, 2, 7, 2, 0)
		sendSeqData(socket, buf, 2, 8, 3, 0)
		sendSeqData(socket, buf, 2, 7, 2, 1)
		sendSeqData(socket, buf, 2, 8, 3, 1)
		sendSeqData(socket, buf, 2, 7, 2, 2)
		sendSeqData(socket, buf, 2, 8, 3, 2)
		sendSeqData(socket, buf, 2, 7, 2, 3)
		sendSeqData(socket, buf, 2, 8, 3, 4)
		sendSeqData(socket, buf, 2, 7, 2, 4)
		sendSeqData(socket, buf, 2, 8, 3, 3)
		sendSeqData(socket, buf, 2, 7, 2, 5)
		sendSeqData(socket, buf, 2, 8, 3, 5)
		sendSeqData(socket, buf, 2, 7, 2, 6)
		sendSeqData(socket, buf, 2, 8, 3, 6)
		sendSeqData(socket, buf, 0, 0, 3, 5)
		sendSeqData(socket, buf, 0, 0, 3, 6)
		sendSeqData(socket, buf, 0, 0, 3, 7)
		sendSeqData(socket, buf, 0, 0, 3, 9)
		sendSeqData(socket, buf, 0, 0, 3, 10)
		sendSeqData(socket, buf, 0, 0, 3, 11)
		sendSeqData(socket, buf, 0, 0, 3, 12)
	}
}

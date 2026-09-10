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
	"math/rand"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/kernels"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/reader/namespace"
	"github.com/cilium/tetragon/pkg/sensors/config/confmap"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/api/v1/tetragon"
	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"

	"github.com/cilium/tetragon/pkg/jsonchecker"

	enterpriseoth "github.com/isovalent/hubble-fgs/pkg/observer/observertesthelper"
	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3"
	"github.com/isovalent/hubble-fgs/pkg/sensors/networkWatermarksEvents"
	"github.com/isovalent/hubble-fgs/pkg/sensors/utils"
	cli "github.com/isovalent/hubble-fgs/pkg/testutils/cliswitches"
	"github.com/isovalent/hubble-fgs/pkg/testutils/runner"

	_ "github.com/isovalent/hubble-fgs/pkg/sensors/exec"
)

func getTcpObserverDisableEvents(t *testing.T, CLISwitches bool, disableConnect bool, disableClose bool, disableAccept bool, disableListen bool) string {
	eventDisableConfig := `
      disableEvents:
`
	eventDisableConfig += "\n        disableConnect: " + strconv.FormatBool(disableConnect)
	eventDisableConfig += "\n        disableClose: " + strconv.FormatBool(disableClose)
	eventDisableConfig += "\n        disableAccept: " + strconv.FormatBool(disableAccept)
	eventDisableConfig += "\n        disableListen: " + strconv.FormatBool(disableListen)

	if CLISwitches {
		require.NoError(t, cli.SetSwitches(t, []cli.SwitchSettings{
			{KeyPtr: &enterpriseOption.Config.Layer3CLIEnable, Value: true},
			{KeyPtr: &enterpriseOption.Config.EnableNetworkEvents, Value: true},
			{KeyPtr: &enterpriseOption.Config.EnableTCP, Value: true},
			{KeyPtr: &enterpriseOption.Config.TCPDisableListenEvents, Value: disableListen},
			{KeyPtr: &enterpriseOption.Config.TCPDisableConnectEvents, Value: disableConnect},
			{KeyPtr: &enterpriseOption.Config.TCPDisableAcceptEvents, Value: disableAccept},
			{KeyPtr: &enterpriseOption.Config.TCPDisableCloseEvents, Value: disableClose},
		}))
		return ""
	}
	return tcpBasicConfig + eventDisableConfig
}

func testTCPDisableConfigConnect4(t *testing.T, CLISwitches bool, disableConnect bool) {
	if runtime.GOARCH != "amd64" && !kernels.MinKernelVersion("5.8.0") {
		t.Skip("Test requires amd64 or kernel >=5.8")
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	configYaml := getTcpObserverDisableEvents(t, CLISwitches, disableConnect, true, true, true)

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	curlChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix("curl")).
		WithArguments(sm.Full("127.0.0.1"))

	execChecker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker("selfExec").
			WithProcess(selfChecker).
			WithParent(ec.NewProcessChecker()),
		ec.NewProcessExecChecker("curlExec").
			WithProcess(curlChecker).
			WithParent(selfChecker),
	)

	connectChecker := ec.NewUnorderedEventChecker(
		ec.NewProcessConnectChecker("curlConnect").
			WithProcess(curlChecker).
			WithParent(selfChecker).
			WithDestinationIp(sm.Full("127.0.0.1")).
			WithDestinationPort(80).
			WithProtocol(tetragon.SocketProtocol_TCP),
	)

	obs := enterpriseoth.GetNoConfigObserver(t, ctx, true)
	require.NoError(t, layer3.StartLayer3Progs(ctx, nil))
	if !CLISwitches {
		tp, err := tracingpolicy.FromYAML(configYaml)
		require.NoError(t, err)
		err = observer.GetSensorManager().AddTracingPolicy(ctx, tp)
		require.NoError(t, err)
	}

	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	observertesthelper.ExecWGCurl(&readyWG, 10, "127.0.0.1")

	// Regardless of enabled/disabled network events, we should exepct the exec events
	err := jsonchecker.JsonTestCheck(t, execChecker)
	assert.NoError(t, err)

	// If connect events are disabled then expect checker failure
	err = jsonchecker.JsonTestCheckExpect(t, connectChecker, disableConnect)
	assert.NoError(t, err)
}

func TestTCPDisableConnectEvent4CLI(t *testing.T) {
	testTCPDisableConfigConnect4(t, true, true)
}

func TestTCPNoDisableConnectEvent4CLI(t *testing.T) {
	testTCPDisableConfigConnect4(t, true, false)
}

func TestTCPDisableConnectEvent4NoCLI(t *testing.T) {
	testTCPDisableConfigConnect4(t, false, true)
}

func TestTCPNoDisableConnectEvent4NoCLI(t *testing.T) {
	testTCPDisableConfigConnect4(t, false, false)
}

func testTCPDisableConfigListenAcceptClose4(t *testing.T, port uint16, CLISwitches bool, disableListen bool, disableAccept bool, disableClose bool) {
	if runtime.GOARCH != "amd64" && !kernels.MinKernelVersion("5.8.0") {
		t.Skip("Test requires amd64 or kernel >=5.8")
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	portstr := fmt.Sprintf("%d", port)

	configYaml := getTcpObserverDisableEvents(t, CLISwitches, true, disableClose, disableAccept, disableListen)

	obs := enterpriseoth.GetNoConfigObserver(t, ctx, true)
	require.NoError(t, layer3.StartLayer3Progs(ctx, nil))

	if !CLISwitches {
		tp, err := tracingpolicy.FromYAML(configYaml)
		require.NoError(t, err)
		err = observer.GetSensorManager().AddTracingPolicy(ctx, tp)
		require.NoError(t, err)
	}

	server := getNCCommand(t, "nc.openbsd")
	client := server
	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	ncChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(server)).
		WithArguments(sm.Full("-nvlp " + portstr + " -s 0.0.0.0"))

	execChecker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker("selfExec").
			WithProcess(selfChecker).
			WithParent(ec.NewProcessChecker()),
		ec.NewProcessExecChecker("ncExec").
			WithProcess(ncChecker).
			WithParent(selfChecker),
	)

	listenChecker := ec.NewUnorderedEventChecker(
		ec.NewProcessListenChecker("ncListen").
			WithProcess(ncChecker).
			WithParent(selfChecker).
			WithIp(sm.Full("0.0.0.0")).
			WithPort(uint32(port)).
			WithProtocol(tetragon.SocketProtocol_TCP),
	)
	acceptChecker := ec.NewUnorderedEventChecker(
		ec.NewProcessAcceptChecker("ncAccept").
			WithProcess(ncChecker).
			WithParent(selfChecker).
			WithSourceIp(sm.Full("127.0.0.1")).
			WithSourcePort(uint32(port)).
			WithProtocol(tetragon.SocketProtocol_TCP),
	)
	closeChecker := ec.NewUnorderedEventChecker(
		ec.NewProcessCloseChecker("ncClose").
			WithProcess(ncChecker).
			WithParent(selfChecker).
			WithSourceIp(sm.Full("127.0.0.1")).
			WithSourcePort(uint32(port)).
			WithProtocol(tetragon.SocketProtocol_TCP).
			WithSocketType(sm.Full("accept")),
	)

	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)

	readyWG.Wait()
	cmdServer := exec.Command(server, "-nvlp", portstr, "-s", "0.0.0.0")
	stdout, err := cmdServer.StdoutPipe()
	assert.NoError(t, err)
	assert.NoError(t, cmdServer.Start())
	err = waitForSocketToListen(t, net.ParseIP("0.0.0.0"), port, syscall.IPPROTO_TCP, syscall.AF_INET)
	assert.NoError(t, err)
	cmdClient := exec.Command(client, "127.0.0.1", portstr)
	stdin, err := cmdClient.StdinPipe()
	assert.NoError(t, err)
	assert.NoError(t, cmdClient.Start())

	sendData(t, stdin, "hello")
	waitForData(t, stdout, "hello")

	killAndWaitCommand(t, cmdServer)
	killAndWaitCommand(t, cmdClient)

	// Regardless of enabled/disabled network events, we should exepct the exec events
	err = jsonchecker.JsonTestCheck(t, execChecker)
	assert.NoError(t, err)

	listenErr := jsonchecker.JsonTestCheckExpect(t, listenChecker, disableListen)
	assert.NoError(t, listenErr)

	acceptErr := jsonchecker.JsonTestCheckExpect(t, acceptChecker, disableAccept)
	assert.NoError(t, acceptErr)

	// Wait for the listening socket to close
	err = waitForListeningSocketToClose(t, net.ParseIP("0.0.0.0"), port, syscall.IPPROTO_TCP, syscall.AF_INET)
	require.NoError(t, err)

	err = jsonchecker.JsonTestCheckExpect(t, closeChecker, disableClose)
	if err == nil {
		return
	}

	// Let's wait for the sockets to close. This is expensive so we only do this if we really have to.
	err = waitForListeningSocketToClose(t, net.ParseIP("127.0.0.1"), port, syscall.IPPROTO_TCP, syscall.AF_INET)
	assert.NoError(t, err)
	err = waitForConnectedSocketToClose(t, net.ParseIP("127.0.0.1"), port, syscall.IPPROTO_TCP, syscall.AF_INET)
	assert.NoError(t, err)

	err = jsonchecker.JsonTestCheckExpect(t, closeChecker, disableClose)
	assert.NoError(t, err)
}

func TestTCPDisableListenAcceptClose4CLI(t *testing.T) {
	testTCPDisableConfigListenAcceptClose4(t, 8101, true, true, true, true)
}

func TestTCPNoDisableListenAcceptClose4CLI(t *testing.T) {
	if !utils.SupportFentry() {
		t.Skipf("Close events without Fentry can cause missed events. skipping test")
	}

	// The close events within these tests are a little flaky when only using kprobes, so always disable
	// close tests if we don't support FEntry.
	testTCPDisableConfigListenAcceptClose4(t, 8102, true, false, false, false)
}

func TestTCPDisableListenAcceptClose4NoCLI(t *testing.T) {
	testTCPDisableConfigListenAcceptClose4(t, 8103, false, true, true, true)
}

func TestTCPNoDisableListenAcceptClose4NoCLI(t *testing.T) {
	// The close events within these tests are a little flaky when only using kprobes, so always disable
	// close tests if we don't support FEntry.
	testTCPDisableConfigListenAcceptClose4(t, 8104, false, false, false, !utils.SupportFentry())
}

const TCPBUFSIZE, TCPBUFVAR = 1024, 256
const tcpHostname = "127.0.0.1"
const tcpPortno = 31337
const tcpProtocol = "tcp4"

var watermarksQuit = false

func handleSes(ses net.Conn) {
	buf := make([]byte, 2*TCPBUFSIZE)
	quit := false
	ses.SetDeadline(time.Now().Add(200 * time.Millisecond))
	for !quit && !watermarksQuit {
		_, err := ses.Read(buf)
		if err != nil {
			opErr, ok := err.(*net.OpError)
			if !ok || !opErr.Timeout() {
				quit = true
			}
		}
	}
}

func runTcpServer() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM)
	conn, err := net.Listen(tcpProtocol, fmt.Sprintf("%s:%d", tcpHostname, tcpPortno))
	if err != nil {
		fmt.Printf("NotReady: %s", err)
		panic(err)
	}
	go func() {
		sig := <-sigs
		if sig == syscall.SIGTERM {
			conn.Close()
			watermarksQuit = true
			// Give chance for sockets to gracefully close
			time.Sleep(500 * time.Millisecond)
			os.Exit(0)
		}
	}()

	fmt.Printf("Ready\n")

	for {
		ses, err := conn.Accept()
		if err != nil {
			panic(err)
		}
		go handleSes(ses)
	}
}

func tcpSendData(socket net.Conn, buf []byte) {
	bufLen := rand.Intn(TCPBUFVAR) - (TCPBUFVAR / 2) + TCPBUFSIZE
	_, err := socket.Write(buf[0:bufLen])
	if err != nil {
		fmt.Printf("ERROR writing to socket\n")
		panic(err)
	}
}

func runTcpClient() {
	baselineRate := 5
	burstRate := 10
	baselineDuration := 1
	burstDuration := 1
	numBursts := 5

	baselineWait := time.Duration(1000000 / baselineRate)
	burstWait := time.Duration(1000000 / burstRate)

	randFile, err := os.Open("/dev/urandom")
	if err != nil {
		fmt.Printf("ERROR opening urandom\n")
		panic(err)
	}

	buf := make([]byte, TCPBUFSIZE+TCPBUFVAR)
	randReader := bufio.NewReader(randFile)
	_, err = randReader.Read(buf)
	if err != nil {
		fmt.Printf("ERROR reading urandom\n")
		panic(err)
	}
	randFile.Close()

	socket, err := net.Dial(tcpProtocol, net.JoinHostPort(tcpHostname, fmt.Sprintf("%d", tcpPortno)))
	if err != nil {
		fmt.Printf("ERROR dialing socket\n")
		panic(err)
	}

	for range numBursts {
		for range baselineDuration * baselineRate {
			tcpSendData(socket, buf)
			time.Sleep(baselineWait * time.Microsecond)
		}
		for range burstDuration * burstRate {
			tcpSendData(socket, buf)
			time.Sleep(burstWait * time.Microsecond)
		}
	}

	socket.Close()
}

func testTCPWatermarks(t *testing.T, CLISwitches, legacy bool) {
	// timing related tests are unreliable currently. In lieu of a solution, let's
	// disable these tests.
	t.Skipf("Test disabled due to unreliable timing in CI")
	if runtime.GOARCH != "amd64" && !kernels.MinKernelVersion("5.8.0") {
		t.Skip("Test requires amd64 or kernel >=5.8")
	}

	bpf.CheckOrMountCgroup2()

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))
	clientProcess := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary)).
		WithArguments(sm.Full("-tcpClient"))
	serverProcess := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary)).
		WithArguments(sm.Full("-tcpServer"))

	var checker *ec.UnorderedEventChecker

	if legacy {
		checker = ec.NewUnorderedEventChecker(
			ec.NewProcessExecChecker("clientExec").
				WithProcess(clientProcess).
				WithParent(selfChecker),
			ec.NewProcessNetworkBurstChecker("burstEgressStart").
				WithProcess(clientProcess).
				WithParent(selfChecker).
				WithProtocol(sm.Full("TCP")).
				WithDirection(sm.Full("egress")).
				WithBurstState(sm.Full("start")),
			ec.NewProcessNetworkBurstChecker("burstEgressEnd").
				WithProcess(clientProcess).
				WithParent(selfChecker).
				WithProtocol(sm.Full("TCP")).
				WithDirection(sm.Full("egress")).
				WithBurstState(sm.Full("end")),
			ec.NewProcessExecChecker("serverExec").
				WithProcess(serverProcess).
				WithParent(selfChecker),
			ec.NewProcessExitChecker("serverExit").
				WithProcess(serverProcess).
				WithParent(selfChecker),
		)
	} else {
		checker = ec.NewUnorderedEventChecker(
			ec.NewProcessExecChecker("clientExec").
				WithProcess(clientProcess).
				WithParent(selfChecker),
			ec.NewProcessNetworkWatermarkChecker("burstEgressStart").
				WithProcess(clientProcess).
				WithParent(selfChecker).
				WithProtocol(sm.Full("TCP")).
				WithWatermarksType(sm.Full("burst")).
				WithDirection(sm.Full("egress")).
				WithWatermarksState(sm.Full("start")),
			ec.NewProcessNetworkWatermarkChecker("burstEgressEnd").
				WithProcess(clientProcess).
				WithParent(selfChecker).
				WithProtocol(sm.Full("TCP")).
				WithWatermarksType(sm.Full("burst")).
				WithDirection(sm.Full("egress")).
				WithWatermarksState(sm.Full("end")),
			ec.NewProcessNetworkWatermarkChecker("dipEgressStart").
				WithProcess(clientProcess).
				WithParent(selfChecker).
				WithProtocol(sm.Full("TCP")).
				WithWatermarksType(sm.Full("dip")).
				WithDirection(sm.Full("egress")).
				WithWatermarksState(sm.Full("start")),
			ec.NewProcessNetworkWatermarkChecker("dipEgressEnd").
				WithProcess(clientProcess).
				WithParent(selfChecker).
				WithProtocol(sm.Full("TCP")).
				WithWatermarksType(sm.Full("dip")).
				WithDirection(sm.Full("egress")).
				WithWatermarksState(sm.Full("end")),
			ec.NewProcessExecChecker("serverExec").
				WithProcess(serverProcess).
				WithParent(selfChecker),
			ec.NewProcessExitChecker("serverExit").
				WithProcess(serverProcess).
				WithParent(selfChecker),
			ec.NewProcessNetworkWatermarkChecker("burstIngressStart").
				WithProcess(serverProcess).
				WithParent(selfChecker).
				WithProtocol(sm.Full("TCP")).
				WithWatermarksType(sm.Full("burst")).
				WithDirection(sm.Full("ingress")).
				WithWatermarksState(sm.Full("start")),
			ec.NewProcessNetworkWatermarkChecker("burstIngressEnd").
				WithProcess(serverProcess).
				WithParent(selfChecker).
				WithProtocol(sm.Full("TCP")).
				WithWatermarksType(sm.Full("burst")).
				WithDirection(sm.Full("ingress")).
				WithWatermarksState(sm.Full("end")),
			ec.NewProcessNetworkWatermarkChecker("dipIngressStart").
				WithProcess(serverProcess).
				WithParent(selfChecker).
				WithProtocol(sm.Full("TCP")).
				WithWatermarksType(sm.Full("dip")).
				WithDirection(sm.Full("ingress")).
				WithWatermarksState(sm.Full("start")),
			ec.NewProcessNetworkWatermarkChecker("dipIngressEnd").
				WithProcess(serverProcess).
				WithParent(selfChecker).
				WithProtocol(sm.Full("TCP")).
				WithWatermarksType(sm.Full("dip")).
				WithDirection(sm.Full("ingress")).
				WithWatermarksState(sm.Full("end")),
		)
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	if CLISwitches {
		require.NoError(t, cli.SetSwitches(t, []cli.SwitchSettings{
			{KeyPtr: &enterpriseOption.Config.Layer3CLIEnable, Value: true},
			{KeyPtr: &enterpriseOption.Config.EnableNetworkEvents, Value: true},
			{KeyPtr: &enterpriseOption.Config.EnableTCP, Value: true},
			{KeyPtr: &enterpriseOption.Config.TCPStatsInterval, Value: 20 * time.Second},
			{KeyPtr: &enterpriseOption.Config.EnableTCPWatermarks, Value: true},
			{KeyPtr: &enterpriseOption.Config.TCPWatermarksWindowSizeMs, Value: uint32(1000)},
			{KeyPtr: &enterpriseOption.Config.TCPWatermarksBurstTriggerPercent, Value: uint32(50)},
			{KeyPtr: &enterpriseOption.Config.TCPWatermarksDipTriggerPercent, Value: uint32(10)},
			{KeyPtr: &enterpriseOption.Config.EnableNetworkWatermarksExitGen, Value: true},
			{KeyPtr: &enterpriseOption.Config.NetworkWatermarksExitGenInterval, Value: 1000 * time.Millisecond},
		}))
	}

	obs := enterpriseoth.GetNoConfigObserver(t, ctx, true)
	require.NoError(t, layer3.StartLayer3Progs(ctx, nil))

	if !CLISwitches {
		var configYaml string
		if legacy {
			configYaml = tcpConfigLegacy
		} else {
			configYaml = tcpConfig
		}
		tp, err := tracingpolicy.FromYAML(configYaml)
		require.NoError(t, err)
		err = observer.GetSensorManager().AddTracingPolicy(ctx, tp)
		require.NoError(t, err)
	}
	option.Config.UsePerfRingBuffer = true
	confmap.UpdateTgRuntimeConf(bpf.MapPrefixPath(), os.Getpid())
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	serverCmd := exec.Command(os.Args[0], "-tcpServer")
	serverOutput, err := serverCmd.StdoutPipe()
	require.NoError(t, err, "could not connect to server output pipe")
	serverCmd.Stderr = os.Stderr

	err = serverCmd.Start()
	require.NoError(t, err, "cannot start server")

	serverBuf := bufio.NewReader(serverOutput)
	var line []byte
	for string(line) != "Ready" {
		line, _, err = serverBuf.ReadLine()
		if err != nil {
			killAndWaitCommand(t, serverCmd)
			t.Fatal(err)
		}
		if len(line) == 0 {
			killAndWaitCommand(t, serverCmd)
			t.Fatal("received empty line from TCP server")
		}
		if strings.HasPrefix(string(line), "NotReady") {
			t.Fatalf("TCP server failed to start: '%s'", string(line))
		}
	}

	serverPid := uint32(serverCmd.Process.Pid)

	watermarksMapFile := filepath.Join(bpf.MapPrefixPath(), networkWatermarksEvents.ProcessNetworkWatermarksMapName)
	m, err := ebpf.LoadPinnedMap(watermarksMapFile, nil)
	require.NoError(t, err, "cannot open map file")
	defer m.Close()
	processKey := &networkWatermarksEvents.ProcessNetworkWatermarksKey{Key: networkWatermarksEvents.PidToWatermarksKey(serverPid, syscall.IPPROTO_TCP, 0)}
	var processValue networkWatermarksEvents.ProcessNetworkWatermarksValue
	err = m.Lookup(processKey, &processValue)
	require.Error(t, err, "server process in watermarks map before traffic")

	clientCmd := exec.Command(os.Args[0], "-tcpClient")
	clientCmd.Stdout = os.Stderr
	clientCmd.Stderr = os.Stderr
	err = clientCmd.Run()
	require.NoError(t, err, "cannot start client")

	err = m.Lookup(processKey, &processValue)
	require.NoError(t, err, "server process must be in watermarks map")

	killAndWaitCommand(t, serverCmd)

	// the burst map record is sure to be removed after exit event is
	// received, let's wait for that and do the lookup check after

	err = jsonchecker.JsonTestCheck(t, checker)
	require.NoError(t, err)

	err = m.Lookup(processKey, &processValue)
	require.Error(t, err, "server process in watermarks map after exit")
}

func TestTCPBurst(t *testing.T) {
	testTCPWatermarks(t, false, true)
}

func TestTCPWatermarks(t *testing.T) {
	testTCPWatermarks(t, false, false)
}

func TestTCPWatermarksCLI(t *testing.T) {
	testTCPWatermarks(t, true, false)
}

func TestNamespaces(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	rootNs := namespace.GetCurrentNamespace()
	nsChecker := ec.NewNamespacesChecker().FromNamespaces(rootNs)

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary)).
		WithNs(nsChecker)

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker("").
			WithProcess(selfChecker).
			WithParent(ec.NewProcessChecker()),
	)

	obs, err := enterpriseoth.GetDefaultObserver(t, ctx, runner.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserver error: %s", err)
	}

	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()
	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

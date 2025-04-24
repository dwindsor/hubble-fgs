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
	"github.com/cilium/tetragon/api/v1/tetragon"
	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/matchers/durationmatcher"
	"github.com/cilium/tetragon/pkg/matchers/listmatcher"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	"github.com/sirupsen/logrus"

	"github.com/cilium/tetragon/pkg/jsonchecker"
	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"
	"github.com/isovalent/hubble-fgs/pkg/sensors/base"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3"
	"github.com/isovalent/hubble-fgs/pkg/sensors/networkWatermarksEvents"
	"github.com/isovalent/hubble-fgs/pkg/sensors/utils"
	"github.com/isovalent/hubble-fgs/pkg/testutils"
	"github.com/isovalent/hubble-fgs/pkg/testutils/runner"

	_ "github.com/isovalent/hubble-fgs/pkg/sensors/exec"
	//_ "github.com/isovalent/hubble-fgs/pkg/sensors/sockmap"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/isovalent/hubble-fgs/pkg/metrics/socketmetrics"
	enterpriseoth "github.com/isovalent/hubble-fgs/pkg/observer/observertesthelper"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

const udpConfigLegacy = `
apiversion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "udp"
spec:
  parser:
    udp:
      enable: true
      cgroup: true
      statsInterval: 20
      deleteIdleSocketInterval: 60
      burst:
        enable: true
        windowSize: 1000
        triggerPercent: 50
    burstExitGen:
      enable: true
      interval: 1000
    dns:
      enable: true
      ports: [53]
`

const udpConfig = `
apiversion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "udp"
spec:
  parser:
    udp:
      enable: true
      cgroup: true
      statsInterval: 20
      deleteIdleSocketInterval: 60
      watermarks:
        enable: true
        windowSize: 1000
        burstTriggerPercent: 50
        dipTriggerPercent: 10
    networkWatermarksExitGen:
      enable: true
      interval: 1000
    dns:
      enable: true
      ports: [53]
`

const udpConfigWithoutDnsQuestions = `
apiversion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "udp"
spec:
  parser:
    udp:
      enable: true
    dns:
      enable: true
      ports: [53]
`

const udpConfigWithDnsQuestions = `
apiversion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "udp"
spec:
  parser:
    udp:
      enable: true
    dns:
      enable: true
      ports: [53]
      reportQuestions: true
`

const udpL7Config = `
apiversion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "udp"
spec:
  parser:
    udp:
      enable: true
      cgroup: true
      statsInterval: 20
      deleteIdleSocketInterval: 60
      seqCheck:
        enable: true
        appId: 1
        ports: [31337]
    dns:
      enable: true
      ports: [53]
`
const udpL7ConfigDisableClose = `
apiversion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "udp"
spec:
  parser:
    dns:
      enable: true
      ports: [53]
    udp:
      enable: true
      cgroup: true
      statsInterval: 20
      deleteIdleSocketInterval: 60
      seqCheck:
        enable: true
        appId: 1
        ports: [31337]
      disableEvents:
        disableClose: `

const udpL7ConfigDisableListen = `
apiversion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "udp"
spec:
  parser:
    dns:
      enable: true
      ports: [53]
    udp:
      enable: true
      cgroup: true
      statsInterval: 20
      deleteIdleSocketInterval: 60
      seqCheck:
        enable: true
        appId: 1
        ports: [31337]
      disableEvents:
        disableListen: `

const udpConfigBasic = `
apiversion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "udp"
spec:
  parser:
    udp:
      enable: true
      cgroup: true
`
const UDPBUFSIZE, UDPBUFVAR = 1024, 256
const udpHostname = "127.0.0.1"
const udpPortno = 31337
const udpProtocol = "udp4"

func runUdpServer() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM)
	go func() {
		sig := <-sigs
		if sig == syscall.SIGTERM {
			os.Exit(0)
		}
	}()

	conn, err := net.ListenPacket(udpProtocol, fmt.Sprintf("%s:%d", udpHostname, udpPortno))
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

func udpSendData(socket net.Conn, buf []byte) {
	bufLen := rand.Intn(UDPBUFVAR) - (UDPBUFVAR / 2) + UDPBUFSIZE
	_, err := socket.Write(buf[0:bufLen])
	if err != nil {
		fmt.Printf("ERROR writing to socket\n")
		panic(err)
	}
}

func runUdpWatermarksClient() {
	baselineRate := 5
	burstRate := 20
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

	buf := make([]byte, UDPBUFSIZE+UDPBUFVAR)
	randReader := bufio.NewReader(randFile)
	_, err = randReader.Read(buf)
	if err != nil {
		fmt.Printf("ERROR reading urandom\n")
		panic(err)
	}
	randFile.Close()

	socket, err := net.Dial(udpProtocol, fmt.Sprintf("%s:%d", udpHostname, udpPortno))
	if err != nil {
		fmt.Printf("ERROR dialing socket\n")
		panic(err)
	}

	for i := 0; i < numBursts; i++ {
		for j := 0; j < (baselineDuration * baselineRate); j++ {
			udpSendData(socket, buf)
			time.Sleep(baselineWait * time.Microsecond)
		}
		for j := 0; j < (burstDuration * burstRate); j++ {
			udpSendData(socket, buf)
			time.Sleep(burstWait * time.Microsecond)
		}
	}
}

func testUdpWatermarks(t *testing.T, legacy bool) {
	// timing related tests are unreliable currently. In lieu of a solution, let's
	// disable these tests.
	t.Skipf("Test disabled due to unreliable timing in CI")
	if !utils.CGroupSKBAvailable() {
		t.Skipf("This test requires CGroup/SKB, skipping")
	}

	clientProcess := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary)).
		WithArguments(sm.Full("-udpWatermarksClient"))

	serverProcess := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary)).
		WithArguments(sm.Full("-udpServer"))

	var checker *ec.UnorderedEventChecker

	if legacy {
		checker = ec.NewUnorderedEventChecker(
			ec.NewProcessExecChecker("clientExec").
				WithProcess(clientProcess),
			ec.NewProcessNetworkBurstChecker("egressStart").
				WithProcess(clientProcess).
				WithProtocol(sm.Full("UDP")).
				WithDirection(sm.Full("egress")).
				WithBurstState(sm.Full("start")),
			ec.NewProcessNetworkBurstChecker("egressEnd").
				WithProcess(clientProcess).
				WithProtocol(sm.Full("UDP")).
				WithDirection(sm.Full("egress")).
				WithBurstState(sm.Full("end")),
			ec.NewProcessExecChecker("serverStart").
				WithProcess(serverProcess),
			ec.NewProcessNetworkBurstChecker("ingressStart").
				WithProcess(serverProcess).
				WithProtocol(sm.Full("UDP")).
				WithDirection(sm.Full("ingress")).
				WithBurstState(sm.Full("start")),
			ec.NewProcessNetworkBurstChecker("ingressEnd").
				WithProcess(serverProcess).
				WithProtocol(sm.Full("UDP")).
				WithDirection(sm.Full("ingress")).
				WithBurstState(sm.Full("end")),
			ec.NewProcessCloseChecker("serverClose").
				WithProcess(serverProcess).
				WithDuration(durationmatcher.Between(&durationmatcher.Duration{Duration: time.Duration(1 * time.Second)},
					&durationmatcher.Duration{Duration: time.Duration(20 * time.Second)})),
			ec.NewProcessExitChecker("serverExit").
				WithProcess(serverProcess),
		)
	} else {
		checker = ec.NewUnorderedEventChecker(
			ec.NewProcessExecChecker("clientExec").
				WithProcess(clientProcess),
			ec.NewProcessNetworkWatermarkChecker("burstEgressStart").
				WithProcess(clientProcess).
				WithProtocol(sm.Full("UDP")).
				WithWatermarksType(sm.Full("burst")).
				WithDirection(sm.Full("egress")).
				WithWatermarksState(sm.Full("start")),
			ec.NewProcessNetworkWatermarkChecker("burstEgressEnd").
				WithProcess(clientProcess).
				WithProtocol(sm.Full("UDP")).
				WithWatermarksType(sm.Full("burst")).
				WithDirection(sm.Full("egress")).
				WithWatermarksState(sm.Full("end")),
			ec.NewProcessNetworkWatermarkChecker("dipEgressStart").
				WithProcess(clientProcess).
				WithProtocol(sm.Full("UDP")).
				WithWatermarksType(sm.Full("dip")).
				WithDirection(sm.Full("egress")).
				WithWatermarksState(sm.Full("start")),
			ec.NewProcessNetworkWatermarkChecker("dipEgressEnd").
				WithProcess(clientProcess).
				WithProtocol(sm.Full("UDP")).
				WithWatermarksType(sm.Full("dip")).
				WithDirection(sm.Full("egress")).
				WithWatermarksState(sm.Full("end")),
			ec.NewProcessExecChecker("serverStart").
				WithProcess(serverProcess),
			ec.NewProcessNetworkWatermarkChecker("burstIngressStart").
				WithProcess(serverProcess).
				WithProtocol(sm.Full("UDP")).
				WithWatermarksType(sm.Full("burst")).
				WithDirection(sm.Full("ingress")).
				WithWatermarksState(sm.Full("start")),
			ec.NewProcessNetworkWatermarkChecker("burstIngressEnd").
				WithProcess(serverProcess).
				WithProtocol(sm.Full("UDP")).
				WithWatermarksType(sm.Full("burst")).
				WithDirection(sm.Full("ingress")).
				WithWatermarksState(sm.Full("end")),
			ec.NewProcessNetworkWatermarkChecker("dipIngressStart").
				WithProcess(serverProcess).
				WithProtocol(sm.Full("UDP")).
				WithWatermarksType(sm.Full("dip")).
				WithDirection(sm.Full("ingress")).
				WithWatermarksState(sm.Full("start")),
			ec.NewProcessNetworkWatermarkChecker("dipIngressEnd").
				WithProcess(serverProcess).
				WithProtocol(sm.Full("UDP")).
				WithWatermarksType(sm.Full("dip")).
				WithDirection(sm.Full("ingress")).
				WithWatermarksState(sm.Full("end")),
			ec.NewProcessCloseChecker("serverClose").
				WithProcess(serverProcess).
				WithDuration(durationmatcher.Between(&durationmatcher.Duration{Duration: time.Duration(1 * time.Second)},
					&durationmatcher.Duration{Duration: time.Duration(20 * time.Second)})),
			ec.NewProcessExitChecker("serverExit").
				WithProcess(serverProcess),
		)
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	if legacy {
		if err := observertesthelper.WriteConfigFile(testConfigFile, udpConfigLegacy); err != nil {
			t.Fatalf("WriteFile(%s): err %s", testConfigFile, err)
		}
	} else {
		if err := observertesthelper.WriteConfigFile(testConfigFile, udpConfig); err != nil {
			t.Fatalf("WriteFile(%s): err %s", testConfigFile, err)
		}
	}

	base := base.GetInitialSensor()
	obs, err := enterpriseoth.GetDefaultObserverWithBase(t, ctx, base, testConfigFile, runner.Conf().TetragonLib, observertesthelper.WithMyPid(), observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserver error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	serverCmd := exec.Command(os.Args[0], "-udpServer")
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
			t.Fatal("received empty line from UDP server")
		}
		if strings.HasPrefix(string(line), "NotReady") {
			t.Fatalf("UDP server failed to start: '%s'", string(line))
		}
	}

	serverPid := uint32(serverCmd.Process.Pid)

	watermarksMapFile := filepath.Join(bpf.MapPrefixPath(), networkWatermarksEvents.ProcessNetworkWatermarksMapName)
	m, err := ebpf.LoadPinnedMap(watermarksMapFile, nil)
	require.NoError(t, err, "cannot open map file")
	defer m.Close()
	processKey := &networkWatermarksEvents.ProcessNetworkWatermarksKey{Key: networkWatermarksEvents.PidToWatermarksKey(serverPid, syscall.IPPROTO_UDP, 0)}
	var processValue networkWatermarksEvents.ProcessNetworkWatermarksValue
	err = m.Lookup(processKey, &processValue)
	assert.Error(t, err, "server process in watermarks map before traffic")

	clientCmd := exec.Command(os.Args[0], "-udpWatermarksClient")
	clientCmd.Stdout = os.Stderr
	clientCmd.Stderr = os.Stderr
	err = clientCmd.Run()
	assert.NoError(t, err, "cannot start client")

	err = m.Lookup(processKey, &processValue)
	assert.NoError(t, err, "server process must be in watermarks map")

	err = m.Lookup(processKey, &processValue)
	assert.NoError(t, err, "client process must be in watermarks map")

	killAndWaitCommand(t, serverCmd)

	quit := false
	for !quit {
		_, err = os.Stat(fmt.Sprintf("/proc/%d", serverPid))
		if err != nil {
			quit = true
		}
		time.Sleep(10 * time.Millisecond)
	}

	// the burst map record is sure to be removed after exit event is
	// received, let's wait for that and do the lookup check after

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)

	err = m.Lookup(processKey, &processValue)
	assert.Error(t, err, "server process in watermarks map after exit")

	killAndWaitCommand(t, clientCmd)
}

func TestUdpBurst(t *testing.T) {
	testUdpWatermarks(t, true)
}

func TestUdpWatermarks(t *testing.T) {
	testUdpWatermarks(t, false)
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

func runUdpLayer7Client() {
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

	socket, err := net.Dial(udpProtocol, fmt.Sprintf("%s:%d", udpHostname, udpPortno))
	if err != nil {
		fmt.Printf("ERROR dialing socket\n")
		panic(err)
	}

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

func TestUdpSeqCheck(t *testing.T) {
	if !utils.CGroupSKBAvailable() {
		t.Skipf("This test requires CGroup/SKB, skipping")
	}

	t.Skip("UDP Seq Checking disabled.")

	clientProcess := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary)).
		WithArguments(sm.Full("-udpLayer7Client"))

	serverProcess := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary)).
		WithArguments(sm.Full("-udpServer"))

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker("clientExec").
			WithProcess(clientProcess),
		ec.NewProcessExecChecker("serverExec").
			WithProcess(serverProcess),
		ec.NewProcessUdpSeqCheckErrorChecker("lineId5Seq3Got4").
			WithProcess(serverProcess).
			WithApplicationId(1).
			WithAppSpecificId(5).
			WithSocket(ec.NewSockInfoChecker().WithSourcePort(udpPortno)).
			WithSeqNumExpected(3).
			WithSeqNumReceived(4),
		ec.NewProcessUdpSeqCheckErrorChecker("lineId6Seq4Got5").
			WithProcess(serverProcess).
			WithApplicationId(1).
			WithAppSpecificId(6).
			WithSocket(ec.NewSockInfoChecker().WithSourcePort(udpPortno)).
			WithSeqNumExpected(4).
			WithSeqNumReceived(5),
		ec.NewProcessUdpSeqCheckErrorChecker("lineId8Seq3Got4").
			WithProcess(serverProcess).
			WithApplicationId(1).
			WithAppSpecificId(8).
			WithSocket(ec.NewSockInfoChecker().WithSourcePort(udpPortno)).
			WithSeqNumExpected(3).
			WithSeqNumReceived(4),
		ec.NewProcessUdpSeqCheckErrorChecker("lineId65536Seq0Got5").
			WithProcess(serverProcess).
			WithApplicationId(1).
			WithAppSpecificId(65536).
			WithSocket(ec.NewSockInfoChecker().WithSourcePort(udpPortno)).
			WithSeqNumExpected(0).
			WithSeqNumReceived(5),
		ec.NewProcessUdpSeqCheckErrorChecker("lineId65536Seq8Got9").
			WithProcess(serverProcess).
			WithApplicationId(1).
			WithAppSpecificId(65536).
			WithSocket(ec.NewSockInfoChecker().WithSourcePort(udpPortno)).
			WithSeqNumExpected(8).
			WithSeqNumReceived(9),
		ec.NewProcessCloseChecker("serverClose").
			WithProcess(serverProcess).
			WithDuration(durationmatcher.Between(&durationmatcher.Duration{Duration: time.Duration(0 * time.Second)},
				&durationmatcher.Duration{Duration: time.Duration(20 * time.Second)})),
		ec.NewProcessExitChecker("serverExit").
			WithProcess(serverProcess),
	)

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	if err := observertesthelper.WriteConfigFile(testConfigFile, udpL7Config); err != nil {
		t.Fatalf("WriteFile(%s): err %s", testConfigFile, err)
	}

	base := base.GetInitialSensor()
	obs, err := enterpriseoth.GetDefaultObserverWithBase(t, ctx, base, testConfigFile, runner.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserver error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	serverCmd := exec.Command(os.Args[0], "-udpServer")
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
			t.Fatal("received empty line from UDP server")
		}
		if strings.HasPrefix(string(line), "NotReady") {
			t.Fatalf("UDP server failed to start: '%s'", string(line))
		}
	}

	serverPid := uint32(serverCmd.Process.Pid)

	clientCmd := exec.Command(os.Args[0], "-udpLayer7Client")
	clientCmd.Stdout = os.Stderr
	clientCmd.Stderr = os.Stderr
	err = clientCmd.Run()
	assert.NoError(t, err, "cannot start client")

	killAndWaitCommand(t, serverCmd)

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

	killAndWaitCommand(t, clientCmd)
}

// Note 20.0.0.0/8 is the DoD and isn't routable on the Internet
// This is included to test UDP latency timestamps are NOT added
// to any real UDP packets.
const udpBasicConfig = `
apiversion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "udp"
spec:
  parser:
    udp:
      enable: true
      cgroup: true
      statsInterval: 2
      latency:
        enable: true
        matchSubnets: [20.0.0.0/8]
        min: 0
        max: 10000
`

const udpBasicConfigWOEnable = `
apiversion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "udp"
spec:
  parser:
    udp:
      cgroup: true
      statsInterval: 2
      latency:
        enable: true
        matchSubnets: [20.0.0.0/8]
        min: 0
        max: 10000
`

// Setting UDP latency max to 1,000,000 means 1% equates to
// 10ms, which a packet across loopback should easily be
// quicker than.
const udpConfigWithLatencyDetection = `
apiversion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "udp"
spec:
  parser:
    udp:
      enable: true
      cgroup: true
      statsInterval: 2
      latency:
        enable: true
        matchSubnets: [127.0.0.1/32]
        matchPorts: [8081]
        min: 0
        max: 1000000
`

// NB(kkourt): Function(t *testing.T, ctx context.Context) is the reasonable
// thing to do here even if revive complains.
//
//revive:disable:context-as-argument
func getBasicUdpObserver(t *testing.T, ctx context.Context) *observer.Observer {
	return getLayer3Observer(t, ctx, udpBasicConfig, true)
}

func getUdpObserverWithLatencyDetection(t *testing.T, ctx context.Context) *observer.Observer {
	return getLayer3Observer(t, ctx, udpConfigWithLatencyDetection, true)
}

func getUdpObserverDisableEvents(t *testing.T, ctx context.Context, CLISwitches bool, disableConnect bool, disableListen bool, disableClose bool, disableStats bool) *observer.Observer {
	eventDisableConfig := `
      disableEvents:
`
	eventDisableConfig += "\n        disableConnect: " + strconv.FormatBool(disableConnect)
	eventDisableConfig += "\n        disableListen: " + strconv.FormatBool(disableListen)
	eventDisableConfig += "\n        disableClose: " + strconv.FormatBool(disableClose)
	eventDisableConfig += "\n        disableStats: " + strconv.FormatBool(disableStats)

	var udpDisableEventsConfig string
	if CLISwitches {
		udpDisableEventsConfig = udpBasicConfigWOEnable + eventDisableConfig
	} else {
		udpDisableEventsConfig = udpBasicConfig + eventDisableConfig
	}
	return getLayer3Observer(t, ctx, udpDisableEventsConfig, true)
}

func TestUdpConnectEvent4(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	server := getNCCommand(t, "nc.openbsd")
	client := server

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	ncSrvChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(server)).
		WithArguments(sm.Full("-unvlp 8081"))

	ncCliChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(client)).
		WithArguments(sm.Full("-u 127.0.0.1 8081"))

	clientStatsChecker := ec.NewProcessSockStatsChecker("clientStats").
		WithProcess(ncCliChecker).
		WithParent(selfChecker).
		WithSocket(ec.NewSockInfoChecker().
			WithProtocol(tetragon.SocketProtocol_UDP).
			WithDestinationIp(sm.Full("127.0.0.1")).
			WithDestinationPort(8081))

	serverStatsChecker := ec.NewProcessSockStatsChecker("serverStats").
		WithProcess(ncSrvChecker).
		WithParent(selfChecker).
		WithSocket(ec.NewSockInfoChecker().
			WithProtocol(tetragon.SocketProtocol_UDP).
			WithSourceIp(sm.Full("127.0.0.1")).
			WithDestinationIp(sm.Full("127.0.0.1")).
			WithSourcePort(8081))

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker("selfExec").
			WithProcess(selfChecker).
			WithParent(ec.NewProcessChecker()),
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
			WithSourcePort(8081).
			WithDestinationIp(sm.Full("127.0.0.1")).
			WithProtocol(tetragon.SocketProtocol_UDP),
		clientStatsChecker,
		serverStatsChecker,
	)

	// We need to check sockstats using a custom stateful checker since stats events can
	// be split up and so checking the individual events won't work. We need to instead
	// keep a cumulative count of the stats we have seen and compare them to expected
	// totals.
	var clientBytesSent uint64
	var clientSegsOut uint32
	var serverBytesReceived uint64
	var serverSegsIn uint32
	statsChecker := &ec.FnEventChecker{
		NextCheckFn: func(event_ ec.Event, _ *logrus.Logger) (bool, error) {
			event, ok := event_.(*tetragon.ProcessSockStats)
			if !ok {
				return false, fmt.Errorf("event is not a sockstats event")
			}

			if event.Stats == nil {
				return false, fmt.Errorf("event has no stats field")
			}

			if clientStatsChecker.Check(event) == nil {
				clientBytesSent += event.Stats.BytesSent
				clientSegsOut += event.Stats.SegsOut
				return false, nil
			}

			if serverStatsChecker.Check(event) == nil {
				serverBytesReceived += event.Stats.BytesReceived
				serverSegsIn += event.Stats.SegsIn
				return false, nil
			}

			return false, fmt.Errorf("sockstats event is neither from client nor server")
		},
		FinalCheckFn: func(_ *logrus.Logger) error {
			defer func() {
				clientBytesSent = 0
				clientSegsOut = 0
				serverBytesReceived = 0
				serverSegsIn = 0
			}()

			if clientBytesSent != 5 {
				return fmt.Errorf("Unexecpected clientBytesSent, wanted 5, got %d", clientBytesSent)
			}

			if clientSegsOut != 1 {
				return fmt.Errorf("Unexecpected clientSegsOut, wanted 1, got %d", clientSegsOut)
			}

			if serverBytesReceived != 5 {
				return fmt.Errorf("Unexecpected serverBytesReceived, wanted 5, got %d", serverBytesReceived)
			}

			if serverSegsIn != 1 {
				return fmt.Errorf("Unexecpected serverSegsIn, wanted 1, got %d", serverSegsIn)
			}

			return nil
		},
	}

	obs := getBasicUdpObserver(t, ctx)
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)

	readyWG.Wait()
	cmdServer := exec.Command(server, "-unvlp", "8081")
	assert.NoError(t, cmdServer.Start())
	time.Sleep(1000 * time.Millisecond)

	cmdClient := exec.Command(client, "-u", "127.0.0.1", "8081")
	stdin, err := cmdClient.StdinPipe()
	assert.NoError(t, err)
	assert.NoError(t, cmdClient.Start())
	_, err = stdin.Write([]byte("hello"))
	assert.NoError(t, err)

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)

	err = jsonchecker.JsonTestCheck(t, statsChecker)
	assert.NoError(t, err)

	killAndWaitCommand(t, cmdServer)
	killAndWaitCommand(t, cmdClient)
}

func TestListenEvent4(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	server := getNCCommand(t, "nc.openbsd")

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	ncSrvChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(server)).
		WithArguments(sm.Full("-unvlp 8081"))

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker("selfExec").
			WithProcess(selfChecker).
			WithParent(ec.NewProcessChecker()),
		ec.NewProcessExecChecker("serverExec").
			WithProcess(ncSrvChecker).
			WithParent(selfChecker),
		ec.NewProcessListenChecker("serverListen").
			WithProcess(ncSrvChecker).
			WithParent(selfChecker).
			WithIp(sm.Full("0.0.0.0")).
			WithPort(8081).
			WithProtocol(tetragon.SocketProtocol_UDP),
	)

	obs := getBasicUdpObserver(t, ctx)
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)

	readyWG.Wait()
	cmdServer := exec.Command(server, "-unvlp", "8081")
	assert.NoError(t, cmdServer.Start())
	time.Sleep(1000 * time.Millisecond)

	err := jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)

	killAndWaitCommand(t, cmdServer)
}

func TestUDPCLISwitch(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	oldEnableUDPValue := enterpriseOption.Config.EnableUDP
	enterpriseOption.Config.EnableUDP = true
	oldLayer3CLIEnableValue := enterpriseOption.Config.Layer3CLIEnable
	enterpriseOption.Config.Layer3CLIEnable = true
	t.Cleanup(func() {
		enterpriseOption.Config.EnableICMP = oldEnableUDPValue
		enterpriseOption.Config.Layer3CLIEnable = oldLayer3CLIEnableValue
	})

	server := getNCCommand(t, "nc.openbsd")

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	ncSrvChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(server)).
		WithArguments(sm.Full("-unvlp 8081"))

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker("selfExec").
			WithProcess(selfChecker).
			WithParent(ec.NewProcessChecker()),
		ec.NewProcessExecChecker("serverExec").
			WithProcess(ncSrvChecker).
			WithParent(selfChecker),
		ec.NewProcessListenChecker("serverListen").
			WithProcess(ncSrvChecker).
			WithParent(selfChecker).
			WithIp(sm.Full("0.0.0.0")).
			WithPort(8081).
			WithProtocol(tetragon.SocketProtocol_UDP),
	)

	obs := getNoConfigObserver(t, ctx, true)
	layer3.StartLayer3Progs(ctx)
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)

	readyWG.Wait()
	cmdServer := exec.Command(server, "-unvlp", "8081")
	assert.NoError(t, cmdServer.Start())
	time.Sleep(1000 * time.Millisecond)

	err := jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)

	killAndWaitCommand(t, cmdServer)
}

func testDisableConnectStatsConfig4(t *testing.T, CLISwitches bool, disableConnect bool, disableStats bool) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	if CLISwitches {
		oldEnableUDPValue := enterpriseOption.Config.EnableUDP
		enterpriseOption.Config.EnableUDP = true
		oldLayer3CLIEnableValue := enterpriseOption.Config.Layer3CLIEnable
		enterpriseOption.Config.Layer3CLIEnable = true
		t.Cleanup(func() {
			enterpriseOption.Config.EnableICMP = oldEnableUDPValue
			enterpriseOption.Config.Layer3CLIEnable = oldLayer3CLIEnableValue
		})
		layer3.EnableLayer3Progs()
	}

	server := getNCCommand(t, "nc.openbsd")
	client := server
	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	ncSrvChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(server)).
		WithArguments(sm.Full("-unvlp 8081"))

	ncCliChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(client)).
		WithArguments(sm.Full("-u 127.0.0.1 8081"))

	execChecker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker("selfExec").
			WithProcess(selfChecker).
			WithParent(ec.NewProcessChecker()),
		ec.NewProcessExecChecker("serverExec").
			WithProcess(ncSrvChecker).
			WithParent(selfChecker),
		ec.NewProcessExecChecker("clientExec").
			WithProcess(ncCliChecker).
			WithParent(selfChecker),
	)

	connectChecker := ec.NewUnorderedEventChecker(
		ec.NewProcessConnectChecker("serverConnect").
			WithSourceIp(sm.Full("127.0.0.1")).
			WithSourcePort(8081).
			WithDestinationIp(sm.Full("127.0.0.1")).
			WithProtocol(tetragon.SocketProtocol_UDP),
	)
	serverStatsChecker := ec.NewUnorderedEventChecker(
		ec.NewProcessSockStatsChecker("serverStats").
			WithSocket(ec.NewSockInfoChecker().
				WithProtocol(tetragon.SocketProtocol_UDP).
				WithSourceIp(sm.Full("127.0.0.1")).
				WithDestinationIp(sm.Full("127.0.0.1")).
				WithSourcePort(8081)),
	)

	obs := getUdpObserverDisableEvents(t, ctx, CLISwitches, disableConnect, true, true, disableStats)
	if CLISwitches {
		layer3.RunLayer3Progs(ctx)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)

	readyWG.Wait()
	cmdServer := exec.Command(server, "-unvlp", "8081")
	assert.NoError(t, cmdServer.Start())
	time.Sleep(1000 * time.Millisecond)

	cmdClient := exec.Command(client, "-u", "127.0.0.1", "8081")
	stdin, err := cmdClient.StdinPipe()
	assert.NoError(t, err)
	assert.NoError(t, cmdClient.Start())
	_, err = stdin.Write([]byte("hello"))
	assert.NoError(t, err)

	// Regardless of enabled/disabled network events, we should exepct the exec events
	err = jsonchecker.JsonTestCheck(t, execChecker)
	assert.NoError(t, err)

	connectErr := jsonchecker.JsonTestCheckExpect(t, connectChecker, disableConnect)
	assert.NoError(t, connectErr)

	statsErr := jsonchecker.JsonTestCheckExpect(t, serverStatsChecker, disableStats)
	assert.NoError(t, statsErr)

	killAndWaitCommand(t, cmdServer)
	killAndWaitCommand(t, cmdClient)
}

func TestDisableConnectStats4CLI(t *testing.T) {
	testDisableConnectStatsConfig4(t, true, true, true)
}

func TestNoDisableConnectStats4CLI(t *testing.T) {
	testDisableConnectStatsConfig4(t, true, false, false)
}

func TestDisableConnectStats4NoCLI(t *testing.T) {
	testDisableConnectStatsConfig4(t, false, true, true)
}

func TestNoDisableConnectStats4NoCLI(t *testing.T) {
	testDisableConnectStatsConfig4(t, false, false, false)
}

func TestConnectAfterStartEvent4(t *testing.T) {
	// FIXME: something broke this test case, but since it was never merged upstream this went
	// unnoticed... need to investigate
	t.Skip("This test is consistently failing at the moment, need to figure out why and fix it up.")

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	server := getNCCommand(t, "nc.openbsd")
	client := server

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	ncSrvChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(server)).
		WithArguments(sm.Full("-unvlp 8081"))

	ncCliChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(client)).
		WithArguments(sm.Full("-u 127.0.0.1 8081"))

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker("selfExec").
			WithProcess(selfChecker).
			WithParent(ec.NewProcessChecker()),
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
			WithSourcePort(8081).
			WithDestinationIp(sm.Full("127.0.0.1")).
			WithProtocol(tetragon.SocketProtocol_UDP),
		// Check client sock stats
		ec.NewProcessSockStatsChecker("clientStats").
			WithProcess(ncCliChecker).
			WithParent(selfChecker).
			WithSocket(ec.NewSockInfoChecker().
				WithProtocol(tetragon.SocketProtocol_UDP).
				WithDestinationIp(sm.Full("127.0.0.1")).
				WithDestinationPort(8081)).
			WithStats(ec.NewSocketStatsChecker().
				WithBytesSent(5).
				WithSegsOut(1)),
		// Check server sock stats
		ec.NewProcessSockStatsChecker("serverStats").
			WithProcess(ncSrvChecker).
			WithParent(selfChecker).
			WithSocket(ec.NewSockInfoChecker().
				WithProtocol(tetragon.SocketProtocol_UDP).
				WithSourceIp(sm.Full("127.0.0.1")).
				WithDestinationIp(sm.Full("127.0.0.1")).
				WithSourcePort(8081)).
			WithStats(ec.NewSocketStatsChecker().
				WithBytesReceived(5).
				WithSegsIn(1)),
	)

	cmdServer := exec.Command(server, "-unvlp", "8081")
	assert.NoError(t, cmdServer.Start())
	time.Sleep(1000 * time.Millisecond)

	obs := getBasicUdpObserver(t, ctx)
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)

	readyWG.Wait()
	cmdClient := exec.Command(client, "-u", "127.0.0.1", "8081")
	stdin, err := cmdClient.StdinPipe()
	assert.NoError(t, err)
	assert.NoError(t, cmdClient.Start())
	_, err = stdin.Write([]byte("hello"))
	assert.NoError(t, err)

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)

	killAndWaitCommand(t, cmdServer)
	killAndWaitCommand(t, cmdClient)
}

func TestUdpDetectLatency4(t *testing.T) {
	// timing related tests are unreliable currently. In lieu of a solution, let's
	// disable these tests.
	t.Skipf("Test disabled due to unreliable timing in CI")
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	server := getNCCommand(t, "nc.openbsd")
	client := server

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	ncSrvChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(server)).
		WithArguments(sm.Full("-unvlp 8081"))

	ncCliChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(client)).
		WithArguments(sm.Full("-u 127.0.0.1 8081"))

	clientStatsChecker := ec.NewProcessSockStatsChecker("clientStats").
		WithProcess(ncCliChecker).
		WithParent(selfChecker).
		WithSocket(ec.NewSockInfoChecker().
			WithProtocol(tetragon.SocketProtocol_UDP).
			WithDestinationIp(sm.Full("127.0.0.1")).
			WithDestinationPort(8081))

	serverStatsChecker := ec.NewProcessSockStatsChecker("serverStats").
		WithProcess(ncSrvChecker).
		WithParent(selfChecker).
		WithSocket(ec.NewSockInfoChecker().
			WithProtocol(tetragon.SocketProtocol_UDP).
			WithSourceIp(sm.Full("127.0.0.1")).
			WithDestinationIp(sm.Full("127.0.0.1")).
			WithSourcePort(8081)).
		WithStats(ec.NewSocketStatsChecker().
			WithLatency(ec.NewHistogramChecker().
				WithBuckets(ec.NewHistogramBucketListMatcher().
					WithValues(ec.NewHistogramBucketChecker().
						WithPercentile(1).
						WithCount(1)))))

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker("selfExec").
			WithProcess(selfChecker).
			WithParent(ec.NewProcessChecker()),
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
			WithSourcePort(8081).
			WithDestinationIp(sm.Full("127.0.0.1")).
			WithProtocol(tetragon.SocketProtocol_UDP),
		clientStatsChecker,
		serverStatsChecker,
	)

	obs := getUdpObserverWithLatencyDetection(t, ctx)
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)

	readyWG.Wait()
	cmdServer := exec.Command(server, "-unvlp", "8081")
	assert.NoError(t, cmdServer.Start())
	time.Sleep(1000 * time.Millisecond)

	cmdClient := exec.Command(client, "-u", "127.0.0.1", "8081")
	stdin, err := cmdClient.StdinPipe()
	assert.NoError(t, err)
	assert.NoError(t, cmdClient.Start())
	_, err = stdin.Write([]byte("hello"))
	assert.NoError(t, err)

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)

	killAndWaitCommand(t, cmdServer)
	killAndWaitCommand(t, cmdClient)
}

func TestUdpMulticast4(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	server := getSocatCommand(t, "socat")
	client := server

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	socatSrvChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(server)).
		WithArguments(sm.Full("- UDP4-LISTEN:8100,ip-add-membership=224.0.0.1:lo"))

	socatCliChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(client)).
		WithArguments(sm.Full("- UDP4-DATAGRAM:224.0.0.1:8100"))

	clientStatsChecker := ec.NewProcessSockStatsChecker("clientStats1").
		WithProcess(socatCliChecker).
		WithParent(selfChecker).
		WithSocket(ec.NewSockInfoChecker().
			WithProtocol(tetragon.SocketProtocol_UDP).
			WithDestinationIp(sm.Full("224.0.0.1")).
			WithDestinationPort(8100)).
		WithStats(ec.NewSocketStatsChecker().
			WithBytesSent(5).
			WithBytesReceived(0))

	serverStatsChecker := ec.NewProcessSockStatsChecker("serverStats").
		WithProcess(socatSrvChecker).
		WithParent(selfChecker).
		WithSocket(ec.NewSockInfoChecker().
			WithProtocol(tetragon.SocketProtocol_UDP).
			WithSourcePort(8100)).
		WithStats(ec.NewSocketStatsChecker().
			WithBytesReceived(5).
			WithBytesSent(0))

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker("selfExec").
			WithProcess(selfChecker).
			WithParent(ec.NewProcessChecker()),
		ec.NewProcessExecChecker("serverExec").
			WithProcess(socatSrvChecker).
			WithParent(selfChecker),
		ec.NewProcessExecChecker("clientExec").
			WithProcess(socatCliChecker).
			WithParent(selfChecker),
		ec.NewProcessConnectChecker("serverConnect").
			WithProcess(socatSrvChecker).
			WithParent(selfChecker).
			WithSourceIp(sm.Full("224.0.0.1")).
			WithSourcePort(8100).
			WithProtocol(tetragon.SocketProtocol_UDP),
		ec.NewProcessConnectChecker("clientConnect").
			WithProcess(socatCliChecker).
			WithParent(selfChecker).
			WithDestinationIp(sm.Full("224.0.0.1")).
			WithDestinationPort(8100).
			WithProtocol(tetragon.SocketProtocol_UDP),
		clientStatsChecker,
		serverStatsChecker,
	)

	obs := getBasicUdpObserver(t, ctx)
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)

	readyWG.Wait()
	cmdServer := exec.Command(server, "-", "UDP4-LISTEN:8100,ip-add-membership=224.0.0.1:lo")
	assert.NoError(t, cmdServer.Start())
	time.Sleep(1000 * time.Millisecond)

	cmdClient := exec.Command(client, "-", "UDP4-DATAGRAM:224.0.0.1:8100")
	stdinClient, err := cmdClient.StdinPipe()
	assert.NoError(t, err)
	assert.NoError(t, cmdClient.Start())
	_, err = stdinClient.Write([]byte("hello"))
	assert.NoError(t, err)
	time.Sleep(1000 * time.Millisecond)

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)

	killAndWaitCommand(t, cmdServer)
	killAndWaitCommand(t, cmdClient)
}
func TestUdpConnectEvent6(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	server := getNCCommand(t, "nc.openbsd")
	client := server

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	ncSrvChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(server)).
		WithArguments(sm.Full("-6unvlp 8081"))

	ncCliChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(client)).
		WithArguments(sm.Full("-6u ::1 8081"))

	clientStatsChecker := ec.NewProcessSockStatsChecker("clientStats").
		WithProcess(ncCliChecker).
		WithParent(selfChecker).
		WithSocket(ec.NewSockInfoChecker().
			WithProtocol(tetragon.SocketProtocol_UDP).
			WithDestinationIp(sm.Full("::1")).
			WithDestinationPort(8081))

	serverStatsChecker := ec.NewProcessSockStatsChecker("serverStats").
		WithProcess(ncSrvChecker).
		WithParent(selfChecker).
		WithSocket(ec.NewSockInfoChecker().
			WithProtocol(tetragon.SocketProtocol_UDP).
			WithSourceIp(sm.Full("::1")).
			WithDestinationIp(sm.Full("::1")).
			WithSourcePort(8081))

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker("selfExec").
			WithProcess(selfChecker).
			WithParent(ec.NewProcessChecker()),
		ec.NewProcessExecChecker("serverExec").
			WithProcess(ncSrvChecker).
			WithParent(selfChecker),
		ec.NewProcessExecChecker("clientExec").
			WithProcess(ncCliChecker).
			WithParent(selfChecker),
		ec.NewProcessConnectChecker("serverConnect").
			WithProcess(ncSrvChecker).
			WithParent(selfChecker).
			WithSourceIp(sm.Full("::1")).
			WithSourcePort(8081).
			WithDestinationIp(sm.Full("::1")).
			WithProtocol(tetragon.SocketProtocol_UDP),
		clientStatsChecker,
		serverStatsChecker,
	)

	// We need to check sockstats using a custom stateful checker since stats events can
	// be split up and so checking the individual events won't work. We need to instead
	// keep a cumulative count of the stats we have seen and compare them to expected
	// totals.
	var clientBytesSent uint64
	var clientSegsOut uint32
	var serverBytesReceived uint64
	var serverSegsIn uint32
	statsChecker := &ec.FnEventChecker{
		NextCheckFn: func(event_ ec.Event, _ *logrus.Logger) (bool, error) {
			event, ok := event_.(*tetragon.ProcessSockStats)
			if !ok {
				return false, fmt.Errorf("event is not a sockstats event")
			}

			if event.Stats == nil {
				return false, fmt.Errorf("event has no stats field")
			}

			if clientStatsChecker.Check(event) == nil {
				clientBytesSent += event.Stats.BytesSent
				clientSegsOut += event.Stats.SegsOut
				return false, nil
			}

			if serverStatsChecker.Check(event) == nil {
				serverBytesReceived += event.Stats.BytesReceived
				serverSegsIn += event.Stats.SegsIn
				return false, nil
			}

			return false, fmt.Errorf("sockstats event is neither from client nor server")
		},
		FinalCheckFn: func(_ *logrus.Logger) error {
			defer func() {
				clientBytesSent = 0
				clientSegsOut = 0
				serverBytesReceived = 0
				serverSegsIn = 0
			}()

			if clientBytesSent != 5 {
				return fmt.Errorf("Unexecpected clientBytesSent, wanted 5, got %d", clientBytesSent)
			}

			if clientSegsOut != 1 {
				return fmt.Errorf("Unexecpected clientSegsOut, wanted 1, got %d", clientSegsOut)
			}

			if serverBytesReceived != 5 {
				return fmt.Errorf("Unexecpected serverBytesReceived, wanted 5, got %d", serverBytesReceived)
			}

			if serverSegsIn != 1 {
				return fmt.Errorf("Unexecpected serverSegsIn, wanted 1, got %d", serverSegsIn)
			}

			return nil
		},
	}

	obs := getBasicUdpObserver(t, ctx)
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)

	readyWG.Wait()
	cmdServer := exec.Command(server, "-6unvlp", "8081")
	assert.NoError(t, cmdServer.Start())
	time.Sleep(1000 * time.Millisecond)

	cmdClient := exec.Command(client, "-6u", "::1", "8081")
	stdin, err := cmdClient.StdinPipe()
	assert.NoError(t, err)
	assert.NoError(t, cmdClient.Start())
	_, err = stdin.Write([]byte("hello"))
	assert.NoError(t, err)

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)

	err = jsonchecker.JsonTestCheck(t, statsChecker)
	assert.NoError(t, err)

	killAndWaitCommand(t, cmdServer)
	killAndWaitCommand(t, cmdClient)
}

func TestListenEvent6(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	server := getNCCommand(t, "nc.openbsd")

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	ncSrvChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(server)).
		WithArguments(sm.Full("-6unvlp 8081"))

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker("selfExec").
			WithProcess(selfChecker).
			WithParent(ec.NewProcessChecker()),
		ec.NewProcessExecChecker("serverExec").
			WithProcess(ncSrvChecker).
			WithParent(selfChecker),
		ec.NewProcessListenChecker("serverListen").
			WithProcess(ncSrvChecker).
			WithParent(selfChecker).
			WithIp(sm.Full("::")).
			WithPort(8081).
			WithProtocol(tetragon.SocketProtocol_UDP),
	)

	obs := getBasicUdpObserver(t, ctx)
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)

	readyWG.Wait()
	cmdServer := exec.Command(server, "-6unvlp", "8081")
	assert.NoError(t, cmdServer.Start())
	time.Sleep(1000 * time.Millisecond)

	err := jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)

	killAndWaitCommand(t, cmdServer)
}

func TestConnectAfterStartEvent6(t *testing.T) {
	// FIXME: something broke this test case, but since it was never merged upstream this went
	// unnoticed... need to investigate
	t.Skip("This test is consistently failing at the moment, need to figure out why and fix it up.")

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	server := getNCCommand(t, "nc.openbsd")
	client := server

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	ncSrvChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(server)).
		WithArguments(sm.Full("-6unvlp 8081"))

	ncCliChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(client)).
		WithArguments(sm.Full("-6u ::1 8081"))

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker("selfExec").
			WithProcess(selfChecker).
			WithParent(ec.NewProcessChecker()),
		ec.NewProcessExecChecker("serverExec").
			WithProcess(ncSrvChecker).
			WithParent(selfChecker),
		ec.NewProcessExecChecker("clientExec").
			WithProcess(ncCliChecker).
			WithParent(selfChecker),
		ec.NewProcessConnectChecker("serverConnect").
			WithProcess(ncSrvChecker).
			WithParent(selfChecker).
			WithSourceIp(sm.Full("::1")).
			WithSourcePort(8081).
			WithDestinationIp(sm.Full("::1")).
			WithProtocol(tetragon.SocketProtocol_UDP),
		// Check client sock stats
		ec.NewProcessSockStatsChecker("clientConnect").
			WithProcess(ncCliChecker).
			WithParent(selfChecker).
			WithSocket(ec.NewSockInfoChecker().
				WithProtocol(tetragon.SocketProtocol_UDP).
				WithDestinationIp(sm.Full("::1")).
				WithDestinationPort(8081)).
			WithStats(ec.NewSocketStatsChecker().
				WithBytesSent(5).
				WithSegsOut(1)),
		// Check server sock stats
		ec.NewProcessSockStatsChecker("clientStats").
			WithProcess(ncSrvChecker).
			WithParent(selfChecker).
			WithSocket(ec.NewSockInfoChecker().
				WithProtocol(tetragon.SocketProtocol_UDP).
				WithSourceIp(sm.Full("::1")).
				WithDestinationIp(sm.Full("::1")).
				WithSourcePort(8081)).
			WithStats(ec.NewSocketStatsChecker().
				WithBytesReceived(5).
				WithSegsIn(1)),
	)

	cmdServer := exec.Command(server, "-6unvlp", "8081")
	assert.NoError(t, cmdServer.Start())
	time.Sleep(1000 * time.Millisecond)

	obs := getBasicUdpObserver(t, ctx)
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)

	readyWG.Wait()
	cmdClient := exec.Command(client, "-6u", "::1", "8081")
	stdin, err := cmdClient.StdinPipe()
	assert.NoError(t, err)
	assert.NoError(t, cmdClient.Start())
	_, err = stdin.Write([]byte("hello"))
	assert.NoError(t, err)

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)

	killAndWaitCommand(t, cmdServer)
	killAndWaitCommand(t, cmdClient)
}

func testDnsEvents(t *testing.T, withQuestions bool) {
	if !utils.CGroupSKBAvailable() {
		t.Skipf("This test requires CGroup/SKB, skipping")
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	config := udpConfigWithoutDnsQuestions
	if withQuestions {
		config = udpConfigWithDnsQuestions
	}

	if err := observertesthelper.WriteConfigFile(testConfigFile, config); err != nil {
		t.Fatalf("WriteFile(%s): err %s", testConfigFile, err)
	}

	base := base.GetInitialSensor()
	obs, err := enterpriseoth.GetDefaultObserverWithBase(t, ctx, base, testConfigFile, runner.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserver error: %s", err)
	}

	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	curl4Checker := ec.NewProcessChecker().
		WithBinary(sm.Suffix("curl")).
		WithArguments(sm.Full("-4 https://www.google.com"))

	curl6Checker := ec.NewProcessChecker().
		WithBinary(sm.Suffix("curl")).
		WithArguments(sm.Full("-6 https://www.google.com"))

	checks := []ec.EventChecker{
		ec.NewProcessExecChecker("curl4Exec").
			WithProcess(curl4Checker).
			WithParent(selfChecker),
		ec.NewProcessConnectChecker("curl4Connect").
			WithProcess(curl4Checker).
			WithParent(selfChecker).
			WithDestinationPort(53).
			WithProtocol(tetragon.SocketProtocol_UDP),
		ec.NewProcessDnsChecker("curl4DnsReply").
			WithProcess(curl4Checker).
			WithParent(selfChecker).
			WithDns(ec.NewDnsInfoChecker().
				WithRcode(0).
				WithNames(ec.NewStringListMatcher().WithValues(sm.Full("www.google.com."))).
				// TODO: remove this check at some point once we stop populating
				// Dns.QuestionTypes
				WithQuestionTypes(ec.NewUint32ListMatcher().WithValues(1)).
				WithQueryTypes(ec.NewDnsTypeListMatcher().WithValues(ec.NewDnsTypeChecker(tetragon.DnsType_A))).
				// TODO: remove this check at some point once we stop populating
				// Dns.AnswerTypes
				WithAnswerTypes(ec.NewUint32ListMatcher().WithValues(1)).
				WithResponseTypes(ec.NewDnsTypeListMatcher().WithValues(ec.NewDnsTypeChecker(tetragon.DnsType_A))).
				WithIps(ec.NewStringListMatcher().
					WithOperator(listmatcher.Subset).
					// Match a valid IPv4 address
					WithValues(sm.Regex(`^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$`)))),
		ec.NewProcessExecChecker("curl6Exec").
			WithProcess(curl6Checker).
			WithParent(selfChecker),
		ec.NewProcessConnectChecker("curl6Connect").
			WithProcess(curl6Checker).
			WithParent(selfChecker).
			WithDestinationPort(53).
			WithProtocol(tetragon.SocketProtocol_UDP),
		ec.NewProcessDnsChecker("curl6DnsReply").
			WithProcess(curl6Checker).
			WithParent(selfChecker).
			WithDns(ec.NewDnsInfoChecker().
				WithRcode(0).
				WithNames(ec.NewStringListMatcher().WithValues(sm.Full("www.google.com."))).
				// TODO: remove this check at some point once we stop populating
				// Dns.QuestionTypes
				WithQuestionTypes(ec.NewUint32ListMatcher().WithValues(28)).
				WithQueryTypes(ec.NewDnsTypeListMatcher().WithValues(ec.NewDnsTypeChecker(tetragon.DnsType_AAAA))).
				// TODO: remove this check at some point once we stop populating
				// Dns.AnswerTypes
				WithAnswerTypes(ec.NewUint32ListMatcher().WithValues(28)).
				WithResponseTypes(ec.NewDnsTypeListMatcher().WithValues(ec.NewDnsTypeChecker(tetragon.DnsType_AAAA))).
				WithIps(ec.NewStringListMatcher().
					WithOperator(listmatcher.Subset).
					// Full IPv6 regex is probably too complicated, let's just see if it
					// contains a ::
					WithValues(sm.Contains(`::`)))),
	}

	questionChecks := []ec.EventChecker{
		// This is less specific than the reply above so it must be specified second
		ec.NewProcessDnsChecker("curl4DnsRequest").
			WithProcess(curl4Checker).
			WithParent(selfChecker).
			WithDns(ec.NewDnsInfoChecker().
				WithRcode(0).
				WithNames(ec.NewStringListMatcher().WithValues(sm.Full("www.google.com."))).
				// TODO: remove this check at some point once we stop populating
				// Dns.QuestionTypes
				WithQuestionTypes(ec.NewUint32ListMatcher().WithValues(1)).
				WithQueryTypes(ec.NewDnsTypeListMatcher().WithValues(ec.NewDnsTypeChecker(tetragon.DnsType_A)))),
		// This is less specific than the reply above so it must be specified second
		ec.NewProcessDnsChecker("curl6DnsRequest").
			WithProcess(curl6Checker).
			WithParent(selfChecker).
			WithDns(ec.NewDnsInfoChecker().
				WithRcode(0).
				WithNames(ec.NewStringListMatcher().WithValues(sm.Full("www.google.com."))).
				WithQueryTypes(ec.NewDnsTypeListMatcher().WithValues(ec.NewDnsTypeChecker(tetragon.DnsType_AAAA)))),
	}

	if withQuestions {
		checks = append(checks, questionChecks...)
	}

	checker := ec.NewUnorderedEventChecker(checks...)

	curl4 := exec.Command("curl", "-4", "https://www.google.com")
	assert.NoError(t, curl4.Start())

	curl6 := exec.Command("curl", "-6", "https://www.google.com")
	assert.NoError(t, curl6.Start())

	// Adjust JSON checker delay to account for events that might be coming in more
	// slowly in 5.4 kernels
	oldDelay := jsonchecker.RetryDelay
	jsonchecker.RetryDelay = oldDelay * 2
	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
	jsonchecker.RetryDelay = oldDelay
}

func TestDnsEventsWithQuestions(t *testing.T) {
	testDnsEvents(t, true)
}

func TestDnsEventsWithoutQuestions(t *testing.T) {
	testDnsEvents(t, false)
}

func testDisableCloseConfig(t *testing.T, disableClose bool) {
	bpf.CheckOrMountCgroup2()

	serverProcess := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary)).
		WithArguments(sm.Full("-udpServer"))

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessCloseChecker("serverClose").
			WithProcess(serverProcess),
	)

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	disableCloseConfig := udpL7ConfigDisableClose + strconv.FormatBool(disableClose)
	if err := observertesthelper.WriteConfigFile(testConfigFile, disableCloseConfig); err != nil {
		t.Fatalf("WriteFile(%s): err %s", testConfigFile, err)
	}
	base := base.GetInitialSensor()
	obs, err := enterpriseoth.GetDefaultObserverWithBase(t, ctx, base, testConfigFile, runner.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserver error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	serverCmd := exec.Command(os.Args[0], "-udpServer")
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
			t.Fatal("received empty line from UDP server")
		}
		if strings.HasPrefix(string(line), "NotReady") {
			t.Fatalf("UDP server failed to start: '%s'", string(line))
		}
	}

	serverPid := uint32(serverCmd.Process.Pid)

	clientCmd := exec.Command(os.Args[0], "-udpLayer7Client")
	clientCmd.Stdout = os.Stderr
	clientCmd.Stderr = os.Stderr
	err = clientCmd.Run()
	assert.NoError(t, err, "cannot start client")

	killAndWaitCommand(t, serverCmd)

	quit := false
	for !quit {
		_, err = os.Stat(fmt.Sprintf("/proc/%d", serverPid))
		if err != nil {
			quit = true
		}
		time.Sleep(10 * time.Millisecond)
	}

	err = jsonchecker.JsonTestCheckExpect(t, checker, disableClose)
	assert.NoError(t, err)

	killAndWaitCommand(t, clientCmd)
}

func TestDisableClose(t *testing.T) {
	testDisableCloseConfig(t, true)
}

func TestNoDisableClose(t *testing.T) {
	testDisableCloseConfig(t, false)
}

func testDisableListenConfig(t *testing.T, disableListen bool) {
	bpf.CheckOrMountCgroup2()

	serverProcess := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary)).
		WithArguments(sm.Full("-udpServer"))

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessListenChecker("serverListen").
			WithProcess(serverProcess),
	)

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	disableListenConfig := udpL7ConfigDisableListen + strconv.FormatBool(disableListen)
	if err := observertesthelper.WriteConfigFile(testConfigFile, disableListenConfig); err != nil {
		t.Fatalf("WriteFile(%s): err %s", testConfigFile, err)
	}
	base := base.GetInitialSensor()
	obs, err := enterpriseoth.GetDefaultObserverWithBase(t, ctx, base, testConfigFile, runner.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserver error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	serverCmd := exec.Command(os.Args[0], "-udpServer")
	serverOutput, err := serverCmd.StdoutPipe()
	require.NoError(t, err, "could not connect to server output pipe")
	serverCmd.Stderr = os.Stderr

	err = serverCmd.Start()
	require.NoError(t, err, "cannot start server")

	serverBuf := bufio.NewReader(serverOutput)
	serverBuf.ReadLine()

	err = jsonchecker.JsonTestCheckExpect(t, checker, disableListen)

	killAndWaitCommand(t, serverCmd)

	assert.NoError(t, err)
}

func TestDisableListen(t *testing.T) {
	testDisableListenConfig(t, true)
}

func TestNoDisableListen(t *testing.T) {
	testDisableListenConfig(t, false)
}

func udpGcMetricGet(ty socketmetrics.UDPGCType) float64 {
	// ToFloat64 is computationally expensive so only use for testing
	counter := socketmetrics.SocketStatsUDPGC.WithLabelValues(socketmetrics.UDPGCTypeStrings[ty])
	return testutil.ToFloat64(counter)
}

func testGC(t *testing.T, defaultInterval bool, interval int, numExpectedGCRuns int) {
	t.Skip("Disabled due to unstable timing on CI runners.")
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	server := getNCCommand(t, "nc.openbsd")
	client := server

	GCTestConfig := udpConfigBasic
	if !defaultInterval {
		GCTestConfig += "\n      statsInterval: " + strconv.Itoa(interval)
	}

	if err := observertesthelper.WriteConfigFile(testConfigFile, GCTestConfig); err != nil {
		t.Fatalf("WriteFile(%s): err %s", testConfigFile, err)
	}
	base := base.GetInitialSensor()
	obs, err := enterpriseoth.GetDefaultObserverWithBase(t, ctx, base, testConfigFile, runner.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserver error: %s", err)
	}

	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)

	readyWG.Wait()
	cmdServer := exec.Command(server, "-unvlp", "8081")
	assert.NoError(t, cmdServer.Start())
	time.Sleep(1000 * time.Millisecond)

	cmdClient := exec.Command(client, "-u", "127.0.0.1", "8081")
	stdin, err := cmdClient.StdinPipe()
	assert.NoError(t, err)
	assert.NoError(t, cmdClient.Start())
	_, err = stdin.Write([]byte("hello"))
	assert.NoError(t, err)

	GCTickerStart := udpGcMetricGet(socketmetrics.UDPGCTypeTicker)

	defaultGCInterval := 60
	var timeToRun int
	if defaultInterval {
		timeToRun = defaultGCInterval * numExpectedGCRuns
	} else {
		timeToRun = interval * numExpectedGCRuns
	}

	time.Sleep(time.Duration(timeToRun) * time.Second)

	GCTickerEnd := udpGcMetricGet(socketmetrics.UDPGCTypeTicker)
	numActualGCRuns := int(GCTickerEnd - GCTickerStart)

	// Allow +- 1 error to prevent flakes
	assert.InDelta(t, numExpectedGCRuns, numActualGCRuns, 1.0,
		"Expected number of runs: %d, actual number: %d",
		numExpectedGCRuns, numActualGCRuns)

	killAndWaitCommand(t, cmdServer)
	killAndWaitCommand(t, cmdClient)
}

func TestGCDefaultInterval(t *testing.T) {
	testGC(t, true, 60, 2)
}

func TestGCWithNonzeroInterval(t *testing.T) {
	testGC(t, false, 5, 4)
}

// FIXME: net io_uring test seems to time out on ARM.
func TestUdpIOUringConnectEvent(t *testing.T) {
	if !utils.CGroupSKBAvailable() {
		t.Skipf("This test requires CGroup/SKB, skipping")
	}
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "x86_64" {
		t.Skipf("Test seems to time out on ARM")
	}
	hostname, err := os.Hostname()
	if err == nil && strings.Contains(hostname, "rhel") {
		t.Skipf("This test is problematic on RHEL, skipping")
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	server := testutils.RepoRootPath("contrib/tester-progs/io_uring/udp_iouring_server")
	client := getNCCommand(t, "nc.openbsd")

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	ncSrvChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(server))

	ncCliChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(client)).
		WithArguments(sm.Full("-u 127.0.0.1 8000"))

	clientStatsChecker := ec.NewProcessSockStatsChecker("clientStats").
		WithProcess(ncCliChecker).
		WithParent(selfChecker).
		WithSocket(ec.NewSockInfoChecker().
			WithProtocol(tetragon.SocketProtocol_UDP).
			WithDestinationIp(sm.Full("127.0.0.1")).
			WithDestinationPort(8000))

	serverStatsChecker := ec.NewProcessSockStatsChecker("serverStats").
		WithProcess(ncSrvChecker).
		WithParent(selfChecker).
		WithSocket(ec.NewSockInfoChecker().
			WithProtocol(tetragon.SocketProtocol_UDP).
			WithSourceIp(sm.Full("127.0.0.1")).
			WithDestinationIp(sm.Full("127.0.0.1")).
			WithSourcePort(8000))

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker("selfExec").
			WithProcess(selfChecker).
			WithParent(ec.NewProcessChecker()),
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
			WithSourcePort(8000).
			WithDestinationIp(sm.Full("127.0.0.1")).
			WithProtocol(tetragon.SocketProtocol_UDP),
		clientStatsChecker,
		serverStatsChecker,
	)

	// We need to check sockstats using a custom stateful checker since stats events can
	// be split up and so checking the individual events won't work. We need to instead
	// keep a cumulative count of the stats we have seen and compare them to expected
	// totals.
	var clientBytesSent uint64
	var clientBytesReceived uint64
	var clientSegsOut uint32
	var clientSegsIn uint32
	var serverBytesSent uint64
	var serverBytesReceived uint64
	var serverSegsOut uint32
	var serverSegsIn uint32

	statsChecker := &ec.FnEventChecker{
		NextCheckFn: func(event_ ec.Event, _ *logrus.Logger) (bool, error) {
			event, ok := event_.(*tetragon.ProcessSockStats)
			if !ok {
				return false, fmt.Errorf("event is not a sockstats event")
			}

			if event.Stats == nil {
				return false, fmt.Errorf("event has no stats field")
			}

			if clientStatsChecker.Check(event) == nil {
				clientBytesSent += event.Stats.BytesSent
				clientBytesReceived += event.Stats.BytesReceived
				clientSegsIn += event.Stats.SegsIn
				clientSegsOut += event.Stats.SegsOut
				return false, nil
			}

			if serverStatsChecker.Check(event) == nil {
				serverBytesSent += event.Stats.BytesSent
				serverBytesReceived += event.Stats.BytesReceived
				serverSegsIn += event.Stats.SegsIn
				serverSegsOut += event.Stats.SegsOut
				return false, nil
			}

			return false, fmt.Errorf("sockstats event is neither from client nor server")
		},
		FinalCheckFn: func(_ *logrus.Logger) error {
			defer func() {
				clientBytesSent = 0
				clientBytesReceived = 0
				clientSegsIn = 0
				clientSegsOut = 0
				serverBytesSent = 0
				serverBytesReceived = 0
				serverSegsIn = 0
				serverSegsOut = 0
			}()

			if clientBytesSent != 5 {
				return fmt.Errorf("Unexecpected clientBytesSent, wanted 5, got %d", clientBytesSent)
			}

			if clientBytesReceived != 5 {
				return fmt.Errorf("Unexecpected clientBytesReceived, wanted 5, got %d", clientBytesReceived)
			}

			if clientSegsIn != 1 {
				return fmt.Errorf("Unexecpected clientSegsIn, wanted 1, got %d", clientSegsIn)
			}

			if clientSegsOut != 1 {
				return fmt.Errorf("Unexecpected clientSegsOut, wanted 1, got %d", clientSegsOut)
			}

			if serverBytesSent != 5 {
				return fmt.Errorf("Unexecpected serverBytesSent, wanted 5, got %d", serverBytesSent)
			}

			if serverBytesReceived != 5 {
				return fmt.Errorf("Unexecpected serverBytesReceived, wanted 5, got %d", serverBytesReceived)
			}

			if serverSegsIn != 1 {
				return fmt.Errorf("Unexecpected serverSegsIn, wanted 1, got %d", serverSegsIn)
			}

			if serverSegsOut != 1 {
				return fmt.Errorf("Unexecpected serverSegsOut, wanted 1, got %d", serverSegsOut)
			}

			return nil
		},
	}

	obs := getBasicUdpObserver(t, ctx)
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)

	readyWG.Wait()
	cmdServer := exec.Command(server)
	serverOutput, err := cmdServer.StdoutPipe()
	require.NoError(t, err, "could not connect to server output pipe")
	cmdServer.Stderr = os.Stderr

	err = cmdServer.Start()
	require.NoError(t, err, "cannot start server")

	serverBuf := bufio.NewReader(serverOutput)
	var line []byte
	for string(line) != "Ready" {
		line, _, err = serverBuf.ReadLine()
		if err != nil {
			killAndWaitCommand(t, cmdServer)
			t.Fatal(err)
		}
		if len(line) == 0 {
			killAndWaitCommand(t, cmdServer)
			t.Fatal("received empty line from UDP server")
		}
		if strings.HasPrefix(string(line), "NotReady") {
			t.Fatalf("UDP server failed to start: '%s'", string(line))
		}
	}

	serverPid := uint32(cmdServer.Process.Pid)
	logger.GetLogger().WithField("ServerPid", serverPid).Info("Running")

	cmdClient := exec.Command(client, "-u", "127.0.0.1", "8000")
	stdin, err := cmdClient.StdinPipe()
	assert.NoError(t, err)
	assert.NoError(t, cmdClient.Start())
	_, err = stdin.Write([]byte("hello"))
	assert.NoError(t, err)

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)

	err = jsonchecker.JsonTestCheck(t, statsChecker)
	assert.NoError(t, err)

	killAndWaitCommand(t, cmdServer)
	killAndWaitCommand(t, cmdClient)
}

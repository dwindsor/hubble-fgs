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
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/api/v1/tetragon"
	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/pkg/bpf"
	ossBTF "github.com/cilium/tetragon/pkg/btf"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/matchers/durationmatcher"
	"github.com/cilium/tetragon/pkg/matchers/listmatcher"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/sirupsen/logrus"

	"github.com/cilium/tetragon/pkg/jsonchecker"
	fgsBTF "github.com/isovalent/hubble-fgs/pkg/btf"
	"github.com/isovalent/hubble-fgs/pkg/sensors/base"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3/internal/udp"
	"github.com/isovalent/hubble-fgs/pkg/sensors/networkWatermarksEvents"
	"github.com/isovalent/hubble-fgs/pkg/testutils/runner"

	_ "github.com/isovalent/hubble-fgs/pkg/sensors/exec"
	//_ "github.com/isovalent/hubble-fgs/pkg/sensors/sockmap"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	tus "github.com/cilium/tetragon/pkg/testutils/sensors"

	"github.com/isovalent/hubble-fgs/pkg/metrics/socketmetrics"
	enterpriseoth "github.com/isovalent/hubble-fgs/pkg/observer/observertesthelper"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

var (
	udpWatermarksClient bool
	udpLayer7Client     bool
	udpServer           bool
	udpIouServer        bool
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
	if v := "5.4.0"; !kernels.MinKernelVersion(v) {
		t.Skipf("Minimum kernel version (%v) not met, skipping", v)
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
	for string(line[:]) != "Ready" {
		line, _, err = serverBuf.ReadLine()
		if err != nil {
			killAndWaitCommand(t, serverCmd)
			panic(err)
		}
		if len(line) == 0 {
			killAndWaitCommand(t, serverCmd)
			panic(fmt.Errorf("received empty line from UDP server"))
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
	if v := "5.4.0"; !kernels.MinKernelVersion(v) {
		t.Skipf("Minimum kernel version (%v) not met, skipping", v)
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
	for string(line[:]) != "Ready" {
		line, _, err = serverBuf.ReadLine()
		if err != nil {
			killAndWaitCommand(t, serverCmd)
			panic(err)
		}
		if len(line) == 0 {
			killAndWaitCommand(t, serverCmd)
			panic(fmt.Errorf("received empty line from UDP server"))
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
func getUdpObserver(t *testing.T, ctx context.Context, config string) *observer.Observer {
	if err := observertesthelper.WriteConfigFile(testConfigFile, config); err != nil {
		t.Fatalf("WriteFile(%s): err %s", testConfigFile, err)
	}

	base := base.GetInitialSensor()
	obs, err := enterpriseoth.GetDefaultObserverWithBase(t, ctx, base, testConfigFile, runner.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserver error: %s", err)
	}
	return obs
}

func getBasicUdpObserver(t *testing.T, ctx context.Context) *observer.Observer {
	return getUdpObserver(t, ctx, udpBasicConfig)
}

func getUdpObserverWithLatencyDetection(t *testing.T, ctx context.Context) *observer.Observer {
	return getUdpObserver(t, ctx, udpConfigWithLatencyDetection)
}

func getUdpObserverDisableEvents(t *testing.T, ctx context.Context, disableConnect bool, disableListen bool, disableClose bool, disableStats bool) *observer.Observer {
	eventDisableConfig := `
      disableEvents:
`
	eventDisableConfig += "\n        disableConnect: " + strconv.FormatBool(disableConnect)
	eventDisableConfig += "\n        disableListen: " + strconv.FormatBool(disableListen)
	eventDisableConfig += "\n        disableClose: " + strconv.FormatBool(disableClose)
	eventDisableConfig += "\n        disableStats: " + strconv.FormatBool(disableStats)

	udpDisableEventsConfig := udpBasicConfig + eventDisableConfig
	return getUdpObserver(t, ctx, udpDisableEventsConfig)
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
	var clientBytesSubmitted uint64
	var clientSegsOut uint32
	var clientSegsSubmitted uint32
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
				clientBytesSubmitted += event.Stats.BytesSubmitted
				clientSegsOut += event.Stats.SegsOut
				clientSegsSubmitted += event.Stats.SegsSubmitted
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
				clientBytesSubmitted = 0
				clientSegsOut = 0
				clientSegsSubmitted = 0
				serverBytesReceived = 0
				serverSegsIn = 0
			}()

			if clientBytesSent != 5 {
				return fmt.Errorf("Unexecpected clientBytesSent, wanted 5, got %d", clientBytesSent)
			}

			if clientBytesSubmitted != 5 {
				return fmt.Errorf("Unexecpected clientBytesSubmitted, wanted 5, got %d", clientBytesSubmitted)
			}

			if clientSegsOut != 1 {
				return fmt.Errorf("Unexecpected clientSegsOut, wanted 1, got %d", clientSegsOut)
			}

			if clientSegsSubmitted != 1 {
				return fmt.Errorf("Unexecpected clientSegsSubmitted, wanted 1, got %d", clientSegsSubmitted)
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

func testDisableConnectStatsConfig4(t *testing.T, disableConnect bool, disableStats bool) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	server := getNCCommand(t, "nc.openbsd")
	client := server

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

	obs := getUdpObserverDisableEvents(t, ctx, disableConnect, true, true, disableStats)
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

	connectErr := jsonchecker.JsonTestCheckExpect(t, connectChecker, disableConnect)
	assert.NoError(t, connectErr)

	statsErr := jsonchecker.JsonTestCheckExpect(t, serverStatsChecker, disableStats)
	assert.NoError(t, statsErr)

	killAndWaitCommand(t, cmdServer)
	killAndWaitCommand(t, cmdClient)
}

func TestDisableConnectStats4(t *testing.T) {
	testDisableConnectStatsConfig4(t, true, true)
}

func TestNoDisableConnectStats4(t *testing.T) {
	testDisableConnectStatsConfig4(t, false, false)
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
				WithBytesSubmitted(5).
				WithSegsOut(1).
				WithSegsSubmitted(1)),
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

func TestLoadUdpSensor(t *testing.T) {
	var sensorProgs []tus.SensorProg
	var sensorMaps []tus.SensorMap

	spec, err := ossBTF.NewBTF()
	useIPv6InitHook := false
	if err != nil {
		logger.GetLogger().WithError(err).Warn("GetCachedBTF failed")
	} else {
		if spec == nil {
			logger.GetLogger().Warn("GetCachedBTF returned nil")
		} else {
			_, err := fgsBTF.GetFuncProto(spec, udp.SkUdpAlloc6.Attach, false)
			if err == nil {
				useIPv6InitHook = true
			}
		}
	}

	if !kernels.MinKernelVersion("5.4.0") { // 4.19 - <5.4
		sensorProgs = []tus.SensorProg{
			0: tus.SensorProg{Name: "tg_udp_init_sock", Type: ebpf.Kprobe},
			1: tus.SensorProg{Name: "tg_udp_destroy_sock", Type: ebpf.Kprobe},
			2: tus.SensorProg{Name: "tg_inet_lazy_send_kp", Type: ebpf.Kprobe},
			3: tus.SensorProg{Name: "tg_udp4_send_kprobe", Type: ebpf.Kprobe},
			4: tus.SensorProg{Name: "tg_udp4_sendret_kprobe", Type: ebpf.Kprobe},
			5: tus.SensorProg{Name: "tg_udp6_send_kprobe", Type: ebpf.Kprobe},
			6: tus.SensorProg{Name: "tg_udp6_sendret_kprobe", Type: ebpf.Kprobe},
			7: tus.SensorProg{Name: "tg_udp_recv_kprobe", Type: ebpf.Kprobe},
			8: tus.SensorProg{Name: "tg_egress_timestamp", Type: ebpf.SchedCLS},
			9: tus.SensorProg{Name: "tg_udp_bind_sock", Type: ebpf.Kprobe},
		}
		sensorMaps = []tus.SensorMap{
			// udp4_send_lazy_kprobe, udp4_sendret_lazy_kprobe, udp6_send_lazy_kprobe,
			// udp6_sendret_lazy_kprobe, udp_recv_lazy_kprobe
			tus.SensorMap{Name: "tg_udp_retprobe_map", Progs: []uint{3, 4, 5, 6}},

			// udp4_send_lazy_kprobe, udp4_sendret_lazy_kprobe, udp6_send_lazy_kprobe,
			// udp6_sendret_lazy_kprobe, udp_recv_lazy_kprobe
			tus.SensorMap{Name: "tg_udp_retprobe_map_stats", Progs: []uint{3, 4, 5, 6}},

			// inet_lazy_send_kp, udp4_sendret_lazy_kprobe, udp6_sendret_lazy_kprobe,
			// udp_recv_lazy_kprobe
			tus.SensorMap{Name: "tg_udp_map", Progs: []uint{2, 4, 6, 7}},
			tus.SensorMap{Name: "tg_udp_config_map", Progs: []uint{2}},

			tus.SensorMap{Name: "tg_latency_config_map", Progs: []uint{2, 8}},

			// udp_destroy_sock, inet_lazy_send_kp,
			tus.SensorMap{Name: "tg_socket_tuple_map", Progs: []uint{1}},
			tus.SensorMap{Name: "tg_socket_tuple_map_stats", Progs: []uint{1}},
		}

		if useIPv6InitHook {
			sensorProgs = append(sensorProgs, tus.SensorProg{Name: "tg_udpv6_init_sock", Type: ebpf.Kprobe})
			sensorMaps = append(sensorMaps, []tus.SensorMap{
				// udp_init_sock, udp4_sendret_lazy_kprobe, udp6_sendret_lazy_kprobe, udp_recv_lazy_kprobe
				tus.SensorMap{Name: "execve_map", Progs: []uint{0, 2, 4, 6, 7, 10}},

				// udp_init_sock, udp_destroy_sock, inet_lazy_send_kp (not stats), udp4_sendret_lazy_kprobe,
				// udp6_sendret_lazy_kprobe, udp_recv_lazy_kprobe
				tus.SensorMap{Name: "tg_socket_map", Progs: []uint{0, 1, 2, 4, 6, 7, 9, 10}},
				tus.SensorMap{Name: "tg_socket_map_stats", Progs: []uint{0, 1, 4, 6, 7, 10}},

				// udp_init_sock, udp_destroy_sock, inet_lazy_send_kp, udp4_sendret_lazy_kprobe,
				// udp6_sendret_lazy_kprobe, udp_recv_lazy_kprobe
				tus.SensorMap{Name: "tcpmon_map", Progs: []uint{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}},
			}...)
		} else {
			sensorMaps = append(sensorMaps, []tus.SensorMap{
				// udp_init_sock, udp4_sendret_lazy_kprobe, udp6_sendret_lazy_kprobe, udp_recv_lazy_kprobe
				tus.SensorMap{Name: "execve_map", Progs: []uint{0, 2, 4, 6, 7}},

				// udp_init_sock, udp_destroy_sock, inet_lazy_send_kp (not stats), udp4_sendret_lazy_kprobe,
				// udp6_sendret_lazy_kprobe, udp_recv_lazy_kprobe
				tus.SensorMap{Name: "tg_socket_map", Progs: []uint{0, 1, 2, 4, 6, 7, 9}},
				tus.SensorMap{Name: "tg_socket_map_stats", Progs: []uint{0, 1, 4, 6, 7}},

				// udp_init_sock, udp_destroy_sock, inet_lazy_send_kp, udp4_sendret_lazy_kprobe,
				// udp6_sendret_lazy_kprobe, udp_recv_lazy_kprobe
				tus.SensorMap{Name: "tcpmon_map", Progs: []uint{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}},
			}...)
		}
	} else if !kernels.MinKernelVersion("5.10.0") { // 5.4 - <5.10
		sensorProgs = []tus.SensorProg{
			0:  tus.SensorProg{Name: "tg_udp_init_sock", Type: ebpf.Kprobe},
			1:  tus.SensorProg{Name: "tg_udp_destroy_sock", Type: ebpf.Kprobe},
			2:  tus.SensorProg{Name: "tg_inet_lazy_send", Type: ebpf.CGroupSKB},
			3:  tus.SensorProg{Name: "tg_inet_lazy_recv", Type: ebpf.CGroupSKB},
			4:  tus.SensorProg{Name: "tg_udp4_send_kprobe", Type: ebpf.Kprobe},
			5:  tus.SensorProg{Name: "tg_udp4_sendret_kprobe", Type: ebpf.Kprobe},
			6:  tus.SensorProg{Name: "tg_udp6_send_kprobe", Type: ebpf.Kprobe},
			7:  tus.SensorProg{Name: "tg_udp6_sendret_kprobe", Type: ebpf.Kprobe},
			8:  tus.SensorProg{Name: "tg_udp_recv_kprobe", Type: ebpf.Kprobe},
			9:  tus.SensorProg{Name: "tg_egress_timestamp", Type: ebpf.SchedCLS},
			10: tus.SensorProg{Name: "tg_udp_bind_sock", Type: ebpf.Kprobe},
		}
		sensorMaps = []tus.SensorMap{
			// udp4_send_lazy_kprobe, udp4_sendret_lazy_kprobe, udp6_send_lazy_kprobe,
			// udp6_sendret_lazy_kprobe, udp_recv_lazy_kprobe
			tus.SensorMap{Name: "tg_udp_retprobe_map", Progs: []uint{4, 5, 6, 7}},

			// udp4_send_lazy_kprobe, udp4_sendret_lazy_kprobe, udp6_send_lazy_kprobe,
			// udp6_sendret_lazy_kprobe, udp_recv_lazy_kprobe
			tus.SensorMap{Name: "tg_udp_retprobe_map_stats", Progs: []uint{4, 5, 6, 7}},

			// inet_lazy_send, inet_lazy_recv, udp4_sendret_lazy_kprobe, udp6_sendret_lazy_kprobe,
			// udp_recv_lazy_kprobe
			tus.SensorMap{Name: "tg_udp_map", Progs: []uint{2, 3, 5, 7, 8}},
			tus.SensorMap{Name: "tg_udp_config_map", Progs: []uint{2, 3}},

			tus.SensorMap{Name: "tg_latency_config_map", Progs: []uint{3, 9}},

			// udp_destroy_sock, inet_lazy_send, inet_lazy_recv
			tus.SensorMap{Name: "tg_socket_tuple_map", Progs: []uint{1, 2, 3, 5, 7, 8}},
			tus.SensorMap{Name: "tg_socket_tuple_map_stats", Progs: []uint{1, 2, 3, 5, 7, 8}},
			tus.SensorMap{Name: "tg_socket_tuple_hint_map", Progs: []uint{1, 2, 3, 5, 7, 8}},
		}

		if useIPv6InitHook {
			sensorProgs = append(sensorProgs, tus.SensorProg{Name: "tg_udpv6_init_sock", Type: ebpf.Kprobe})
			sensorMaps = append(sensorMaps, []tus.SensorMap{
				// udp_init_sock, udp4_sendret_lazy_kprobe, udp6_sendret_lazy_kprobe, udp_recv_lazy_kprobe
				tus.SensorMap{Name: "execve_map", Progs: []uint{0, 2, 3, 5, 7, 8, 11}},

				// udp_init_sock, udp_destroy_sock, inet_lazy_send (not stats), inet_lazy_recv (not stats),
				// udp4_sendret_lazy_kprobe, udp6_sendret_lazy_kprobe, udp_recv_lazy_kprobe
				tus.SensorMap{Name: "tg_socket_map", Progs: []uint{0, 1, 2, 3, 5, 7, 8, 10, 11}},
				tus.SensorMap{Name: "tg_socket_map_stats", Progs: []uint{0, 1, 5, 7, 8, 11}},

				// udp_init_sock, udp_destroy_sock, inet_lazy_send, inet_lazy_recv, udp4_sendret_lazy_kprobe,
				// udp6_sendret_lazy_kprobe, udp_recv_lazy_kprobe
				tus.SensorMap{Name: "tcpmon_map", Progs: []uint{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}},
			}...)
		} else {
			sensorMaps = append(sensorMaps, []tus.SensorMap{
				// udp_init_sock, udp4_sendret_lazy_kprobe, udp6_sendret_lazy_kprobe, udp_recv_lazy_kprobe
				tus.SensorMap{Name: "execve_map", Progs: []uint{0, 2, 3, 5, 7, 8}},

				// udp_init_sock, udp_destroy_sock, inet_lazy_send (not stats), inet_lazy_recv (not stats),
				// udp4_sendret_lazy_kprobe, udp6_sendret_lazy_kprobe, udp_recv_lazy_kprobe
				tus.SensorMap{Name: "tg_socket_map", Progs: []uint{0, 1, 2, 3, 5, 7, 8, 10}},
				tus.SensorMap{Name: "tg_socket_map_stats", Progs: []uint{0, 1, 5, 7, 8}},

				// udp_init_sock, udp_destroy_sock, inet_lazy_send, inet_lazy_recv, udp4_sendret_lazy_kprobe,
				// udp6_sendret_lazy_kprobe, udp_recv_lazy_kprobe
				tus.SensorMap{Name: "tcpmon_map", Progs: []uint{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}},
			}...)
		}
	} else { // 5.10+
		sensorProgs = []tus.SensorProg{
			0:  tus.SensorProg{Name: "tg_udp_init_sock", Type: ebpf.Kprobe},
			1:  tus.SensorProg{Name: "tg_udp_destroy_sock", Type: ebpf.Kprobe},
			2:  tus.SensorProg{Name: "tg_inet_send", Type: ebpf.CGroupSKB},
			3:  tus.SensorProg{Name: "tg_inet_recv", Type: ebpf.CGroupSKB},
			4:  tus.SensorProg{Name: "tg_udp4_send_kprobe", Type: ebpf.Kprobe},
			5:  tus.SensorProg{Name: "tg_udp4_sendret_kprobe", Type: ebpf.Kprobe},
			6:  tus.SensorProg{Name: "tg_udp6_send_kprobe", Type: ebpf.Kprobe},
			7:  tus.SensorProg{Name: "tg_udp6_sendret_kprobe", Type: ebpf.Kprobe},
			8:  tus.SensorProg{Name: "tg_udp_recv_kprobe", Type: ebpf.Kprobe},
			9:  tus.SensorProg{Name: "tg_egress_timestamp", Type: ebpf.SchedCLS},
			10: tus.SensorProg{Name: "tg_udp_bind_sock", Type: ebpf.Kprobe},
			11: tus.SensorProg{Name: "tg_udp_bind_dummy4", Type: ebpf.CGroupSock},
			12: tus.SensorProg{Name: "tg_udp_bind_dummy6", Type: ebpf.CGroupSock},
		}
		sensorMaps = []tus.SensorMap{
			// udp4_send_lazy_kprobe, udp4_sendret_lazy_kprobe, udp6_send_lazy_kprobe,
			// udp6_sendret_lazy_kprobe, udp_recv_lazy_kprobe
			tus.SensorMap{Name: "tg_udp_retprobe_map", Progs: []uint{4, 5, 6, 7}},

			// udp4_send_lazy_kprobe, udp4_sendret_lazy_kprobe, udp6_send_lazy_kprobe,
			// udp6_sendret_lazy_kprobe, udp_recv_lazy_kprobe
			tus.SensorMap{Name: "tg_udp_retprobe_map_stats", Progs: []uint{4, 5, 6, 7}},

			// inet_lazy_send, inet_lazy_recv, udp4_sendret_lazy_kprobe, udp6_sendret_lazy_kprobe,
			// udp_recv_lazy_kprobe
			tus.SensorMap{Name: "tg_udp_map", Progs: []uint{2, 3, 5, 7, 8}},
			tus.SensorMap{Name: "tg_udp_config_map", Progs: []uint{2, 3}},

			tus.SensorMap{Name: "tg_latency_config_map", Progs: []uint{3, 9}},

			// udp_destroy_sock, inet_send, inet_recv
			tus.SensorMap{Name: "tg_socket_tuple_map", Progs: []uint{1, 2, 3, 5, 7, 8}},
			tus.SensorMap{Name: "tg_socket_tuple_map_stats", Progs: []uint{1, 2, 3, 5, 7, 8}},
			tus.SensorMap{Name: "tg_socket_tuple_hint_map", Progs: []uint{1, 2, 3, 5, 7, 8}},
		}

		if useIPv6InitHook {
			sensorProgs = append(sensorProgs, tus.SensorProg{Name: "tg_udpv6_init_sock", Type: ebpf.Kprobe})
			sensorMaps = append(sensorMaps, []tus.SensorMap{
				// udp_init_sock, udp4_sendret_lazy_kprobe, udp6_sendret_lazy_kprobe, udp_recv_lazy_kprobe
				tus.SensorMap{Name: "execve_map", Progs: []uint{0, 2, 3, 5, 7, 8, 13}},

				// udp_init_sock, udp_destroy_sock, inet_lazy_send (not stats), inet_lazy_recv (not stats),
				// udp4_sendret_lazy_kprobe, udp6_sendret_lazy_kprobe, udp_recv_lazy_kprobe
				tus.SensorMap{Name: "tg_socket_map", Progs: []uint{0, 1, 2, 3, 5, 7, 8, 10, 13}},
				tus.SensorMap{Name: "tg_socket_map_stats", Progs: []uint{0, 1, 5, 7, 8, 13}},

				// udp_init_sock, udp_destroy_sock, inet_lazy_send, inet_lazy_recv, udp4_sendret_lazy_kprobe,
				// udp6_sendret_lazy_kprobe, udp_recv_lazy_kprobe
				tus.SensorMap{Name: "tcpmon_map", Progs: []uint{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 13}},
			}...)
		} else {
			sensorMaps = append(sensorMaps, []tus.SensorMap{
				// udp_init_sock, udp4_sendret_lazy_kprobe, udp6_sendret_lazy_kprobe, udp_recv_lazy_kprobe
				tus.SensorMap{Name: "execve_map", Progs: []uint{0, 2, 3, 5, 7, 8}},

				// udp_init_sock, udp_destroy_sock, inet_lazy_send (not stats), inet_lazy_recv (not stats),
				// udp4_sendret_lazy_kprobe, udp6_sendret_lazy_kprobe, udp_recv_lazy_kprobe
				tus.SensorMap{Name: "tg_socket_map", Progs: []uint{0, 1, 2, 3, 5, 7, 8, 10}},
				tus.SensorMap{Name: "tg_socket_map_stats", Progs: []uint{0, 1, 5, 7, 8}},

				// udp_init_sock, udp_destroy_sock, inet_lazy_send, inet_lazy_recv, udp4_sendret_lazy_kprobe,
				// udp6_sendret_lazy_kprobe, udp_recv_lazy_kprobe
				tus.SensorMap{Name: "tcpmon_map", Progs: []uint{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}},
			}...)
		}
	}

	if err := observertesthelper.WriteConfigFile(testConfigFile, udpBasicConfig); err != nil {
		t.Fatalf("WriteFile(%s): err %s", testConfigFile, err)
	}

	sens, err := observertesthelper.GetDefaultSensorsWithFile(t, testConfigFile, runner.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultSensorsWithFile error: %s", err)
	}

	tus.CheckSensorLoad(sens, sensorMaps, sensorProgs, t)

	sensors.UnloadSensors(sens)
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
	var clientBytesSubmitted uint64
	var clientSegsOut uint32
	var clientSegsSubmitted uint32
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
				clientBytesSubmitted += event.Stats.BytesSubmitted
				clientSegsOut += event.Stats.SegsOut
				clientSegsSubmitted += event.Stats.SegsSubmitted
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
				clientBytesSubmitted = 0
				clientSegsOut = 0
				clientSegsSubmitted = 0
				serverBytesReceived = 0
				serverSegsIn = 0
			}()

			if clientBytesSent != 5 {
				return fmt.Errorf("Unexecpected clientBytesSent, wanted 5, got %d", clientBytesSent)
			}

			if clientBytesSubmitted != 5 {
				return fmt.Errorf("Unexecpected clientBytesSubmitted, wanted 5, got %d", clientBytesSubmitted)
			}

			if clientSegsOut != 1 {
				return fmt.Errorf("Unexecpected clientSegsOut, wanted 1, got %d", clientSegsOut)
			}

			if clientSegsSubmitted != 1 {
				return fmt.Errorf("Unexecpected clientSegsSubmitted, wanted 1, got %d", clientSegsSubmitted)
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
				WithBytesSubmitted(5).
				WithSegsOut(1).
				WithSegsSubmitted(1)),
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

func TestDnsEvents(t *testing.T) {
	if !kernels.MinKernelVersion("5.4.0") {
		t.Skipf("dns requires kernel >= 5.4")
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	if err := observertesthelper.WriteConfigFile(testConfigFile, udpConfig); err != nil {
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

	checker := ec.NewUnorderedEventChecker(
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
		// This is less specific than the above so it must be specified second
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
		// This is less specific than the above so it must be specified second
		ec.NewProcessDnsChecker("curl6DnsRequest").
			WithProcess(curl6Checker).
			WithParent(selfChecker).
			WithDns(ec.NewDnsInfoChecker().
				WithRcode(0).
				WithNames(ec.NewStringListMatcher().WithValues(sm.Full("www.google.com."))).
				WithQueryTypes(ec.NewDnsTypeListMatcher().WithValues(ec.NewDnsTypeChecker(tetragon.DnsType_AAAA)))),
	)

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
	for string(line[:]) != "Ready" {
		line, _, err = serverBuf.ReadLine()
		if err != nil {
			killAndWaitCommand(t, serverCmd)
			panic(err)
		}
		if len(line) == 0 {
			killAndWaitCommand(t, serverCmd)
			panic(fmt.Errorf("received empty line from UDP server"))
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
	if !kernels.MinKernelVersion("5.4.0") {
		t.Skipf("io_uring requires kernel >= 5.4")
	}
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "x86_64" {
		t.Skipf("Test seems to time out on ARM")
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	server := os.Args[0]
	client := getNCCommand(t, "nc.openbsd")

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	ncSrvChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(server)).
		WithArguments(sm.Full("-udpIouServer"))

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
	var clientBytesSubmitted uint64
	var clientBytesReceived uint64
	var clientBytesConsumed uint64
	var clientSegsOut uint32
	var clientSegsSubmitted uint32
	var clientSegsIn uint32
	var clientSegsConsumed uint32
	var serverBytesSent uint64
	var serverBytesSubmitted uint64
	var serverBytesReceived uint64
	var serverBytesConsumed uint64
	var serverSegsOut uint32
	var serverSegsSubmitted uint32
	var serverSegsIn uint32
	var serverSegsConsumed uint32

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
				clientBytesSubmitted += event.Stats.BytesSubmitted
				clientBytesReceived += event.Stats.BytesReceived
				clientBytesConsumed += event.Stats.BytesConsumed
				clientSegsIn += event.Stats.SegsIn
				clientSegsConsumed += event.Stats.SegsConsumed
				clientSegsOut += event.Stats.SegsOut
				clientSegsSubmitted += event.Stats.SegsSubmitted
				return false, nil
			}

			if serverStatsChecker.Check(event) == nil {
				serverBytesSent += event.Stats.BytesSent
				serverBytesSubmitted += event.Stats.BytesSubmitted
				serverBytesReceived += event.Stats.BytesReceived
				serverBytesConsumed += event.Stats.BytesConsumed
				serverSegsIn += event.Stats.SegsIn
				serverSegsConsumed += event.Stats.SegsConsumed
				serverSegsOut += event.Stats.SegsOut
				serverSegsSubmitted += event.Stats.SegsSubmitted
				return false, nil
			}

			return false, fmt.Errorf("sockstats event is neither from client nor server")
		},
		FinalCheckFn: func(_ *logrus.Logger) error {
			defer func() {
				clientBytesSent = 0
				clientBytesSubmitted = 0
				clientBytesReceived = 0
				clientBytesConsumed = 0
				clientSegsIn = 0
				clientSegsConsumed = 0
				clientSegsOut = 0
				clientSegsSubmitted = 0
				serverBytesSent = 0
				serverBytesSubmitted = 0
				serverBytesReceived = 0
				serverBytesConsumed = 0
				serverSegsIn = 0
				serverSegsConsumed = 0
				serverSegsOut = 0
				serverSegsSubmitted = 0
			}()

			if clientBytesSent != 5 {
				return fmt.Errorf("Unexecpected clientBytesSent, wanted 5, got %d", clientBytesSent)
			}

			if clientBytesSubmitted != 5 {
				return fmt.Errorf("Unexecpected clientBytesSubmitted, wanted 5, got %d", clientBytesSubmitted)
			}

			if clientBytesReceived != 5 {
				return fmt.Errorf("Unexecpected clientBytesReceived, wanted 5, got %d", clientBytesReceived)
			}

			if clientBytesConsumed != 5 {
				return fmt.Errorf("Unexecpected clientBytesConsumed, wanted 5, got %d", clientBytesConsumed)
			}

			if clientSegsIn != 1 {
				return fmt.Errorf("Unexecpected clientSegsIn, wanted 1, got %d", clientSegsIn)
			}

			if clientSegsConsumed != 1 {
				return fmt.Errorf("Unexecpected clientSegsConsumed, wanted 1, got %d", clientSegsConsumed)
			}

			if clientSegsOut != 1 {
				return fmt.Errorf("Unexecpected clientSegsOut, wanted 1, got %d", clientSegsOut)
			}

			if clientSegsSubmitted != 1 {
				return fmt.Errorf("Unexecpected clientSegsSubmitted, wanted 1, got %d", clientSegsSubmitted)
			}

			if serverBytesSent != 5 {
				return fmt.Errorf("Unexecpected serverBytesSent, wanted 5, got %d", serverBytesSent)
			}

			if serverBytesSubmitted != 5 {
				return fmt.Errorf("Unexecpected serverBytesSubmitted, wanted 5, got %d", serverBytesSubmitted)
			}

			if serverBytesReceived != 5 {
				return fmt.Errorf("Unexecpected serverBytesReceived, wanted 5, got %d", serverBytesReceived)
			}

			if serverBytesConsumed != 5 {
				return fmt.Errorf("Unexecpected serverBytesConsumed, wanted 5, got %d", serverBytesConsumed)
			}

			if serverSegsIn != 1 {
				return fmt.Errorf("Unexecpected serverSegsIn, wanted 1, got %d", serverSegsIn)
			}

			if serverSegsConsumed != 1 {
				return fmt.Errorf("Unexecpected serverSegsConsumed, wanted 1, got %d", serverSegsConsumed)
			}

			if serverSegsOut != 1 {
				return fmt.Errorf("Unexecpected serverSegsOut, wanted 1, got %d", serverSegsOut)
			}

			if serverSegsSubmitted != 1 {
				return fmt.Errorf("Unexecpected serverSegsSubmitted, wanted 1, got %d", serverSegsSubmitted)
			}

			return nil
		},
	}

	obs := getBasicUdpObserver(t, ctx)
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)

	readyWG.Wait()
	cmdServer := exec.Command(os.Args[0], "-udpIouServer")
	serverOutput, err := cmdServer.StdoutPipe()
	require.NoError(t, err, "could not connect to server output pipe")
	cmdServer.Stderr = os.Stderr

	err = cmdServer.Start()
	require.NoError(t, err, "cannot start server")

	serverBuf := bufio.NewReader(serverOutput)
	var line []byte
	for string(line[:]) != "Ready" {
		line, _, err = serverBuf.ReadLine()
		if err != nil {
			killAndWaitCommand(t, cmdServer)
			panic(err)
		}
		if len(line) == 0 {
			killAndWaitCommand(t, cmdServer)
			panic(fmt.Errorf("received empty line from UDP server"))
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

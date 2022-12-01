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

package udp

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/api/v1/tetragon"
	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/matchers/durationmatcher"
	"github.com/cilium/tetragon/pkg/matchers/listmatcher"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/sirupsen/logrus"

	"github.com/cilium/tetragon/pkg/jsonchecker"
	"github.com/isovalent/hubble-fgs/pkg/sensors/base"
	"github.com/isovalent/hubble-fgs/pkg/sensors/burstEvents"
	"github.com/isovalent/hubble-fgs/pkg/sensors/ip"
	"github.com/isovalent/hubble-fgs/pkg/testutils/runner"

	_ "github.com/cilium/tetragon/pkg/sensors"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/exec"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/sockmap"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
)

var (
	client bool
	server bool
)

const (
	testConfigFile = "/tmp/hubble-tetragon.gotest.yaml"
)

func init() {
	flag.BoolVar(&client, "client", false, "internal")
	flag.BoolVar(&server, "server", false, "internal")
}

func TestMain(m *testing.M) {
	// FIXME: we need to skip these tests in kvm ci kernels <5.10 due to extreme flakiness
	// in CI. Once we have a chance to debug the issue, let's drop this check.
	if v := "4.19.0"; !kernels.MinKernelVersion(v) && os.Getenv("KVM_CI") != "" {
		fmt.Fprintf(os.Stderr, "Minimum kernel version (%v) for UDP tests in KVM CI not met, skipping", v)
		return
	}

	flag.Parse()
	if server {
		udpServer()
		os.Exit(0)
	}
	if client {
		udpClient()
		os.Exit(0)
	}
	ec := runner.TestSensorsRun(m, "SensorUdp")
	os.Exit(ec)
}

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

const BUFSIZE, BUFVAR = 1024, 256
const hostname = "127.0.0.1"
const portno = 31337
const protocol = "udp4"

func udpServer() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM)
	go func() {
		sig := <-sigs
		if sig == syscall.SIGTERM {
			os.Exit(0)
		}
	}()

	conn, err := net.ListenPacket(protocol, fmt.Sprintf("%s:%d", hostname, portno))
	if err != nil {
		panic(err)
	}
	buf := make([]byte, 2*BUFSIZE)
	fmt.Printf("Ready\n")
	for {
		_, _, err = conn.ReadFrom(buf)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR reading from socket\n")
			panic(err)
		}
	}
}

func sendData(socket net.Conn, buf []byte) {
	bufLen := rand.Intn(BUFVAR) - (BUFVAR / 2) + BUFSIZE
	_, err := socket.Write(buf[0:bufLen])
	if err != nil {
		fmt.Printf("ERROR writing to socket\n")
		panic(err)
	}
}

func udpClient() {
	baselineRate := 5
	burstRate := 10
	baselineDuration := 1
	burstDuration := 1
	numBursts := 3

	baselineWait := time.Duration(1000000 / baselineRate)
	burstWait := time.Duration(1000000 / burstRate)

	randFile, err := os.Open("/dev/urandom")
	if err != nil {
		fmt.Printf("ERROR opening urandom\n")
		panic(err)
	}

	buf := make([]byte, BUFSIZE+BUFVAR)
	randReader := bufio.NewReader(randFile)
	_, err = randReader.Read(buf)
	if err != nil {
		fmt.Printf("ERROR reading urandom\n")
		panic(err)
	}
	randFile.Close()

	socket, err := net.Dial(protocol, fmt.Sprintf("%s:%d", hostname, portno))
	if err != nil {
		fmt.Printf("ERROR dialing socket\n")
		panic(err)
	}

	for i := 0; i < numBursts; i++ {
		for j := 0; j < (baselineDuration * baselineRate); j++ {
			sendData(socket, buf)
			time.Sleep(baselineWait * time.Microsecond)
		}
		for j := 0; j < (burstDuration * burstRate); j++ {
			sendData(socket, buf)
			time.Sleep(burstWait * time.Microsecond)
		}
	}
}

func TestUdpBurst(t *testing.T) {
	if v := "4.19.0"; !kernels.MinKernelVersion(v) {
		t.Skipf("Minimum kernel version (%v) not met, skipping", v)
	}

	bpf.CheckOrMountCgroup2()

	clientProcess := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary)).
		WithArguments(sm.Full("-client"))

	serverProcess := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary)).
		WithArguments(sm.Full("-server"))

	checker := ec.NewUnorderedEventChecker(
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
		ec.NewProcessExecChecker("severStart").
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

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	if err := observer.WriteConfigFile(testConfigFile, udpConfig); err != nil {
		t.Fatalf("WriteFile(%s): err %s", testConfigFile, err)
	}

	base := base.GetInitialSensor()
	obs, err := observer.GetDefaultObserverWithBase(t, ctx, base, testConfigFile, runner.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserver error: %s", err)
	}
	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	serverCmd := exec.Command(os.Args[0], "-server")
	serverOutput, err := serverCmd.StdoutPipe()
	require.NoError(t, err, "could not connect to server output pipe")
	serverCmd.Stderr = os.Stderr

	err = serverCmd.Start()
	require.NoError(t, err, "cannot start server")

	serverBuf := bufio.NewReader(serverOutput)
	serverBuf.ReadLine()

	serverPid := uint32(serverCmd.Process.Pid)

	burstMapFile := filepath.Join(bpf.MapPrefixPath(), burstEvents.ProcessNetworkBurstMapName)
	m, err := ebpf.LoadPinnedMap(burstMapFile, nil)
	require.NoError(t, err, "cannot open map file")
	defer m.Close()
	processKey := &burstEvents.ProcessNetworkBurstKey{Key: burstEvents.PidToBurstKey(serverPid, syscall.IPPROTO_UDP, 0)}
	var processValue burstEvents.ProcessNetworkBurstValue

	err = m.Lookup(processKey, &processValue)
	assert.Error(t, err, "server process in burst map before traffic")

	clientCmd := exec.Command(os.Args[0], "-client")
	clientCmd.Stdout = os.Stderr
	clientCmd.Stderr = os.Stderr
	err = clientCmd.Run()
	assert.NoError(t, err, "cannot start client")

	err = m.Lookup(processKey, &processValue)
	assert.NoError(t, err, "server process must be in burst map")

	err = m.Lookup(processKey, &processValue)
	assert.NoError(t, err, "client process must be in burst map")

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
	assert.Error(t, err, "server process in burst map after exit")

	killAndWaitCommand(t, clientCmd)
}

// Note 20.0.0.0/8 is the DoD and isn't routable on the Internet
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

// NB(kkourt): Function(t *testing.T, ctx context.Context) is the reasonable
// thing to do here even if revive complains.
//
//revive:disable:context-as-argument
func getBasicUdpObserver(t *testing.T, ctx context.Context) *observer.Observer {
	if err := observer.WriteConfigFile(testConfigFile, udpBasicConfig); err != nil {
		t.Fatalf("WriteFile(%s): err %s", testConfigFile, err)
	}

	base := base.GetInitialSensor()
	obs, err := observer.GetDefaultObserverWithBase(t, ctx, base, testConfigFile, runner.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserver error: %s", err)
	}
	return obs
}

func getNCCommand(t *testing.T, orig string) string {
	if _, err := exec.LookPath(orig); err == nil {
		return orig
	}

	server := "nc.openbsd"
	if _, err := exec.LookPath(server); err != nil {
		t.Fatalf("Binary %q doesn't exist on host machine, cannot continue", server)
	}
	t.Logf("Using %q instead of original program %q", server, orig)

	return server
}

func killAndWaitCommand(t *testing.T, cmd *exec.Cmd) {
	if cmd != nil {
		if cmd.Process != nil {
			cmd.Process.Kill()
		} else {
			t.Logf("Command %q process disappeared, skipping kill", cmd.Args[0])
		}
		_ = cmd.Wait()
	}
}

func TestGetProtocolShift(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	obs := getBasicUdpObserver(t, ctx)
	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)

	readyWG.Wait()

	protocolShift, err := ip.ProtocolShift()
	assert.NoError(t, err)
	protocolShift2, err := ip.ProtocolShift()
	assert.NoError(t, err)
	assert.Equal(t, protocolShift, protocolShift2)
	if !kernels.MinKernelVersion("5.6.0") {
		assert.Equal(t, protocolShift, true)
	} else {
		assert.Equal(t, protocolShift, false)
	}
}

func TestConnectEvent4(t *testing.T) {
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
		NextCheckFn: func(event_ ec.Event, log *logrus.Logger) (bool, error) {
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
		FinalCheckFn: func(event *logrus.Logger) error {
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
	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)

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
	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)

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

func TestLoadUdpSensor(t *testing.T) {
	var sensorProgs []tus.SensorProg
	var sensorMaps []tus.SensorMap

	if !kernels.MinKernelVersion("5.4.0") { // 4.19 - <5.4
		sensorProgs = []tus.SensorProg{
			0: tus.SensorProg{Name: "sk_allocret", Type: ebpf.Kprobe},
			1: tus.SensorProg{Name: "sock_release_lazy", Type: ebpf.Kprobe},
			2: tus.SensorProg{Name: "inet_lazy_send_kp", Type: ebpf.Kprobe},
			3: tus.SensorProg{Name: "udp4_send_lazy_kprobe", Type: ebpf.Kprobe},
			4: tus.SensorProg{Name: "udp4_sendret_lazy_kprobe", Type: ebpf.Kprobe},
			5: tus.SensorProg{Name: "udp6_send_lazy_kprobe", Type: ebpf.Kprobe},
			6: tus.SensorProg{Name: "udp6_sendret_lazy_kprobe", Type: ebpf.Kprobe},
			7: tus.SensorProg{Name: "udp_recv_lazy_kprobe", Type: ebpf.Kprobe},
			8: tus.SensorProg{Name: "udp_egress_timestamp", Type: ebpf.SchedCLS},
		}
		sensorMaps = []tus.SensorMap{
			// sk_allocret, udp4_sendret_lazy_kprobe, udp6_sendret_lazy_kprobe, udp_recv_lazy_kprobe
			tus.SensorMap{Name: "execve_map", Progs: []uint{0, 2, 4, 6, 7}},

			// udp4_send_lazy_kprobe, udp4_sendret_lazy_kprobe, udp6_send_lazy_kprobe,
			// udp6_sendret_lazy_kprobe, udp_recv_lazy_kprobe
			tus.SensorMap{Name: "udp_retprobe_map", Progs: []uint{3, 4, 5, 6}},

			// inet_lazy_send_kp, udp4_sendret_lazy_kprobe, udp6_sendret_lazy_kprobe,
			// udp_recv_lazy_kprobe
			tus.SensorMap{Name: "udp_map", Progs: []uint{2, 4, 6, 7}},
			tus.SensorMap{Name: "udp_config_map", Progs: []uint{2, 8}},

			// sk_allocret, sock_release_lazy, inet_lazy_send_kp (not stats), udp4_sendret_lazy_kprobe,
			// udp6_sendret_lazy_kprobe, udp_recv_lazy_kprobe
			tus.SensorMap{Name: "socket_map", Progs: []uint{0, 1, 2, 4, 6, 7}},
			tus.SensorMap{Name: "socket_map_stats", Progs: []uint{0, 1, 4, 6, 7}},

			// sk_allocret, sock_release_lazy, inet_lazy_send_kp, udp4_sendret_lazy_kprobe,
			// udp6_sendret_lazy_kprobe, udp_recv_lazy_kprobe
			tus.SensorMap{Name: "tcpmon_map", Progs: []uint{0, 1, 2, 4, 6, 7, 8}},

			// sock_release_lazy
			tus.SensorMap{Name: "fd_lookup_config_map", Progs: []uint{1}},
		}
	} else if !kernels.MinKernelVersion("5.10.0") { // 5.6 - <5.10
		sensorProgs = []tus.SensorProg{
			0: tus.SensorProg{Name: "sk_allocret", Type: ebpf.Kprobe},
			1: tus.SensorProg{Name: "sock_release_lazy", Type: ebpf.Kprobe},
			2: tus.SensorProg{Name: "inet_lazy_send", Type: ebpf.CGroupSKB},
			3: tus.SensorProg{Name: "inet_lazy_recv", Type: ebpf.CGroupSKB},
			4: tus.SensorProg{Name: "udp4_send_lazy_kprobe", Type: ebpf.Kprobe},
			5: tus.SensorProg{Name: "udp4_sendret_lazy_kprobe", Type: ebpf.Kprobe},
			6: tus.SensorProg{Name: "udp6_send_lazy_kprobe", Type: ebpf.Kprobe},
			7: tus.SensorProg{Name: "udp6_sendret_lazy_kprobe", Type: ebpf.Kprobe},
			8: tus.SensorProg{Name: "udp_recv_lazy_kprobe", Type: ebpf.Kprobe},
			9: tus.SensorProg{Name: "udp_egress_timestamp", Type: ebpf.SchedCLS},
		}
		sensorMaps = []tus.SensorMap{
			// sk_allocret, udp4_sendret_lazy_kprobe, udp6_sendret_lazy_kprobe, udp_recv_lazy_kprobe
			tus.SensorMap{Name: "execve_map", Progs: []uint{0, 2, 3, 5, 7, 8}},

			// udp4_send_lazy_kprobe, udp4_sendret_lazy_kprobe, udp6_send_lazy_kprobe,
			// udp6_sendret_lazy_kprobe, udp_recv_lazy_kprobe
			tus.SensorMap{Name: "udp_retprobe_map", Progs: []uint{4, 5, 6, 7}},

			// inet_lazy_send, inet_lazy_recv, udp4_sendret_lazy_kprobe, udp6_sendret_lazy_kprobe,
			// udp_recv_lazy_kprobe
			tus.SensorMap{Name: "udp_map", Progs: []uint{2, 3, 5, 7, 8}},
			tus.SensorMap{Name: "udp_config_map", Progs: []uint{2, 3, 9}},

			// sk_allocret, sock_release_lazy, inet_lazy_send (not stats), inet_lazy_recv (not stats),
			// udp4_sendret_lazy_kprobe, udp6_sendret_lazy_kprobe, udp_recv_lazy_kprobe
			tus.SensorMap{Name: "socket_map", Progs: []uint{0, 1, 2, 3, 5, 7, 8}},
			tus.SensorMap{Name: "socket_map_stats", Progs: []uint{0, 1, 5, 7, 8}},

			// sk_allocret_v56, sock_release_lazy_v56, inet_lazy_send, inet_lazy_recv, udp4_sendret_lazy_kprobe,
			// udp6_sendret_lazy_kprobe, udp_recv_lazy_kprobe
			tus.SensorMap{Name: "tcpmon_map", Progs: []uint{0, 1, 2, 3, 5, 7, 8, 9}},

			// sock_release_lazy
			tus.SensorMap{Name: "fd_lookup_config_map", Progs: []uint{1}},
		}
	} else { // 5.10+
		sensorProgs = []tus.SensorProg{
			0: tus.SensorProg{Name: "sock_create", Type: ebpf.CGroupSock},
			1: tus.SensorProg{Name: "sock_release", Type: ebpf.Kprobe},
			2: tus.SensorProg{Name: "inet_send", Type: ebpf.CGroupSKB},
			3: tus.SensorProg{Name: "inet_recv", Type: ebpf.CGroupSKB},
			4: tus.SensorProg{Name: "udp4_send_kprobe", Type: ebpf.Kprobe},
			5: tus.SensorProg{Name: "udp4_sendret_kprobe", Type: ebpf.Kprobe},
			6: tus.SensorProg{Name: "udp6_send_kprobe", Type: ebpf.Kprobe},
			7: tus.SensorProg{Name: "udp6_sendret_kprobe", Type: ebpf.Kprobe},
			8: tus.SensorProg{Name: "udp_recv_kprobe", Type: ebpf.Kprobe},
			9: tus.SensorProg{Name: "udp_egress_timestamp", Type: ebpf.SchedCLS},
		}
		sensorMaps = []tus.SensorMap{
			// inet_send, inet_recv, udp4_sendret_kprobe, udp6_sendret_kprobe, udp_recv_kprobe
			// TODO this map is broken at the moment, disabling
			// tus.SensorMap{Name: "socket_cookie_to_proc_map", Progs: []uint{ /* 0, 1, */ 2, 3, 4, 6, 8}},

			// udp4_sendret_kprobe, udp6_sendret_kprobe, udp_recv_kprobe
			tus.SensorMap{Name: "execve_map", Progs: []uint{0, 2, 3, 5, 7, 8}},

			// udp4_send_kprobe, udp4_sendret_kprobe, udp6_send_kprobe,
			// udp6_sendret_kprobe, udp_recv_kprobe
			tus.SensorMap{Name: "udp_retprobe_map", Progs: []uint{4, 5, 6, 7}},

			// inet_send, inet_recv, udp4_sendret_kprobe, udp6_sendret_kprobe,
			// udp_recv_kprobe
			tus.SensorMap{Name: "udp_map", Progs: []uint{2, 3, 5, 7, 8}},
			tus.SensorMap{Name: "udp_config_map", Progs: []uint{2, 3, 9}},

			// sock_create, sock_release, inet_send, inet_recv, udp4_sendret_kprobe,
			// udp6_sendret_kprobe, udp_recv_kprobe
			tus.SensorMap{Name: "socket_map", Progs: []uint{0, 1, 2, 3, 5, 7, 8}},
			tus.SensorMap{Name: "socket_map_stats", Progs: []uint{0, 1, 2, 3, 5, 7, 8}},

			// sock_create, sock_release, inet_send, inet_recv, udp4_sendret_kprobe, udp6_sendret_kprobe
			// udp_recv_kprobe
			tus.SensorMap{Name: "tcpmon_map", Progs: []uint{0, 1, 2, 3, 5, 7, 8, 9}},

			// sock_release
			tus.SensorMap{Name: "fd_lookup_config_map", Progs: []uint{1}},
		}
	}

	if err := observer.WriteConfigFile(testConfigFile, udpBasicConfig); err != nil {
		t.Fatalf("WriteFile(%s): err %s", testConfigFile, err)
	}

	sens, err := observer.GetDefaultSensorsWithFile(t, context.TODO(), testConfigFile, runner.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultSensorsWithFile error: %s", err)
	}

	tus.CheckSensorLoad(sens, sensorMaps, sensorProgs, t)

	sensors.UnloadAll(tus.Conf().TetragonLib)
}

func TestConnectEvent6(t *testing.T) {
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
		NextCheckFn: func(event_ ec.Event, log *logrus.Logger) (bool, error) {
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
		FinalCheckFn: func(event *logrus.Logger) error {
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
	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)

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
	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)

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

	bpf.CheckOrMountCgroup2()

	if err := observer.WriteConfigFile(testConfigFile, udpConfig); err != nil {
		t.Fatalf("WriteFile(%s): err %s", testConfigFile, err)
	}

	obs, err := observer.GetDefaultObserverWithLib(t, ctx, testConfigFile, runner.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserver error: %s", err)
	}

	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
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
				WithQuestionTypes(ec.NewUint32ListMatcher().WithValues(1)).
				WithAnswerTypes(ec.NewUint32ListMatcher().WithValues(1)).
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
				WithQuestionTypes(ec.NewUint32ListMatcher().WithValues(1))),
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
				WithQuestionTypes(ec.NewUint32ListMatcher().WithValues(28)).
				WithAnswerTypes(ec.NewUint32ListMatcher().WithValues(28)).
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
				WithQuestionTypes(ec.NewUint32ListMatcher().WithValues(28))),
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

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
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/isovalent/hubble-fgs/api/v1/fgs"
	ec "github.com/isovalent/hubble-fgs/api/v1/fgs/codegen/eventchecker"
	sm "github.com/isovalent/hubble-fgs/api/v1/fgs/codegen/eventchecker/matchers/stringmatcher"
	"github.com/isovalent/hubble-fgs/pkg/observer"
	"github.com/isovalent/hubble-fgs/pkg/sensors/burstEventsPoll"
	"github.com/sirupsen/logrus"

	_ "github.com/isovalent/hubble-fgs/pkg/sensors/exec"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/sockmap"

	"github.com/stretchr/testify/assert"
)

var (
	selfBinary  string
	fgsLib      string
	cmdWaitTime time.Duration
	client      bool
	server      bool
)

const (
	testConfigFile = "/tmp/hubble-fgs.gotest.yaml"
)

func init() {
	flag.StringVar(&fgsLib, "hubble-lib", "../../../bpf/objs/", "hubble lib directory (location of btf file and bpf objs). Will be overridden by an FGS_LIB env variable.")
	flag.DurationVar(&cmdWaitTime, "command-wait", 20000*time.Millisecond, "duration to wait for fgs to gather logs from commands")
	flag.BoolVar(&client, "client", false, "internal")
	flag.BoolVar(&server, "server", false, "internal")

	bpf.SetMapPrefix("testObserver")
}

func TestMain(m *testing.M) {
	flag.Parse()
	if server {
		udpServer()
		os.Exit(0)
	}
	if client {
		udpClient()
		os.Exit(0)
	}
	bpf.CheckOrMountFS("")
	bpf.CheckOrMountDebugFS()
	bpf.ConfigureResourceLimits()
	bpf.SetMapPrefix("testObserver")
	selfBinary = filepath.Base(os.Args[0])
	exitCode := m.Run()
	os.Exit(exitCode)
}

const udpConfig = `
apiversion: isovalent.com/v1alpha1
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
    burstPoll:
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

	if v := "5.4.0"; !kernels.MinKernelVersion(v) {
		t.Skipf("Minimum kernel version (%v) not met, skipping", v)
	}

	bpf.CheckOrMountCgroup2()

	clientProcess := ec.NewProcessChecker().
		WithBinary(sm.Suffix(selfBinary)).
		WithArguments(sm.Full("-client"))

	serverProcess := ec.NewProcessChecker().
		WithBinary(sm.Suffix(selfBinary)).
		WithArguments(sm.Full("-server"))

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker().
			WithProcess(clientProcess),
		ec.NewProcessNetworkBurstChecker().
			WithProcess(clientProcess).
			WithProtocol(sm.Full("UDP")).
			WithDirection(sm.Full("egress")).
			WithBurstState(sm.Full("start")),
		ec.NewProcessNetworkBurstChecker().
			WithProcess(clientProcess).
			WithProtocol(sm.Full("UDP")).
			WithDirection(sm.Full("egress")).
			WithBurstState(sm.Full("end")),
		ec.NewProcessExecChecker().
			WithProcess(serverProcess),
		ec.NewProcessNetworkBurstChecker().
			WithProcess(serverProcess).
			WithProtocol(sm.Full("UDP")).
			WithDirection(sm.Full("ingress")).
			WithBurstState(sm.Full("start")),
		ec.NewProcessNetworkBurstChecker().
			WithProcess(serverProcess).
			WithProtocol(sm.Full("UDP")).
			WithDirection(sm.Full("ingress")).
			WithBurstState(sm.Full("end")),
	)

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
	defer cancel()

	if err := observer.WriteConfigFile(testConfigFile, udpConfig); err != nil {
		t.Fatalf("WriteFile(%s): err %s", testConfigFile, err)
	}

	obs, err := observer.GetDefaultObserverWithLib(t, testConfigFile, fgsLib)
	if err != nil {
		t.Fatalf("GetDefaultObserver error: %s", err)
	}
	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	serverCmd := exec.Command(os.Args[0], "-server")
	serverOutput, err := serverCmd.StdoutPipe()
	if err != nil {
		fmt.Printf("ERROR Could not connect to server output pipe\n")
		panic(err)
	}
	serverCmd.Stderr = os.Stderr
	if err != nil {
		fmt.Printf("ERROR Could not connect to server input pipe\n")
		panic(err)
	}

	err = serverCmd.Start()
	if err != nil {
		fmt.Printf("ERROR Cannot start server\n")
		panic(err)
	}

	serverBuf := bufio.NewReader(serverOutput)
	serverBuf.ReadLine()

	serverPid := uint32(serverCmd.Process.Pid)

	burstMapFile := filepath.Join(bpf.MapPrefixPath(), burstEventsPoll.ProcessNetworkBurstMapName)
	m, err := ebpf.LoadPinnedMap(burstMapFile, nil)
	if err != nil {
		fmt.Printf("ERROR Cannot open map file\n")
		panic(err)
	}
	defer m.Close()
	processKey := &burstEventsPoll.ProcessNetworkBurstKey{Key: burstEventsPoll.PidToBurstKey(serverPid, syscall.IPPROTO_UDP, 0)}
	var processValue burstEventsPoll.ProcessNetworkBurstValue
	err = m.Lookup(processKey, &processValue)
	if err == nil {
		fmt.Printf("ERROR Server process in burst map before traffic\n")
		os.Exit(-1)
	}

	clientCmd := exec.Command(os.Args[0], "-client")
	clientCmd.Stdout = os.Stderr
	clientCmd.Stderr = os.Stderr
	err = clientCmd.Run()
	if err != nil {
		fmt.Printf("ERROR Cannot start client\n")
		panic(err)
	}

	err = observer.JsonTestCheckNew(t, checker)
	assert.NoError(t, err)

	err = m.Lookup(processKey, &processValue)
	if err != nil {
		fmt.Printf("ERROR Server process not in burst map\n")
		burstEventsPoll.Stop()
		panic(err)
	}

	if serverCmd != nil {
		serverProcess := serverCmd.Process
		if serverProcess != nil {
			serverProcess.Kill()
			serverProcess.Wait()
		} else {
			fmt.Printf("ERROR serverProcess is nil\n")
			os.Exit(-1)
		}
	} else {
		fmt.Printf("ERROR serverCmd is nil\n")
		os.Exit(-1)
	}

	quit := false
	for !quit {
		_, err = os.Stat(fmt.Sprintf("/proc/%d", serverPid))
		if err != nil {
			quit = true
		}
		time.Sleep(10 * time.Millisecond)
	}

	err = m.Lookup(processKey, &processValue)
	if err == nil {
		fmt.Printf("ERROR Server process in burst map after exit\n")
		os.Exit(-1)
	}
}

const udpBasicConfig = `
apiversion: isovalent.com/v1alpha1
kind: TracingPolicy
metadata:
  name: "udp"
spec:
  parser:
    udp:
      enable: true
      cgroup: true
      statsInterval: 2
`

func getBasicUdpObserver(t *testing.T) *observer.Observer {
	if err := observer.WriteConfigFile(testConfigFile, udpBasicConfig); err != nil {
		t.Fatalf("WriteFile(%s): err %s", testConfigFile, err)
	}
	obs, err := observer.GetDefaultObserverWithLib(t, testConfigFile, fgsLib)
	if err != nil {
		t.Fatalf("GetDefaultObserver error: %s", err)
	}
	return obs
}

func getNCCommand(t *testing.T, orig string) string {
	if _, err := exec.LookPath(orig); err == nil {
		return orig
	}

	server := "nc"
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

func TestConnectEvent(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
	defer cancel()

	server := getNCCommand(t, "nc.traditional")
	client := server

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(selfBinary))

	ncSrvChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(server)).
		WithArguments(sm.Full("-unvlp 8081"))

	ncCliChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(client)).
		WithArguments(sm.Full("-u 127.0.0.1 8081"))

	clientStatsChecker := ec.NewProcessSockStatsChecker().
		WithProcess(ncCliChecker).
		WithParent(selfChecker).
		WithSocket(ec.NewSockInfoChecker().
			WithProtocol(fgs.SocketProtocol_UDP).
			WithDestinationIp(sm.Full("127.0.0.1")).
			WithDestinationPort(8081))

	serverStatsChecker := ec.NewProcessSockStatsChecker().
		WithProcess(ncSrvChecker).
		WithParent(selfChecker).
		WithSocket(ec.NewSockInfoChecker().
			WithProtocol(fgs.SocketProtocol_UDP).
			WithSourceIp(sm.Full("127.0.0.1")).
			WithDestinationIp(sm.Full("127.0.0.1")).
			WithSourcePort(8081))

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker().
			WithProcess(selfChecker).
			WithParent(ec.NewProcessChecker()),
		ec.NewProcessExecChecker().
			WithProcess(ncSrvChecker).
			WithParent(selfChecker),
		ec.NewProcessExecChecker().
			WithProcess(ncCliChecker).
			WithParent(selfChecker),
		ec.NewProcessConnectChecker().
			WithProcess(ncSrvChecker).
			WithParent(selfChecker).
			WithSourceIp(sm.Full("127.0.0.1")).
			WithSourcePort(8081).
			WithDestinationIp(sm.Full("127.0.0.1")).
			WithProtocol(fgs.SocketProtocol_UDP),
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
			event, ok := event_.(*fgs.ProcessSockStats)
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

	obs := getBasicUdpObserver(t)
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

	err = observer.JsonTestCheckNew(t, checker)
	assert.NoError(t, err)

	err = observer.JsonTestCheckNew(t, statsChecker)
	assert.NoError(t, err)

	killAndWaitCommand(t, cmdServer)
	killAndWaitCommand(t, cmdClient)
}

func TestConnectAfterStartEvent(t *testing.T) {
	// FIXME: something broke this test case, but since it was never merged upstream this went
	// unnoticed... need to investigate
	t.Skip("This test is consistently failing at the moment, need to figure out why and fix it up.")

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
	defer cancel()

	server := getNCCommand(t, "nc.traditional")
	client := server

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(selfBinary))

	ncSrvChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(server)).
		WithArguments(sm.Full("-unvlp 8081"))

	ncCliChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(client)).
		WithArguments(sm.Full("-u 127.0.0.1 8081"))

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker().
			WithProcess(selfChecker).
			WithParent(ec.NewProcessChecker()),
		ec.NewProcessExecChecker().
			WithProcess(ncSrvChecker).
			WithParent(selfChecker),
		ec.NewProcessExecChecker().
			WithProcess(ncCliChecker).
			WithParent(selfChecker),
		ec.NewProcessConnectChecker().
			WithProcess(ncSrvChecker).
			WithParent(selfChecker).
			WithSourceIp(sm.Full("127.0.0.1")).
			WithSourcePort(8081).
			WithDestinationIp(sm.Full("127.0.0.1")).
			WithProtocol(fgs.SocketProtocol_UDP),
		// Check client sock stats
		ec.NewProcessSockStatsChecker().
			WithProcess(ncCliChecker).
			WithParent(selfChecker).
			WithSocket(ec.NewSockInfoChecker().
				WithProtocol(fgs.SocketProtocol_UDP).
				WithDestinationIp(sm.Full("127.0.0.1")).
				WithDestinationPort(8081)).
			WithStats(ec.NewSocketStatsChecker().
				WithBytesSent(5).
				WithBytesSubmitted(5).
				WithSegsOut(1).
				WithSegsSubmitted(1)),
		// Check server sock stats
		ec.NewProcessSockStatsChecker().
			WithProcess(ncSrvChecker).
			WithParent(selfChecker).
			WithSocket(ec.NewSockInfoChecker().
				WithProtocol(fgs.SocketProtocol_UDP).
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

	obs := getBasicUdpObserver(t)
	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)

	readyWG.Wait()
	cmdClient := exec.Command(client, "-u", "127.0.0.1", "8081")
	stdin, err := cmdClient.StdinPipe()
	assert.NoError(t, err)
	assert.NoError(t, cmdClient.Start())
	_, err = stdin.Write([]byte("hello"))
	assert.NoError(t, err)

	err = observer.JsonTestCheckNew(t, checker)
	assert.NoError(t, err)

	killAndWaitCommand(t, cmdServer)
	killAndWaitCommand(t, cmdClient)
}

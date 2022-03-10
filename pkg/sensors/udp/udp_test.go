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
	"github.com/isovalent/hubble-fgs/pkg/bpf"
	ec "github.com/isovalent/hubble-fgs/pkg/eventchecker"
	"github.com/isovalent/hubble-fgs/pkg/kernels"
	"github.com/isovalent/hubble-fgs/pkg/observer"
	sensors "github.com/isovalent/hubble-fgs/pkg/sensors"
	"github.com/isovalent/hubble-fgs/pkg/sensors/burstEventsPoll"
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
	exportFile     = "/tmp/hubble-fgs.gotest"
	testConfigFile = "/tmp/hubble-fgs.gotest.yaml"
	jsonRetries    = 10
)

func init() {
	flag.StringVar(&fgsLib, "hubble-lib", "../../../bpf/objs/", "hubble lib directory (location of btf file and bpf objs). Will be overridden by an FGS_LIB env variable.")
	flag.DurationVar(&cmdWaitTime, "command-wait", 20000*time.Millisecond, "duration to wait for fgs to gather logs from commands")
	flag.BoolVar(&client, "client", false, "internal")
	flag.BoolVar(&server, "server", false, "internal")
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
	numBursts := 1

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

	if v := "5.8.0"; !kernels.MinKernelVersion(v) {
		t.Skipf("Minimum kernel version (%v) not met, skipping", v)
	}

	bpf.CheckOrMountCgroup2()

	clientProcess := ec.ProcessWithCommand(ec.SuffixStringMatch(selfBinary), ec.FullStringMatch("-client"))
	serverProcess := ec.ProcessWithCommand(ec.SuffixStringMatch(selfBinary), ec.FullStringMatch("-server"))

	ProcessNetworkBurstEgress := ec.NewProcessNetworkBurstChecker().
		WithBurstDirection("egress")
	ProcessNetworkBurstIngress := ec.NewProcessNetworkBurstChecker().
		WithBurstDirection("ingress")

	checker := ec.NewUnorderedMultiResponseChecker(
		ec.NewExecEventChecker().
			HasProcess(clientProcess).
			End(),
		ec.NewProcessNetworkBurstEventChecker().
			HasProcess(clientProcess).
			HasProcessNetworkBurst(ProcessNetworkBurstEgress).
			End(),
		ec.NewExecEventChecker().
			HasProcess(serverProcess).
			End(),
		ec.NewProcessNetworkBurstEventChecker().
			HasProcess(serverProcess).
			HasProcessNetworkBurst(ProcessNetworkBurstIngress).
			End(),
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
	observer.LoopEvents(t, &doneWG, &readyWG, obs, ctx)
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

	burstMapFile := filepath.Join(sensors.MapDir, burstEventsPoll.ProcessNetworkBurstMapName)
	m, err := ebpf.LoadPinnedMap(burstMapFile, nil)
	if err != nil {
		fmt.Printf("ERROR Cannot open map file\n")
		panic(err)
	}
	defer m.Close()
	processKey := &burstEventsPoll.ProcessNetworkBurstKey{Key: burstEventsPoll.PidToBurstKey(uint32(serverCmd.Process.Pid), syscall.IPPROTO_UDP, 0)}
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

	err = observer.JsonTestCheck(t, checker)
	assert.NoError(t, err)

	err = m.Lookup(processKey, &processValue)
	if err != nil {
		fmt.Printf("ERROR Server process not in burst map\n")
		panic(err)
	}

	var serverPid = 0
	if serverCmd != nil {
		serverProcess := serverCmd.Process
		if serverProcess != nil {
			serverPid = serverProcess.Pid
			serverProcess.Kill()
		}
	}

	if serverPid != 0 {
		quit := false
		for !quit {
			_, err = os.Stat(fmt.Sprintf("/proc/%d", serverPid))
			if err == nil {
				quit = true
			}
			time.Sleep(10 * time.Millisecond)
		}
	}

	err = m.Lookup(processKey, &processValue)
	if err == nil {
		fmt.Printf("ERROR Server process in burst map after exit\n")
		os.Exit(-1)
	}

	observer.TestDone(t, obs)
}

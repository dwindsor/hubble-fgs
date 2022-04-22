package tcp

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
	"github.com/isovalent/hubble-fgs/api/v1/fgs"
	"github.com/isovalent/hubble-fgs/pkg/bpf"
	ec "github.com/isovalent/hubble-fgs/pkg/eventchecker"
	"github.com/isovalent/hubble-fgs/pkg/kernels"
	"github.com/isovalent/hubble-fgs/pkg/observer"
	"github.com/isovalent/hubble-fgs/pkg/reader"
	"github.com/isovalent/hubble-fgs/pkg/sensors/burstEventsPoll"
	"github.com/stretchr/testify/assert"

	_ "github.com/isovalent/hubble-fgs/pkg/sensors/exec"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/sockmap"
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

const tcpConfig = `
apiversion: isovalent.com/v1alpha1
kind: TracingPolicy
metadata:
  name: "tcp"
spec:
  parser:
    tcp:
      enable: true
      statsInterval: 20
      burst:
        enable: true
        windowSize: 1000
        triggerPercent: 50
    burstPoll:
      enable: true
      interval: 1000
    dns:
      enable: true
`

const tcpBasicConfig = `
apiversion: isovalent.com/v1alpha1
kind: TracingPolicy
metadata:
  name: "tcp"
spec:
  parser:
    tcp:
      enable: true
`

func init() {
	flag.StringVar(&fgsLib, "hubble-lib", "../../../bpf/objs/", "hubble lib directory (location of btf file and bpf objs). Will be overridden by an FGS_LIB env variable.")
	flag.DurationVar(&cmdWaitTime, "command-wait", 20000*time.Millisecond, "duration to wait for fgs to gather logs from commands")
	flag.BoolVar(&client, "client", false, "internal")
	flag.BoolVar(&server, "server", false, "internal")

	bpf.SetMapPrefix("testObserver")
}

func getBasicTcpObserver(t *testing.T) *observer.Observer {
	if err := observer.WriteConfigFile(testConfigFile, tcpBasicConfig); err != nil {
		t.Fatalf("WriteFile(%s): err %s", testConfigFile, err)
	}
	obs, err := observer.GetDefaultObserverWithLib(t, testConfigFile, fgsLib)
	if err != nil {
		t.Fatalf("GetDefaultObserver error: %s", err)
	}
	return obs
}

func TestMain(m *testing.M) {
	flag.Parse()
	if server {
		tcpServer()
		os.Exit(0)
	}
	if client {
		tcpClient()
		os.Exit(0)
	}
	bpf.CheckOrMountFS("")
	bpf.CheckOrMountDebugFS()
	bpf.ConfigureResourceLimits()
	selfBinary = filepath.Base(os.Args[0])
	exitCode := m.Run()
	os.Exit(exitCode)
}

func TestConnectEvent(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
	defer cancel()

	selfChecker := ec.ProcessWithBinary(ec.SuffixStringMatch(selfBinary))
	curlChecker := ec.ProcessWithCommand(
		ec.SuffixStringMatch("curl"), ec.FullStringMatch("127.0.0.1"),
	)
	checker := ec.NewUnorderedMultiResponseChecker(
		ec.NewExecEventChecker().
			HasProcess(selfChecker).
			HasParent().
			End(),
		ec.NewExecEventChecker().
			HasProcess(curlChecker).
			HasParent(selfChecker).
			End(),
		ec.NewConnectEventChecker().
			HasProcess(curlChecker).
			HasParent(selfChecker).
			HasDstIP("127.0.0.1").
			HasDstPort(80).
			HasProtocol(fgs.SocketProtocol_TCP).
			End(),
		ec.NewCloseEventChecker().
			HasProcess(curlChecker).
			HasParent(selfChecker).
			HasDstIP("127.0.0.1").
			HasDstPort(80).
			HasProtocol(fgs.SocketProtocol_TCP).
			HasType("connect").
			End(),
	)

	obs := getBasicTcpObserver(t)
	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	observer.ExecWGCurl(&readyWG, 10, "127.0.0.1")
	err := observer.JsonTestCheck(t, checker)
	assert.NoError(t, err)
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

func TestExecEventClone(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
	defer cancel()

	orig := "nc.traditional"
	server := orig
	client := server
	if _, err := exec.LookPath(server); err != nil {
		server = "nc"
		client = server

		if _, err := exec.LookPath(server); err != nil {
			t.Fatalf("Binary server=%q,client=%q doesn't exist on host machine, cannot continue",
				server, client)
		}

		t.Logf("Using server=%v,client=%v instead of original programs (server=%v,client=%v)",
			server, client, orig, orig)
	}

	selfChecker := ec.NewProcessChecker().WithBinary(ec.SuffixStringMatch(selfBinary))
	ncSrvChecker := ec.NewProcessChecker().
		WithBinary(ec.SuffixStringMatch(server)).
		WithArguments(ec.FullStringMatch("-nvlp 8081"))
	ncCliChecker := ec.NewProcessChecker().
		WithBinary(ec.SuffixStringMatch(client)).
		WithArguments(ec.FullStringMatch("127.0.0.1 8081"))

	checker := ec.NewUnorderedMultiResponseChecker(
		ec.NewExecEventChecker().
			HasProcess(selfChecker).
			HasParent().
			End(),
		ec.NewExecEventChecker().
			HasProcess(ncSrvChecker).
			HasParent(selfChecker).
			End(),
		ec.NewListenEventChecker().
			HasProcess(ncSrvChecker).
			HasParent(selfChecker).
			HasIP("0.0.0.0").
			HasPort(8081).
			HasProtocol(fgs.SocketProtocol_TCP).
			End(),
		ec.NewExecEventChecker().
			HasProcess(ncCliChecker).
			HasParent(selfChecker).
			End(),
		ec.NewConnectEventChecker().
			HasProcess(ncCliChecker).
			HasParent(selfChecker).
			HasDstIP("127.0.0.1").
			HasDstPort(8081).
			HasProtocol(fgs.SocketProtocol_TCP).
			End(),
	)

	obs := getBasicTcpObserver(t)
	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)

	readyWG.Wait()
	cmdServer := exec.Command(server, "-nvlp", "8081")
	assert.NoError(t, cmdServer.Start())
	time.Sleep(1000 * time.Millisecond)
	cmdClient := exec.Command(client, "127.0.0.1", "8081")
	assert.NoError(t, cmdClient.Start())

	err := observer.JsonTestCheck(t, checker)
	assert.NoError(t, err)

	killAndWaitCommand(t, cmdServer)
	killAndWaitCommand(t, cmdClient)
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

func TestExistingListenEvent(t *testing.T) {
	server := getNCCommand(t, "nc.traditional")
	selfChecker := ec.ProcessWithBinary(ec.SuffixStringMatch(selfBinary))
	ncChecker := ec.ProcessWithCommand(
		ec.SuffixStringMatch(server), ec.FullStringMatch("-nvlp 8081"),
	)

	checker := ec.NewUnorderedMultiResponseChecker(
		ec.NewExecEventChecker().
			HasProcess(selfChecker).
			HasParent().
			End(),
		ec.NewExecEventChecker().
			HasProcess(ncChecker).
			HasParent(selfChecker).
			End(),
		ec.NewListenEventChecker().
			HasProcess(ncChecker).
			HasParent(selfChecker).
			HasIP("0.0.0.0").
			HasPort(8081).
			HasProtocol(fgs.SocketProtocol_TCP).
			End(),
	)

	/* Start server before creating obs */
	cmdServer := exec.Command(server, "-nvlp", "8081")
	assert.NoError(t, cmdServer.Start())

	/* Create obs */
	getBasicTcpObserver(t)
	killAndWaitCommand(t, cmdServer)

	err := observer.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestExistingAcceptEvent(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
	defer cancel()

	server := getNCCommand(t, "nc.traditional")
	client := server

	selfChecker := ec.ProcessWithBinary(ec.SuffixStringMatch(selfBinary))
	ncChecker := ec.ProcessWithCommand(
		ec.SuffixStringMatch(server), ec.FullStringMatch("-nvlp 8081"),
	)

	checker := ec.NewUnorderedMultiResponseChecker(
		ec.NewExecEventChecker().
			HasProcess(selfChecker).
			HasParent().
			End(),
		ec.NewExecEventChecker().
			HasProcess(ncChecker).
			HasParent(selfChecker).
			End(),
		ec.NewListenEventChecker().
			HasProcess(ncChecker).
			HasParent(selfChecker).
			HasIP("0.0.0.0").
			HasPort(8081).
			HasProtocol(fgs.SocketProtocol_TCP).
			End(),
		ec.NewAcceptEventChecker().
			HasProcess(ncChecker).
			HasParent(selfChecker).
			HasSrcIP("127.0.0.1").
			HasSrcPort(8081).
			HasProtocol(fgs.SocketProtocol_TCP).
			End(),
	)

	/* Start server before creating obs */
	cmdServer := exec.Command(server, "-nvlp", "8081")
	assert.NoError(t, cmdServer.Start())
	time.Sleep(1000 * time.Millisecond)

	/* Create obs */
	obs := getBasicTcpObserver(t)
	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)

	readyWG.Wait()
	time.Sleep(1000 * time.Millisecond)
	cmdClient := exec.Command(client, "127.0.0.1", "8081")
	assert.NoError(t, cmdClient.Start())

	err := observer.JsonTestCheck(t, checker)
	assert.NoError(t, err)

	killAndWaitCommand(t, cmdServer)
	killAndWaitCommand(t, cmdClient)
}

func TestExistingRootCWDListenEvent(t *testing.T) {
	server := getNCCommand(t, "nc.traditional")
	selfChecker := ec.ProcessWithBinary(ec.SuffixStringMatch(selfBinary))
	ncChecker := ec.ProcessWithCommand(
		ec.SuffixStringMatch(server), ec.FullStringMatch("-nvlp 8081"),
	)

	checker := ec.NewUnorderedMultiResponseChecker(
		ec.NewExecEventChecker().
			HasProcess(selfChecker).
			HasParent().
			End(),
		ec.NewExecEventChecker().
			HasProcess(ncChecker).
			HasParent(selfChecker).
			End(),
		ec.NewListenEventChecker().
			HasProcess(ncChecker).
			HasParent(selfChecker).
			HasIP("0.0.0.0").
			HasPort(8081).
			HasProtocol(fgs.SocketProtocol_TCP).
			End(),
	)

	path, err := os.Getwd()
	if err != nil {
		t.Fail()
	}

	/* Start server in '/' before creating observer */
	os.Chdir("/")
	cmdServer := exec.Command(server, "-nvlp", "8081")
	assert.NoError(t, cmdServer.Start())
	os.Chdir(path)

	/* Create obs */
	getBasicTcpObserver(t)
	killAndWaitCommand(t, cmdServer)

	err = observer.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestListenAcceptClose(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
	defer cancel()

	server := getNCCommand(t, "nc.traditional")
	client := server

	selfChecker := ec.ProcessWithBinary(ec.SuffixStringMatch(selfBinary))
	ncSrvChecker := ec.ProcessWithCommand(
		ec.SuffixStringMatch(server), ec.FullStringMatch("-nvlp 8081"),
	)

	checker := ec.NewUnorderedMultiResponseChecker(
		ec.NewExecEventChecker().
			HasProcess(selfChecker).
			HasParent().
			End(),
		ec.NewExecEventChecker().
			HasProcess(ncSrvChecker).
			HasParent(selfChecker).
			End(),
		ec.NewListenEventChecker().
			HasProcess(ncSrvChecker).
			HasParent(selfChecker).
			HasIP("0.0.0.0").
			HasPort(8081).
			HasProtocol(fgs.SocketProtocol_TCP).
			End(),
		ec.NewAcceptEventChecker().
			HasProcess(ncSrvChecker).
			HasParent(selfChecker).
			HasSrcIP("127.0.0.1").
			HasSrcPort(8081).
			HasProtocol(fgs.SocketProtocol_TCP).
			End(),
		ec.NewCloseEventChecker().
			HasProcess(ncSrvChecker).
			HasParent(selfChecker).
			HasSrcIP("0.0.0.0").
			HasSrcPort(8081).
			HasProtocol(fgs.SocketProtocol_TCP).
			HasType("listen").
			End(),
		// TODO: it would be good if we could also check the close event on
		// the accept socket, but it goes into TIME_WAIT and then
		// eventually close and I don't want to wait for it. So we need
		// some go way to close the sockets.
	)

	exitChecker := ec.NewUnorderedMultiResponseChecker(
		ec.NewExitEventChecker().
			HasProcess(ncSrvChecker).
			HasParent(selfChecker).
			HasSignal(syscall.SIGKILL).
			End(),
	)

	obs := getBasicTcpObserver(t)
	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)

	readyWG.Wait()
	cmdServer := exec.Command(server, "-nvlp", "8081")
	assert.NoError(t, cmdServer.Start())
	time.Sleep(1000 * time.Millisecond)
	cmdClient := exec.Command(client, "127.0.0.1", "8081")
	assert.NoError(t, cmdClient.Start())

	err := observer.JsonTestCheck(t, checker)
	assert.NoError(t, err)

	killAndWaitCommand(t, cmdServer)
	killAndWaitCommand(t, cmdClient)

	err = observer.JsonTestCheck(t, exitChecker)
	assert.NoError(t, err)
}

func TestDockerExistingListenEvent(t *testing.T) {
	if err := exec.Command("docker", "version").Run(); err != nil {
		t.Skipf("docker not available. skipping test: %s", err)
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
	defer cancel()

	/* Start server before creating obs */
	observer.DockerRun(t, "--name", "fgs-test-server", "--entrypoint", "nc", "quay.io/cilium/alpine-curl:1.0", "-nvlp", "8081")
	observer.WaitForProcess("nc -nvlp 8081")
	time.Sleep(2 * time.Second)

	/* Create obs */
	obs := getBasicTcpObserver(t)
	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)

	// Ideally we would also verify the dockerID, but our current dockerID
	// scanner from procFS does not match github actions docker env that
	// does not prepend a 'docker' string to the cgroup name. For now
	// drop the comparison and just ensure we get the events.
	//fgsServerID := serverDockerID[:31]

	// Current code reports binary behind symlink in proc case (binaries running
	// before fgs starts), but in runtime event we report the name of the symlink.
	// In this test the difference is busybox vs nc.
	selfChecker := ec.ProcessWithBinary(ec.SuffixStringMatch(selfBinary))
	ncSrvChecker := ec.NewProcessChecker().
		WithBinary("/bin/busybox").
		WithArguments("-nvlp 8081").
		WithCWD("/").
		WithUID(0)

	checker := ec.NewUnorderedMultiResponseChecker(
		ec.NewExecEventChecker().
			HasProcess(selfChecker).
			HasParent().
			End(),
		ec.NewExecEventChecker().
			HasProcess(ncSrvChecker).
			End(),
		ec.NewListenEventChecker().
			HasProcess(ncSrvChecker).
			HasIP("0.0.0.0").
			HasPort(8081).
			HasProtocol(fgs.SocketProtocol_TCP).
			End(),
	)

	err := observer.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestDockerListenConnect(t *testing.T) {
	if err := exec.Command("docker", "version").Run(); err != nil {
		t.Skipf("docker not available. skipping test: %s", err)
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
	defer cancel()

	obs := getBasicTcpObserver(t)
	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)

	readyWG.Wait()
	serverDockerID := observer.DockerRun(t, "--name", "fgs-test-server", "--entrypoint", "nc", "quay.io/cilium/alpine-curl:1.0", "-nvlp", "8081")
	time.Sleep(1 * time.Second)
	clientDockerID := observer.DockerRun(t, "--link", "fgs-test-server", "--entrypoint", "nc", "quay.io/cilium/alpine-curl:1.0", "-p", "9876", "fgs-test-server", "8081")

	// FGS sends 31 bytes + \0 to user-space. Since it might have an arbitrary prefix,
	// match only on the first 24 bytes.
	fgsServerID := ec.PrefixStringMatch(serverDockerID[:24])
	fgsClientID := ec.PrefixStringMatch(clientDockerID[:24])

	selfChecker := ec.ProcessWithBinary(ec.SuffixStringMatch(selfBinary))
	ncSrvChecker := ec.NewProcessChecker().
		WithBinary("/usr/bin/nc").
		WithArguments("-nvlp 8081").
		WithCWD("/").
		WithUID(0).
		WithDocker(fgsServerID)
	ncCliChecker := ec.NewProcessChecker().
		WithBinary("/usr/bin/nc").
		WithArguments("-p 9876 fgs-test-server 8081").
		WithCWD("/").
		WithUID(0).
		WithDocker(fgsClientID)

	checker := ec.NewUnorderedMultiResponseChecker(
		ec.NewExecEventChecker().
			HasProcess(selfChecker).
			HasParent().
			End(),
		ec.NewExecEventChecker().
			HasProcess(ncSrvChecker).
			End(),
		ec.NewListenEventChecker().
			HasProcess(ncSrvChecker).
			HasIP("0.0.0.0").
			HasPort(8081).
			End(),
		ec.NewExecEventChecker().
			HasProcess(ncCliChecker).
			End(),
		ec.NewConnectEventChecker().
			HasProcess(ncCliChecker).
			HasDstPort(8081).
			HasSrcPort(9876).
			HasProtocol(fgs.SocketProtocol_TCP).
			End(),
		ec.NewCloseEventChecker().
			HasProcess(ncSrvChecker).
			HasSrcIP("0.0.0.0").
			HasSrcPort(8081).
			HasType("listen").
			End(),
		ec.NewCloseEventChecker().
			HasProcess(ncCliChecker).
			HasDstPort(8081).
			HasSrcPort(9876).
			HasProtocol(fgs.SocketProtocol_TCP).
			HasType("connect").
			End(),
	)

	err := observer.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

const BUFSIZE, BUFVAR = 1024, 256
const hostname = "127.0.0.1"
const portno = 31337
const protocol = "tcp4"

func handleSes(ses net.Conn) {
	buf := make([]byte, 2*BUFSIZE)
	quit := false
	for !quit {
		_, err := ses.Read(buf)
		if err != nil {
			quit = true
		}
	}
}

func tcpServer() {

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM)
	go func() {
		sig := <-sigs
		if sig == syscall.SIGTERM {
			os.Exit(0)
		}
	}()

	conn, err := net.Listen(protocol, fmt.Sprintf("%s:%d", hostname, portno))
	if err != nil {
		panic(err)
	}
	fmt.Printf("Ready\n")

	for {
		ses, err := conn.Accept()
		if err != nil {
			panic(err)
		}
		go handleSes(ses)
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

func tcpClient() {
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

func TestTcpBurst(t *testing.T) {

	if v := "5.8.0"; !kernels.MinKernelVersion(v) {
		t.Skipf("Minimum kernel version (%v) not met, skipping", v)
	}

	bpf.CheckOrMountCgroup2()

	clientProcess := ec.ProcessWithCommand(ec.SuffixStringMatch(selfBinary), ec.FullStringMatch("-client"))
	serverProcess := ec.ProcessWithCommand(ec.SuffixStringMatch(selfBinary), ec.FullStringMatch("-server"))

	ProcessNetworkBurstEgressStart := ec.NewProcessNetworkBurstChecker().
		WithBurstProtocol("TCP").
		WithBurstDirection("egress").
		WithBurstState("start")
	ProcessNetworkBurstEgressEnd := ec.NewProcessNetworkBurstChecker().
		WithBurstProtocol("TCP").
		WithBurstDirection("egress").
		WithBurstState("end")
	ProcessNetworkBurstIngressStart := ec.NewProcessNetworkBurstChecker().
		WithBurstProtocol("TCP").
		WithBurstDirection("ingress").
		WithBurstState("start")
	ProcessNetworkBurstIngressEnd := ec.NewProcessNetworkBurstChecker().
		WithBurstProtocol("TCP").
		WithBurstDirection("ingress").
		WithBurstState("end")

	checker := ec.NewUnorderedMultiResponseChecker(
		ec.NewExecEventChecker().
			HasProcess(clientProcess).
			End(),
		ec.NewProcessNetworkBurstEventChecker().
			HasProcess(clientProcess).
			HasProcessNetworkBurst(ProcessNetworkBurstEgressStart).
			End(),
		ec.NewProcessNetworkBurstEventChecker().
			HasProcess(clientProcess).
			HasProcessNetworkBurst(ProcessNetworkBurstEgressEnd).
			End(),
		ec.NewExecEventChecker().
			HasProcess(serverProcess).
			End(),
		ec.NewProcessNetworkBurstEventChecker().
			HasProcess(serverProcess).
			HasProcessNetworkBurst(ProcessNetworkBurstIngressStart).
			End(),
		ec.NewProcessNetworkBurstEventChecker().
			HasProcess(serverProcess).
			HasProcessNetworkBurst(ProcessNetworkBurstIngressEnd).
			End(),
	)

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
	defer cancel()

	if err := observer.WriteConfigFile(testConfigFile, tcpConfig); err != nil {
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
	processKey := &burstEventsPoll.ProcessNetworkBurstKey{Key: burstEventsPoll.PidToBurstKey(serverPid, syscall.IPPROTO_TCP, 0)}
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

func TestNamespaces(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
	defer cancel()

	rootNs := reader.GetCurrentNamespace()
	selfChecker := ec.NewProcessChecker().WithBinary(ec.SuffixStringMatch(selfBinary)).WithNs(rootNs)

	checker := ec.NewUnorderedMultiResponseChecker(
		ec.NewExecEventChecker().
			HasProcess(selfChecker).
			HasParent().
			End(),
	)

	obs, err := observer.GetDefaultObserver(t, fgsLib)
	if err != nil {
		t.Fatalf("GetDefaultObserver error: %s", err)
	}

	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()
	err = observer.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

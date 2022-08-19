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
	"github.com/cilium/tetragon/api/v1/tetragon"
	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/kernels"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/reader/namespace"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/stretchr/testify/assert"

	"github.com/cilium/tetragon/pkg/jsonchecker"
	"github.com/isovalent/hubble-fgs/pkg/sensors/base"
	"github.com/isovalent/hubble-fgs/pkg/sensors/burstEventsPoll"
	"github.com/isovalent/hubble-fgs/pkg/testutils/runner"

	_ "github.com/cilium/tetragon/pkg/sensors"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/exec"

	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
)

var (
	client bool
	server bool
)

const (
	testConfigFile = "/tmp/hubble-tetragon.gotest.yaml"
)

const tcpConfig = `
apiversion: cilium.io/v1alpha1
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
apiversion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "tcp"
spec:
  parser:
    tcp:
      enable: true
`

func init() {
	flag.BoolVar(&client, "client", false, "internal")
	flag.BoolVar(&server, "server", false, "internal")
}

// NB(kkourt): Function(t *testing.T, ctx context.Context) is the reasonable
// thing to do here even if revive complains.
//revive:disable:context-as-argument
func getBasicTcpObserver(t *testing.T, ctx context.Context) *observer.Observer {
	if err := observer.WriteConfigFile(testConfigFile, tcpBasicConfig); err != nil {
		t.Fatalf("WriteFile(%s): err %s", testConfigFile, err)
	}
	obs, err := observer.GetDefaultObserverWithLib(t, ctx, testConfigFile, runner.Conf().TetragonLib)
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
	ec := runner.TestSensorsRun(m, "SensorTcp")
	os.Exit(ec)
}

func TestConnectEvent(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	curlChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix("curl")).
		WithArguments(sm.Full("127.0.0.1"))

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker().
			WithProcess(selfChecker).
			WithParent(ec.NewProcessChecker()),
		ec.NewProcessExecChecker().
			WithProcess(curlChecker).
			WithParent(selfChecker),
		ec.NewProcessConnectChecker().
			WithProcess(curlChecker).
			WithParent(selfChecker).
			WithDestinationIp(sm.Full("127.0.0.1")).
			WithDestinationPort(80).
			WithProtocol(tetragon.SocketProtocol_TCP),
		ec.NewProcessCloseChecker().
			WithProcess(curlChecker).
			WithParent(selfChecker).
			WithDestinationIp(sm.Full("127.0.0.1")).
			WithDestinationPort(80).
			WithProtocol(tetragon.SocketProtocol_TCP).
			WithSocketType(sm.Full("connect")),
	)

	obs := getBasicTcpObserver(t, ctx)
	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	observer.ExecWGCurl(&readyWG, 10, "127.0.0.1")
	err := jsonchecker.JsonTestCheck(t, checker)
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

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
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

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	ncSrvChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(server)).
		WithArguments(sm.Full("-nvlp 8081"))

	ncCliChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(client)).
		WithArguments(sm.Full("127.0.0.1 8081"))

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker().
			WithProcess(selfChecker).
			WithParent(ec.NewProcessChecker()),
		ec.NewProcessExecChecker().
			WithProcess(ncSrvChecker).
			WithParent(selfChecker),
		ec.NewProcessListenChecker().
			WithProcess(ncSrvChecker).
			WithParent(selfChecker).
			WithIp(sm.Full("0.0.0.0")).
			WithPort(8081).
			WithProtocol(tetragon.SocketProtocol_TCP),
		ec.NewProcessExecChecker().
			WithProcess(ncCliChecker).
			WithParent(selfChecker),
		ec.NewProcessConnectChecker().
			WithProcess(ncCliChecker).
			WithParent(selfChecker).
			WithDestinationIp(sm.Full("127.0.0.1")).
			WithDestinationPort(8081).
			WithProtocol(tetragon.SocketProtocol_TCP),
	)

	obs := getBasicTcpObserver(t, ctx)
	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)

	readyWG.Wait()
	cmdServer := exec.Command(server, "-nvlp", "8081")
	assert.NoError(t, cmdServer.Start())
	time.Sleep(1000 * time.Millisecond)
	cmdClient := exec.Command(client, "127.0.0.1", "8081")
	assert.NoError(t, cmdClient.Start())

	err := jsonchecker.JsonTestCheck(t, checker)
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

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	ncChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(server)).
		WithArguments(sm.Full("-nvlp 8081"))

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker().
			WithProcess(selfChecker).
			WithParent(ec.NewProcessChecker()),
		ec.NewProcessExecChecker().
			WithProcess(ncChecker).
			WithParent(selfChecker),
		ec.NewProcessListenChecker().
			WithProcess(ncChecker).
			WithParent(selfChecker).
			WithIp(sm.Full("0.0.0.0")).
			WithPort(8081).
			WithProtocol(tetragon.SocketProtocol_TCP),
	)

	/* Start server before creating obs */
	cmdServer := exec.Command(server, "-nvlp", "8081")
	assert.NoError(t, cmdServer.Start())

	time.Sleep(1000 * time.Millisecond)

	/* Create obs */
	getBasicTcpObserver(t, context.TODO())
	killAndWaitCommand(t, cmdServer)

	err := jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestExistingAcceptEvent(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	server := getNCCommand(t, "nc.traditional")
	client := server

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	ncChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(server)).
		WithArguments(sm.Full("-nvlp 8081"))

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker().
			WithProcess(selfChecker).
			WithParent(ec.NewProcessChecker()),
		ec.NewProcessExecChecker().
			WithProcess(ncChecker).
			WithParent(selfChecker),
		ec.NewProcessListenChecker().
			WithProcess(ncChecker).
			WithParent(selfChecker).
			WithIp(sm.Full("0.0.0.0")).
			WithPort(8081).
			WithProtocol(tetragon.SocketProtocol_TCP),
		ec.NewProcessAcceptChecker().
			WithProcess(ncChecker).
			WithParent(selfChecker).
			WithSourceIp(sm.Full("127.0.0.1")).
			WithSourcePort(8081).
			WithProtocol(tetragon.SocketProtocol_TCP),
	)

	/* Start server before creating obs */
	cmdServer := exec.Command(server, "-nvlp", "8081")
	assert.NoError(t, cmdServer.Start())
	time.Sleep(1000 * time.Millisecond)

	/* Create obs */
	obs := getBasicTcpObserver(t, ctx)
	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)

	readyWG.Wait()
	time.Sleep(1000 * time.Millisecond)
	cmdClient := exec.Command(client, "127.0.0.1", "8081")
	assert.NoError(t, cmdClient.Start())

	err := jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)

	killAndWaitCommand(t, cmdServer)
	killAndWaitCommand(t, cmdClient)
}

func TestExistingRootCWDListenEvent(t *testing.T) {
	server := getNCCommand(t, "nc.traditional")

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	ncChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(server)).
		WithArguments(sm.Full("-nvlp 8081")).
		WithCwd(sm.Full("/"))

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker().
			WithProcess(selfChecker).
			WithParent(ec.NewProcessChecker()),
		ec.NewProcessExecChecker().
			WithProcess(ncChecker).
			WithParent(selfChecker),
		ec.NewProcessListenChecker().
			WithProcess(ncChecker).
			WithParent(selfChecker).
			WithIp(sm.Full("0.0.0.0")).
			WithPort(8081).
			WithProtocol(tetragon.SocketProtocol_TCP),
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
	getBasicTcpObserver(t, context.TODO())
	killAndWaitCommand(t, cmdServer)

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestListenAcceptClose(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	server := getNCCommand(t, "nc.traditional")
	client := server

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	ncChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(server)).
		WithArguments(sm.Full("-nvlp 8081"))

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker().
			WithProcess(selfChecker).
			WithParent(ec.NewProcessChecker()),
		ec.NewProcessExecChecker().
			WithProcess(ncChecker).
			WithParent(selfChecker),
		ec.NewProcessListenChecker().
			WithProcess(ncChecker).
			WithParent(selfChecker).
			WithIp(sm.Full("0.0.0.0")).
			WithPort(8081).
			WithProtocol(tetragon.SocketProtocol_TCP),
		ec.NewProcessAcceptChecker().
			WithProcess(ncChecker).
			WithParent(selfChecker).
			WithSourceIp(sm.Full("127.0.0.1")).
			WithSourcePort(8081).
			WithProtocol(tetragon.SocketProtocol_TCP),
		ec.NewProcessCloseChecker().
			WithProcess(ncChecker).
			WithParent(selfChecker).
			WithSourceIp(sm.Full("0.0.0.0")).
			WithSourcePort(8081).
			WithProtocol(tetragon.SocketProtocol_TCP).
			WithSocketType(sm.Full("listen")),
		// TODO: it would be good if we could also check the close event on
		// the accept socket, but it goes into TIME_WAIT and then
		// eventually close and I don't want to wait for it. So we need
		// some go way to close the sockets.
	)

	exitChecker := ec.NewUnorderedEventChecker(
		ec.NewProcessExitChecker().
			WithProcess(ncChecker).
			WithParent(selfChecker).
			WithSignal(sm.Full("SIGKILL")),
	)

	obs := getBasicTcpObserver(t, ctx)
	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)

	readyWG.Wait()
	cmdServer := exec.Command(server, "-nvlp", "8081")
	assert.NoError(t, cmdServer.Start())
	time.Sleep(1000 * time.Millisecond)
	cmdClient := exec.Command(client, "127.0.0.1", "8081")
	assert.NoError(t, cmdClient.Start())

	err := jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)

	killAndWaitCommand(t, cmdServer)
	killAndWaitCommand(t, cmdClient)

	err = jsonchecker.JsonTestCheck(t, exitChecker)
	assert.NoError(t, err)
}

func TestDockerExistingListenEvent(t *testing.T) {
	if err := exec.Command("docker", "version").Run(); err != nil {
		t.Skipf("docker not available. skipping test: %s", err)
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	/* Start server before creating obs */
	observer.DockerRun(t, "--name", "fgs-test-server", "--entrypoint", "nc", "quay.io/cilium/alpine-curl:1.0", "-nvlp", "8081")
	observer.WaitForProcess("nc -nvlp 8081")
	time.Sleep(2 * time.Second)

	/* Create obs */
	obs := getBasicTcpObserver(t, ctx)
	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)

	// Ideally we would also verify the dockerID, but our current dockerID
	// scanner from procFS does not match github actions docker env that
	// does not prepend a 'docker' string to the cgroup name. For now
	// drop the comparison and just ensure we get the events.
	//fgsServerID := serverDockerID[:31]

	// Current code reports binary behind symlink in proc case (binaries running
	// before fgs starts), but in runtime event we report the name of the symlink.
	// In this test the difference is busybox vs nc.
	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	ncChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix("busybox")).
		WithArguments(sm.Full("-nvlp 8081")).
		WithCwd(sm.Full("/")).
		WithUid(0)

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker().
			WithProcess(selfChecker).
			WithParent(ec.NewProcessChecker()),
		ec.NewProcessExecChecker().
			WithProcess(ncChecker),
		ec.NewProcessListenChecker().
			WithProcess(ncChecker).
			WithIp(sm.Full("0.0.0.0")).
			WithPort(8081).
			WithProtocol(tetragon.SocketProtocol_TCP),
	)

	err := jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestDockerListenConnect(t *testing.T) {
	if err := exec.Command("docker", "version").Run(); err != nil {
		t.Skipf("docker not available. skipping test: %s", err)
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	obs := getBasicTcpObserver(t, ctx)
	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)

	readyWG.Wait()
	serverDockerID := observer.DockerRun(t, "--name", "fgs-test-server", "--entrypoint", "nc", "quay.io/cilium/alpine-curl:1.0", "-nvlp", "8081")
	time.Sleep(1 * time.Second)
	clientDockerID := observer.DockerRun(t, "--link", "fgs-test-server", "--entrypoint", "nc", "quay.io/cilium/alpine-curl:1.0", "-p", "9876", "fgs-test-server", "8081")

	// FGS sends 31 bytes + \0 to user-space. Since it might have an arbitrary prefix,
	// match only on the first 24 bytes.
	fgsServerID := sm.Prefix(serverDockerID[:24])
	fgsClientID := sm.Prefix(clientDockerID[:24])

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	ncSrvChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix("/nc")).
		WithArguments(sm.Full("-nvlp 8081")).
		WithCwd(sm.Full("/")).
		WithUid(0).
		WithDocker(fgsServerID)

	ncCliChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix("/nc")).
		WithArguments(sm.Full("-p 9876 fgs-test-server 8081")).
		WithCwd(sm.Full("/")).
		WithUid(0).
		WithDocker(fgsClientID)

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker().
			WithProcess(selfChecker).
			WithParent(ec.NewProcessChecker()),
		ec.NewProcessExecChecker().
			WithProcess(ncSrvChecker),
		ec.NewProcessListenChecker().
			WithProcess(ncSrvChecker).
			WithIp(sm.Full("0.0.0.0")).
			WithPort(8081).
			WithProtocol(tetragon.SocketProtocol_TCP),
		ec.NewProcessExecChecker().
			WithProcess(ncCliChecker),
		ec.NewProcessConnectChecker().
			WithProcess(ncCliChecker).
			WithDestinationPort(8081).
			WithSourcePort(9876).
			WithProtocol(tetragon.SocketProtocol_TCP),
		ec.NewProcessCloseChecker().
			WithProcess(ncSrvChecker).
			WithSourceIp(sm.Full("0.0.0.0")).
			WithSourcePort(8081).
			WithProtocol(tetragon.SocketProtocol_TCP).
			WithSocketType(sm.Full("listen")),
		ec.NewProcessCloseChecker().
			WithProcess(ncCliChecker).
			WithDestinationPort(8081).
			WithSourcePort(9876).
			WithProtocol(tetragon.SocketProtocol_TCP).
			WithSocketType(sm.Full("connect")),
	)

	err := jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

const BUFSIZE, BUFVAR = 1024, 256
const hostname = "127.0.0.1"
const portno = 31337
const protocol = "tcp4"

var burstQuit = false

func handleSes(ses net.Conn) {
	buf := make([]byte, 2*BUFSIZE)
	quit := false
	ses.SetDeadline(time.Now().Add(200 * time.Millisecond))
	for !quit && !burstQuit {
		_, err := ses.Read(buf)
		if err != nil {
			opErr, ok := err.(*net.OpError)
			if !ok || !opErr.Timeout() {
				quit = true
			}
		}
	}
}

func tcpServer() {

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM)
	conn, err := net.Listen(protocol, fmt.Sprintf("%s:%d", hostname, portno))
	if err != nil {
		panic(err)
	}
	go func() {
		sig := <-sigs
		if sig == syscall.SIGTERM {
			conn.Close()
			burstQuit = true
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

	socket.Close()
}

func TestTcpBurst(t *testing.T) {

	if v := "5.8.0"; !kernels.MinKernelVersion(v) {
		t.Skipf("Minimum kernel version (%v) not met, skipping", v)
	}

	bpf.CheckOrMountCgroup2()

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))
	clientProcess := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary)).
		WithArguments(sm.Full("-client"))
	serverProcess := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary)).
		WithArguments(sm.Full("-server"))

	burstEgressStart := ec.NewProcessNetworkBurstChecker().
		WithProcess(clientProcess).
		WithParent(selfChecker).
		WithProtocol(sm.Full("TCP")).
		WithDirection(sm.Full("egress")).
		WithBurstState(sm.Full("start"))
	burstEgressEnd := ec.NewProcessNetworkBurstChecker().
		WithProcess(clientProcess).
		WithParent(selfChecker).
		WithProtocol(sm.Full("TCP")).
		WithDirection(sm.Full("egress")).
		WithBurstState(sm.Full("end"))
	burstIngressStart := ec.NewProcessNetworkBurstChecker().
		WithProcess(serverProcess).
		WithParent(selfChecker).
		WithProtocol(sm.Full("TCP")).
		WithDirection(sm.Full("ingress")).
		WithBurstState(sm.Full("start"))
	burstIngressEnd := ec.NewProcessNetworkBurstChecker().
		WithProcess(serverProcess).
		WithParent(selfChecker).
		WithProtocol(sm.Full("TCP")).
		WithDirection(sm.Full("ingress")).
		WithBurstState(sm.Full("end"))

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker().
			WithProcess(clientProcess).
			WithParent(selfChecker),
		burstEgressStart,
		burstEgressEnd,
		ec.NewProcessExecChecker().
			WithProcess(serverProcess).
			WithParent(selfChecker),
		burstIngressStart,
		burstIngressEnd,
	)

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	if err := observer.WriteConfigFile(testConfigFile, tcpConfig); err != nil {
		t.Fatalf("WriteFile(%s): err %s", testConfigFile, err)
	}
	dfltBase := base.GetInitialSensor()
	obs, err := observer.GetDefaultObserverWithBase(t, ctx, dfltBase, testConfigFile, runner.Conf().TetragonLib)
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

	err = jsonchecker.JsonTestCheck(t, checker)
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

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	rootNs := namespace.GetCurrentNamespace()
	nsChecker := ec.NewNamespacesChecker().FromNamespaces(rootNs)

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary)).
		WithNs(nsChecker)

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker().
			WithProcess(selfChecker).
			WithParent(ec.NewProcessChecker()),
	)

	obs, err := observer.GetDefaultObserver(t, ctx, runner.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserver error: %s", err)
	}

	observer.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()
	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestLoadTcpSensor(t *testing.T) {
	if err := observer.WriteConfigFile(testConfigFile, tcpBasicConfig); err != nil {
		t.Fatalf("WriteFile(%s): err %s", testConfigFile, err)
	}

	sens, err := observer.GetDefaultSensorsWithFile(t, context.TODO(), testConfigFile, runner.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultSensorsWithFile error: %s", err)
	}

	var sensorProgs = []tus.SensorProg{
		0: tus.SensorProg{Name: "event_tcp4_connect", Type: ebpf.Kprobe},
		1: tus.SensorProg{Name: "event_tcp4_close", Type: ebpf.Kprobe},
		2: tus.SensorProg{Name: "event_sys_listen", Type: ebpf.Kprobe},
		3: tus.SensorProg{Name: "event_tcp_v4_send_check", Type: ebpf.Kprobe},

		// base sensor
		4: tus.SensorProg{Name: "event_execve", Type: ebpf.TracePoint},
		5: tus.SensorProg{Name: "event_exit", Type: ebpf.TracePoint},
		6: tus.SensorProg{Name: "event_wake_up_new_task", Type: ebpf.Kprobe},
	}

	var sensorMaps = []tus.SensorMap{
		// all but base
		tus.SensorMap{Name: "socket_map", Progs: []uint{0, 1, 2, 3}},

		// all but base, event_tcp_v4_send_check
		tus.SensorMap{Name: "socket_map_stats", Progs: []uint{0, 1, 2}},

		// all programs
		tus.SensorMap{Name: "tcpmon_map", Progs: []uint{0, 1, 2, 3, 4, 5, 6}},

		// all but event_tcp4_close
		tus.SensorMap{Name: "execve_map", Progs: []uint{0, 2, 3, 4, 5, 6}},
		tus.SensorMap{Name: "execve_map_stats", Progs: []uint{0, 2, 3, 4, 5, 6}},
	}

	tus.CheckSensorLoad(sens, sensorMaps, sensorProgs, t)

	sensors.UnloadAll(tus.Conf().TetragonLib)
}

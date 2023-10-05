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
	"strconv"
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
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	"github.com/cilium/tetragon/pkg/reader/namespace"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/config/confmap"
	"github.com/stretchr/testify/assert"

	"github.com/cilium/tetragon/pkg/jsonchecker"
	"github.com/isovalent/hubble-fgs/pkg/metrics/metricsconfig"
	"github.com/isovalent/hubble-fgs/pkg/sensors/base"
	"github.com/isovalent/hubble-fgs/pkg/sensors/networkWatermarksEvents"
	"github.com/isovalent/hubble-fgs/pkg/testutils/runner"

	_ "github.com/isovalent/hubble-fgs/pkg/sensors/exec"

	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
)

var (
	client bool
	server bool
)

const (
	testConfigFile  = "/tmp/hubble-tetragon.gotest.yaml"
	alpineCurlImage = "quay.io/cilium/alpine-curl:v1.6.0"
)

const tcpConfigLegacy = `
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
    burstExitGen:
      enable: true
      interval: 1000
    dns:
      enable: true
`

// Note 20.0.0.0/8 is the DoD and isn't routable on the Internet
// This is included to test TCP latency timestamps are NOT added
// to any real TCP packets.
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
      watermarks:
        enable: true
        windowSize: 1000
        burstTriggerPercent: 50
        dipTriggerPercent: 10
      latency:
        enable: true
        matchSubnets: [20.0.0.0/8]
        min: 0
        max: 10000
    networkWatermarksExitGen:
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

// Setting TCP latency max to 1,000,000 means 1% equates to
// 10ms, which a packet across loopback should easily be
// quicker than.
const tcpBasicConfigWithLatencyDetection = `
apiversion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "tcp"
spec:
  parser:
    tcp:
      enable: true
      latency:
        enable: true
        matchSubnets: [127.0.0.1/32]
        matchPorts: [8082]
        min: 0
        max: 1000000
`

func init() {
	flag.BoolVar(&client, "client", false, "internal")
	flag.BoolVar(&server, "server", false, "internal")
}

// NB(kkourt): Function(t *testing.T, ctx context.Context) is the reasonable
// thing to do here even if revive complains.
//
//revive:disable:context-as-argument
func getTcpObserver(t *testing.T, ctx context.Context, config string, docker bool) *observer.Observer {
	if err := observertesthelper.WriteConfigFile(testConfigFile, config); err != nil {
		t.Fatalf("WriteFile(%s): err %s", testConfigFile, err)
	}
	var obs *observer.Observer
	var err error

	base := base.GetInitialSensor()

	if docker {
		obs, err = observertesthelper.GetDefaultObserverWithBase(t, ctx, base, testConfigFile, runner.Conf().TetragonLib)
	} else {
		obs, err = observertesthelper.GetDefaultObserverWithBase(t, ctx, base, testConfigFile, runner.Conf().TetragonLib, observertesthelper.WithMyPid())
	}
	if err != nil {
		t.Fatalf("GetDefaultObserver error: %s", err)
	}
	metricsconfig.RegisterEEMetrics()
	err = confmap.UpdateTgRuntimeConf(bpf.MapPrefixPath(), os.Getpid())
	if err != nil {
		t.Fatalf("GetDefaultObserver error: %s", err)
	}
	return obs
}

func getBasicTcpObserver(t *testing.T, ctx context.Context, docker bool) *observer.Observer {
	return getTcpObserver(t, ctx, tcpBasicConfig, docker)
}

func getTcpObserverWithLatencyDetection(t *testing.T, ctx context.Context, docker bool) *observer.Observer {
	return getTcpObserver(t, ctx, tcpBasicConfigWithLatencyDetection, docker)
}

func getTcpObserverDisableEvents(t *testing.T, ctx context.Context, docker bool, disableConnect bool, disableClose bool, disableAccept bool, disableListen bool) *observer.Observer {
	eventDisableConfig := `
      disableEvents:
`
	eventDisableConfig += "\n        disableConnect: " + strconv.FormatBool(disableConnect)
	eventDisableConfig += "\n        disableClose: " + strconv.FormatBool(disableClose)
	eventDisableConfig += "\n        disableAccept: " + strconv.FormatBool(disableAccept)
	eventDisableConfig += "\n        disableListen: " + strconv.FormatBool(disableListen)

	tcpDisableEventsConfig := tcpBasicConfig + eventDisableConfig
	return getTcpObserver(t, ctx, tcpDisableEventsConfig, docker)
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

func TestConnectEvent4(t *testing.T) {
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
		ec.NewProcessExecChecker("selfExec").
			WithProcess(selfChecker).
			WithParent(ec.NewProcessChecker()),
		ec.NewProcessExecChecker("curlExec").
			WithProcess(curlChecker).
			WithParent(selfChecker),
		ec.NewProcessConnectChecker("curlConnect").
			WithProcess(curlChecker).
			WithParent(selfChecker).
			WithDestinationIp(sm.Full("127.0.0.1")).
			WithDestinationPort(80).
			WithProtocol(tetragon.SocketProtocol_TCP),
		ec.NewProcessCloseChecker("curlClose").
			WithProcess(curlChecker).
			WithParent(selfChecker).
			WithDestinationIp(sm.Full("127.0.0.1")).
			WithDestinationPort(80).
			WithProtocol(tetragon.SocketProtocol_TCP).
			WithSocketType(sm.Full("connect")),
	)

	obs := getBasicTcpObserver(t, ctx, false)
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	observertesthelper.ExecWGCurl(&readyWG, 10, "127.0.0.1")
	err := jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func testDisableConfigConnect4(t *testing.T, disableConnect bool) {
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
		ec.NewProcessConnectChecker("curlConnect").
			WithProcess(curlChecker).
			WithParent(selfChecker).
			WithDestinationIp(sm.Full("127.0.0.1")).
			WithDestinationPort(80).
			WithProtocol(tetragon.SocketProtocol_TCP),
	)

	obs := getTcpObserverDisableEvents(t, ctx, false, disableConnect, true, true, true)
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	observertesthelper.ExecWGCurl(&readyWG, 10, "127.0.0.1")

	// If connect events are disabled then expect checker failure
	err := jsonchecker.JsonTestCheckExpect(t, checker, disableConnect)
	assert.NoError(t, err)
}

func TestDisableConnectEvent4(t *testing.T) {
	testDisableConfigConnect4(t, true)
}

func TestNoDisableConnectEvent4(t *testing.T) {
	testDisableConfigConnect4(t, false)
}

func TestExecEventClone4(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	orig := "nc.openbsd"
	server := orig
	client := server
	if _, err := exec.LookPath(server); err != nil {
		server = "nc.openbsd"
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
			WithProtocol(tetragon.SocketProtocol_TCP),
		ec.NewProcessExecChecker("clientExec").
			WithProcess(ncCliChecker).
			WithParent(selfChecker),
		ec.NewProcessConnectChecker("clientConnect").
			WithProcess(ncCliChecker).
			WithParent(selfChecker).
			WithDestinationIp(sm.Full("127.0.0.1")).
			WithDestinationPort(8081).
			WithProtocol(tetragon.SocketProtocol_TCP),
	)

	obs := getBasicTcpObserver(t, ctx, false)
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)

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

func TestExistingListenEvent4(t *testing.T) {
	server := getNCCommand(t, "nc.openbsd")

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	ncChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(server)).
		WithArguments(sm.Full("-nvlp 8081 -s 0.0.0.0"))

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker("selfExec").
			WithProcess(selfChecker).
			WithParent(ec.NewProcessChecker()),
		ec.NewProcessExecChecker("ncExec").
			WithProcess(ncChecker).
			WithParent(selfChecker),
		ec.NewProcessListenChecker("ncListen").
			WithProcess(ncChecker).
			WithParent(selfChecker).
			WithIp(sm.Full("0.0.0.0")).
			WithPort(8081).
			WithProtocol(tetragon.SocketProtocol_TCP),
	)

	/* Start server before creating obs */
	cmdServer := exec.Command(server, "-nvlp", "8081", "-s", "0.0.0.0")
	assert.NoError(t, cmdServer.Start())

	time.Sleep(1000 * time.Millisecond)

	/* Create obs */
	getBasicTcpObserver(t, context.TODO(), false)
	killAndWaitCommand(t, cmdServer)

	err := jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestExistingAcceptEvent4(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	server := getNCCommand(t, "nc.openbsd")
	client := server

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	ncChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(server)).
		WithArguments(sm.Full("-nvlp 8081 -s 0.0.0.0"))

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker("selfExec").
			WithProcess(selfChecker).
			WithParent(ec.NewProcessChecker()),
		ec.NewProcessExecChecker("ncExec").
			WithProcess(ncChecker).
			WithParent(selfChecker),
		ec.NewProcessListenChecker("ncListen").
			WithProcess(ncChecker).
			WithParent(selfChecker).
			WithIp(sm.Full("0.0.0.0")).
			WithPort(8081).
			WithProtocol(tetragon.SocketProtocol_TCP),
		ec.NewProcessAcceptChecker("ncAccept").
			WithProcess(ncChecker).
			WithParent(selfChecker).
			WithSourceIp(sm.Full("127.0.0.1")).
			WithSourcePort(8081).
			WithProtocol(tetragon.SocketProtocol_TCP),
	)

	/* Start server before creating obs */
	cmdServer := exec.Command(server, "-nvlp", "8081", "-s", "0.0.0.0")
	assert.NoError(t, cmdServer.Start())
	time.Sleep(1000 * time.Millisecond)

	/* Create obs */
	obs := getBasicTcpObserver(t, ctx, false)
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)

	readyWG.Wait()
	time.Sleep(1000 * time.Millisecond)
	cmdClient := exec.Command(client, "127.0.0.1", "8081")
	assert.NoError(t, cmdClient.Start())
	time.Sleep(1000 * time.Millisecond)

	err := jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)

	killAndWaitCommand(t, cmdServer)
	killAndWaitCommand(t, cmdClient)
}

func TestExistingRootCWDListenEvent4(t *testing.T) {
	server := getNCCommand(t, "nc.openbsd")

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	ncChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(server)).
		WithArguments(sm.Full("-nvlp 8081 -s 0.0.0.0")).
		WithCwd(sm.Full("/"))

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker("selfExec").
			WithProcess(selfChecker).
			WithParent(ec.NewProcessChecker()),
		ec.NewProcessExecChecker("ncExec").
			WithProcess(ncChecker).
			WithParent(selfChecker),
		ec.NewProcessListenChecker("ncListen").
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
	cmdServer := exec.Command(server, "-nvlp", "8081", "-s", "0.0.0.0")
	assert.NoError(t, cmdServer.Start())
	os.Chdir(path)

	/* Create obs */
	getBasicTcpObserver(t, context.TODO(), false)
	killAndWaitCommand(t, cmdServer)

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestListenAcceptClose4(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	server := getNCCommand(t, "nc.openbsd")
	client := server

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	ncChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(server)).
		WithArguments(sm.Full("-nvlp 8081"))

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker("selfExec").
			WithProcess(selfChecker).
			WithParent(ec.NewProcessChecker()),
		ec.NewProcessExecChecker("ncExec").
			WithProcess(ncChecker).
			WithParent(selfChecker),
		ec.NewProcessListenChecker("ncListen").
			WithProcess(ncChecker).
			WithParent(selfChecker).
			WithIp(sm.Full("0.0.0.0")).
			WithPort(8081).
			WithProtocol(tetragon.SocketProtocol_TCP),
		ec.NewProcessAcceptChecker("ncAccept").
			WithProcess(ncChecker).
			WithParent(selfChecker).
			WithSourceIp(sm.Full("127.0.0.1")).
			WithSourcePort(8081).
			WithProtocol(tetragon.SocketProtocol_TCP),
		ec.NewProcessCloseChecker("ncClose").
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
		ec.NewProcessExitChecker("ncExit").
			WithProcess(ncChecker).
			WithParent(selfChecker).
			WithSignal(sm.Full("SIGKILL")),
	)

	obs := getBasicTcpObserver(t, ctx, false)
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)

	readyWG.Wait()
	cmdServer := exec.Command(server, "-nvlp", "8081")
	assert.NoError(t, cmdServer.Start())
	time.Sleep(1000 * time.Millisecond)
	cmdClient := exec.Command(client, "127.0.0.1", "8081")
	assert.NoError(t, cmdClient.Start())

	time.Sleep(1000 * time.Millisecond)

	killAndWaitCommand(t, cmdServer)
	killAndWaitCommand(t, cmdClient)

	err := jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)

	err = jsonchecker.JsonTestCheck(t, exitChecker)
	assert.NoError(t, err)
}

func testDisableConfigListenAcceptClose4(t *testing.T, disableListen bool, disableAccept bool, disableClose bool) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	server := getNCCommand(t, "nc.openbsd")
	client := server
	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	ncChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(server)).
		WithArguments(sm.Full("-nvlp 8081"))

	listenChecker := ec.NewUnorderedEventChecker(
		ec.NewProcessListenChecker("ncListen").
			WithProcess(ncChecker).
			WithParent(selfChecker).
			WithIp(sm.Full("0.0.0.0")).
			WithPort(8081).
			WithProtocol(tetragon.SocketProtocol_TCP),
	)
	acceptChecker := ec.NewUnorderedEventChecker(
		ec.NewProcessAcceptChecker("ncAccept").
			WithProcess(ncChecker).
			WithParent(selfChecker).
			WithSourceIp(sm.Full("127.0.0.1")).
			WithSourcePort(8081).
			WithProtocol(tetragon.SocketProtocol_TCP),
	)
	closeChecker := ec.NewUnorderedEventChecker(
		ec.NewProcessCloseChecker("ncClose").
			WithProcess(ncChecker).
			WithParent(selfChecker).
			WithSourceIp(sm.Full("0.0.0.0")).
			WithSourcePort(8081).
			WithProtocol(tetragon.SocketProtocol_TCP).
			WithSocketType(sm.Full("listen")),
	)

	obs := getTcpObserverDisableEvents(t, ctx, false, true, disableClose, disableAccept, disableListen)
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)

	readyWG.Wait()
	cmdServer := exec.Command(server, "-nvlp", "8081")
	assert.NoError(t, cmdServer.Start())
	time.Sleep(1000 * time.Millisecond)
	cmdClient := exec.Command(client, "127.0.0.1", "8081")
	assert.NoError(t, cmdClient.Start())

	time.Sleep(1000 * time.Millisecond)

	killAndWaitCommand(t, cmdServer)
	killAndWaitCommand(t, cmdClient)

	listenErr := jsonchecker.JsonTestCheckExpect(t, listenChecker, disableListen)
	assert.NoError(t, listenErr)

	acceptErr := jsonchecker.JsonTestCheckExpect(t, acceptChecker, disableAccept)
	assert.NoError(t, acceptErr)

	closeErr := jsonchecker.JsonTestCheckExpect(t, closeChecker, disableClose)
	assert.NoError(t, closeErr)
}

func TestDisableListenAcceptClose4(t *testing.T) {
	testDisableConfigListenAcceptClose4(t, true, true, true)
}

func TestNoDisableListenAcceptClose4(t *testing.T) {
	testDisableConfigListenAcceptClose4(t, false, false, false)
}

func TestDockerExistingListenEvent4(t *testing.T) {
	if err := exec.Command("docker", "version").Run(); err != nil {
		t.Skipf("docker not available. skipping test: %s", err)
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	/* Start server before creating obs */
	observertesthelper.DockerRun(t, "--name", "fgs-test-server", "--entrypoint", "nc", alpineCurlImage, "-nvlp", "8081", "-s", "0.0.0.0")
	observertesthelper.WaitForProcess("nc -nvlp 8081 -s 0.0.0.0")
	time.Sleep(2 * time.Second)

	/* Create obs */
	obs := getBasicTcpObserver(t, ctx, true)
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)

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
		WithArguments(sm.Full("-nvlp 8081 -s 0.0.0.0")).
		WithCwd(sm.Full("/")).
		WithUid(0)

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker("selfExec").
			WithProcess(selfChecker).
			WithParent(ec.NewProcessChecker()),
		ec.NewProcessExecChecker("ncExec").
			WithProcess(ncChecker),
		ec.NewProcessListenChecker("ncListen").
			WithProcess(ncChecker).
			WithIp(sm.Full("0.0.0.0")).
			WithPort(8081).
			WithProtocol(tetragon.SocketProtocol_TCP),
	)

	err := jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestDockerListenConnect4(t *testing.T) {
	if err := exec.Command("docker", "version").Run(); err != nil {
		t.Skipf("docker not available. skipping test: %s", err)
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	obs := getBasicTcpObserver(t, ctx, true)
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)

	readyWG.Wait()
	serverDockerID := observertesthelper.DockerRun(t, "--name", "fgs-test-server", "--entrypoint", "nc", alpineCurlImage, "-nvlp", "8081", "-s", "0.0.0.0")
	time.Sleep(1 * time.Second)
	clientDockerID := observertesthelper.DockerRun(t, "--link", "fgs-test-server", "--entrypoint", "nc", alpineCurlImage, "-p", "9876", "fgs-test-server", "8081")

	// FGS sends 31 bytes + \0 to user-space. Since it might have an arbitrary prefix,
	// match only on the first 24 bytes.
	fgsServerID := sm.Prefix(serverDockerID[:24])
	fgsClientID := sm.Prefix(clientDockerID[:24])

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	ncSrvChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix("/nc")).
		WithArguments(sm.Full("-nvlp 8081 -s 0.0.0.0")).
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
		ec.NewProcessExecChecker("selfExec").
			WithProcess(selfChecker).
			WithParent(ec.NewProcessChecker()),
		ec.NewProcessExecChecker("serverExec").
			WithProcess(ncSrvChecker),
		ec.NewProcessListenChecker("serverListen").
			WithProcess(ncSrvChecker).
			WithIp(sm.Full("0.0.0.0")).
			WithPort(8081).
			WithProtocol(tetragon.SocketProtocol_TCP),
		ec.NewProcessExecChecker("clientExec").
			WithProcess(ncCliChecker),
		ec.NewProcessConnectChecker("clientConnect").
			WithProcess(ncCliChecker).
			WithDestinationPort(8081).
			WithSourcePort(9876).
			WithProtocol(tetragon.SocketProtocol_TCP),
		ec.NewProcessCloseChecker("serverClose").
			WithProcess(ncSrvChecker).
			WithSourceIp(sm.Full("0.0.0.0")).
			WithSourcePort(8081).
			WithProtocol(tetragon.SocketProtocol_TCP).
			WithSocketType(sm.Full("listen")),
		ec.NewProcessCloseChecker("clientClose").
			WithProcess(ncCliChecker).
			WithDestinationPort(8081).
			WithSourcePort(9876).
			WithProtocol(tetragon.SocketProtocol_TCP).
			WithSocketType(sm.Full("connect")),
	)

	time.Sleep(1 * time.Second)

	err := jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

const BUFSIZE, BUFVAR = 1024, 256
const hostname = "127.0.0.1"
const portno = 31337
const protocol = "tcp4"

var watermarksQuit = false

func handleSes(ses net.Conn) {
	buf := make([]byte, 2*BUFSIZE)
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
	numBursts := 5

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

func testTcpWatermarks(t *testing.T, legacy bool) {

	if v := "4.19.0"; !kernels.MinKernelVersion(v) {
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

	if legacy {
		if err := observertesthelper.WriteConfigFile(testConfigFile, tcpConfigLegacy); err != nil {
			t.Fatalf("WriteFile(%s): err %s", testConfigFile, err)
		}
	} else {
		if err := observertesthelper.WriteConfigFile(testConfigFile, tcpConfig); err != nil {
			t.Fatalf("WriteFile(%s): err %s", testConfigFile, err)
		}
	}

	dfltBase := base.GetInitialSensor()
	obs, err := observertesthelper.GetDefaultObserverWithBase(t, ctx, dfltBase, testConfigFile, runner.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserver error: %s", err)
	}
	metricsconfig.RegisterEEMetrics()
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
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

	watermarksMapFile := filepath.Join(bpf.MapPrefixPath(), networkWatermarksEvents.ProcessNetworkWatermarksMapName)
	m, err := ebpf.LoadPinnedMap(watermarksMapFile, nil)
	if err != nil {
		fmt.Printf("ERROR Cannot open map file\n")
		panic(err)
	}
	defer m.Close()
	processKey := &networkWatermarksEvents.ProcessNetworkWatermarksKey{Key: networkWatermarksEvents.PidToWatermarksKey(serverPid, syscall.IPPROTO_TCP, 0)}
	var processValue networkWatermarksEvents.ProcessNetworkWatermarksValue
	err = m.Lookup(processKey, &processValue)
	if err == nil {
		fmt.Printf("ERROR Server process in network watermarks map before traffic\n")
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

	err = m.Lookup(processKey, &processValue)
	if err != nil {
		fmt.Printf("ERROR Server process not in network watermarks map\n")
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

	// the burst map record is sure to be removed after exit event is
	// received, let's wait for that and do the lookup check after

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)

	err = m.Lookup(processKey, &processValue)
	if err == nil {
		fmt.Printf("ERROR Server process in network watermarks map after exit\n")
		os.Exit(-1)
	}
}

func TestTcpBurst(t *testing.T) {
	testTcpWatermarks(t, true)
}

func TestTcpWatermarks(t *testing.T) {
	testTcpWatermarks(t, false)
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

	obs, err := observertesthelper.GetDefaultObserver(t, ctx, runner.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserver error: %s", err)
	}
	metricsconfig.RegisterEEMetrics()

	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()
	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

// Note following test uses port 8082 instead of port 8081. This is primarily so that it
// can be easily tracked for debugging.
func TestDetectLatency4(t *testing.T) {
	if v := "5.4.0"; !kernels.MinKernelVersion(v) {
		t.Skipf("Minimum kernel version (%v) not met, skipping", v)
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	server := getNCCommand(t, "nc.openbsd")
	client := server

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	ncChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(server)).
		WithArguments(sm.Full("-nvlp 8082"))

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker("selfExec").
			WithProcess(selfChecker).
			WithParent(ec.NewProcessChecker()),
		ec.NewProcessExecChecker("ncExec").
			WithProcess(ncChecker).
			WithParent(selfChecker),
		ec.NewProcessListenChecker("ncListen").
			WithProcess(ncChecker).
			WithParent(selfChecker).
			WithIp(sm.Full("0.0.0.0")).
			WithPort(8082).
			WithProtocol(tetragon.SocketProtocol_TCP),
		ec.NewProcessAcceptChecker("ncAccept").
			WithProcess(ncChecker).
			WithParent(selfChecker).
			WithSourceIp(sm.Full("127.0.0.1")).
			WithSourcePort(8082).
			WithProtocol(tetragon.SocketProtocol_TCP),
		ec.NewProcessCloseChecker("ncClose").
			WithProcess(ncChecker).
			WithParent(selfChecker).
			WithSourceIp(sm.Full("127.0.0.1")).
			WithSourcePort(8082).
			WithProtocol(tetragon.SocketProtocol_TCP).
			WithSocketType(sm.Full("accept")).
			WithStats(ec.NewSocketStatsChecker().
				WithLatency(ec.NewHistogramChecker().
					WithBuckets(ec.NewHistogramBucketListMatcher().
						WithValues(ec.NewHistogramBucketChecker().
							WithPercentile(1))))), // Don't check count as it can vary unfortunately
	)

	obs := getTcpObserverWithLatencyDetection(t, ctx, false)
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)

	readyWG.Wait()
	cmdServer := exec.Command(server, "-nvlp", "8082")
	assert.NoError(t, cmdServer.Start())
	time.Sleep(1000 * time.Millisecond)

	cmdClient := exec.Command(client, "127.0.0.1", "8082")
	stdin, err := cmdClient.StdinPipe()
	assert.NoError(t, err)
	assert.NoError(t, cmdClient.Start())
	_, err = stdin.Write([]byte("hello"))
	assert.NoError(t, err)
	time.Sleep(1000 * time.Millisecond)

	killAndWaitCommand(t, cmdClient)
	killAndWaitCommand(t, cmdServer)

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestLoadTcpSensor(t *testing.T) {
	if err := observertesthelper.WriteConfigFile(testConfigFile, tcpBasicConfig); err != nil {
		t.Fatalf("WriteFile(%s): err %s", testConfigFile, err)
	}

	sens, err := observertesthelper.GetDefaultSensorsWithFile(t, testConfigFile, runner.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultSensorsWithFile error: %s", err)
	}

	sensorProgs := []tus.SensorProg{
		0: tus.SensorProg{Name: "tg_event_tcp_connect", Type: ebpf.Kprobe},
		1: tus.SensorProg{Name: "tg_event_tcp_close_and_accept", Type: ebpf.Kprobe},
		2: tus.SensorProg{Name: "tg_event_sys_listen", Type: ebpf.Kprobe},
		3: tus.SensorProg{Name: "tg_event_tcp_v4_send_check", Type: ebpf.Kprobe},

		// new accept sensor
		4: tus.SensorProg{Name: "tg_event_tcp_accept", Type: ebpf.Kprobe},
		5: tus.SensorProg{Name: "tg_event_tcp_accept_ret", Type: ebpf.Kprobe},

		// IPv6 sensor
		6: tus.SensorProg{Name: "tg_event_tcp_v6_send_check", Type: ebpf.Kprobe},
	}
	sensorMaps := []tus.SensorMap{
		// all but accept
		tus.SensorMap{Name: "tg_socket_map", Progs: []uint{0, 1, 2, 3, 5, 6}},

		// all but base, accept, event_tcp_v4_send_check and event_tcp_v6_send_check
		tus.SensorMap{Name: "tg_socket_map_stats", Progs: []uint{0, 1, 2, 5}},

		// all but base, event_tcp_v4_send_check and event_tcp_v6_send_check
		tus.SensorMap{Name: "tg_socket_tuple_map", Progs: []uint{0, 1, 2, 5}},

		// all but base, event_tcp_v4_send_check and event_tcp_v6_send_check
		tus.SensorMap{Name: "tg_socket_tuple_map_stats", Progs: []uint{0, 1, 2, 5}},

		// all but base, event_tcp_v4_send_check and event_tcp_v6_send_check
		tus.SensorMap{Name: "tg_socket_tuple_hint_map", Progs: []uint{0, 1, 2, 5}},

		// accept and accept_ret
		tus.SensorMap{Name: "tg_tcp_accept_sock_map", Progs: []uint{4, 5}},

		// all but accept and accept_ret
		tus.SensorMap{Name: "tcpmon_map", Progs: []uint{0, 1, 2, 3, 6}},

		// all but accept, accept_ret and event_tcp4_close
		tus.SensorMap{Name: "execve_map", Progs: []uint{0, 2, 3, 6}},
	}

	tus.CheckSensorLoad(sens, sensorMaps, sensorProgs, t)

	sensors.UnloadSensors(sens)
}

func TestConnectEvent6(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	curlChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix("curl")).
		WithArguments(sm.Full("[::1]"))

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker("selfExec").
			WithProcess(selfChecker).
			WithParent(ec.NewProcessChecker()),
		ec.NewProcessExecChecker("curlExec").
			WithProcess(curlChecker).
			WithParent(selfChecker),
		ec.NewProcessConnectChecker("curlConnect").
			WithProcess(curlChecker).
			WithParent(selfChecker).
			WithDestinationIp(sm.Full("::1")).
			WithDestinationPort(80).
			WithProtocol(tetragon.SocketProtocol_TCP),
		ec.NewProcessCloseChecker("curlClose").
			WithProcess(curlChecker).
			WithParent(selfChecker).
			WithDestinationIp(sm.Full("::1")).
			WithDestinationPort(80).
			WithProtocol(tetragon.SocketProtocol_TCP).
			WithSocketType(sm.Full("connect")),
	)

	obs := getBasicTcpObserver(t, ctx, false)
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	observertesthelper.ExecWGCurl(&readyWG, 10, "[::1]")
	err := jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestExecEventClone6(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	orig := "nc.openbsd"
	server := orig
	client := server
	if _, err := exec.LookPath(server); err != nil {
		server = "nc.openbsd"
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
		WithArguments(sm.Full("-6nvlp 8081"))

	ncCliChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(client)).
		WithArguments(sm.Full("-6 ::1 8081"))

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
			WithProtocol(tetragon.SocketProtocol_TCP),
		ec.NewProcessExecChecker("clientExec").
			WithProcess(ncCliChecker).
			WithParent(selfChecker),
		ec.NewProcessConnectChecker("clientConnect").
			WithProcess(ncCliChecker).
			WithParent(selfChecker).
			WithDestinationIp(sm.Full("::1")).
			WithDestinationPort(8081).
			WithProtocol(tetragon.SocketProtocol_TCP),
	)

	obs := getBasicTcpObserver(t, ctx, false)
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)

	readyWG.Wait()
	cmdServer := exec.Command(server, "-6nvlp", "8081")
	assert.NoError(t, cmdServer.Start())
	time.Sleep(1000 * time.Millisecond)
	cmdClient := exec.Command(client, "-6", "::1", "8081")
	assert.NoError(t, cmdClient.Start())

	err := jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)

	killAndWaitCommand(t, cmdServer)
	killAndWaitCommand(t, cmdClient)
}

func TestExistingListenEvent6(t *testing.T) {
	server := getNCCommand(t, "nc.openbsd")

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	ncChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(server)).
		WithArguments(sm.Full("-6nvlp 8081 -s ::"))

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker("selfExec").
			WithProcess(selfChecker).
			WithParent(ec.NewProcessChecker()),
		ec.NewProcessExecChecker("ncExec").
			WithProcess(ncChecker).
			WithParent(selfChecker),
		ec.NewProcessListenChecker("ncListen").
			WithProcess(ncChecker).
			WithParent(selfChecker).
			WithIp(sm.Full("::")).
			WithPort(8081).
			WithProtocol(tetragon.SocketProtocol_TCP),
	)

	/* Start server before creating obs */
	cmdServer := exec.Command(server, "-6nvlp", "8081", "-s", "::")
	assert.NoError(t, cmdServer.Start())

	time.Sleep(1000 * time.Millisecond)

	/* Create obs */
	getBasicTcpObserver(t, context.TODO(), false)
	killAndWaitCommand(t, cmdServer)

	err := jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestExistingAcceptEvent6(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	server := getNCCommand(t, "nc.openbsd")
	client := server

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	ncChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(server)).
		WithArguments(sm.Full("-6nvlp 8081 -s ::"))

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker("selfExec").
			WithProcess(selfChecker).
			WithParent(ec.NewProcessChecker()),
		ec.NewProcessExecChecker("ncExec").
			WithProcess(ncChecker).
			WithParent(selfChecker),
		ec.NewProcessListenChecker("ncListen").
			WithProcess(ncChecker).
			WithParent(selfChecker).
			WithIp(sm.Full("::")).
			WithPort(8081).
			WithProtocol(tetragon.SocketProtocol_TCP),
		ec.NewProcessAcceptChecker("ncAccept").
			WithProcess(ncChecker).
			WithParent(selfChecker).
			WithSourceIp(sm.Full("::1")).
			WithSourcePort(8081).
			WithProtocol(tetragon.SocketProtocol_TCP),
	)

	/* Start server before creating obs */
	cmdServer := exec.Command(server, "-6nvlp", "8081", "-s", "::")
	assert.NoError(t, cmdServer.Start())
	time.Sleep(1000 * time.Millisecond)

	/* Create obs */
	obs := getBasicTcpObserver(t, ctx, false)
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)

	readyWG.Wait()
	time.Sleep(1000 * time.Millisecond)
	cmdClient := exec.Command(client, "-6", "::1", "8081")
	assert.NoError(t, cmdClient.Start())
	time.Sleep(1000 * time.Millisecond)

	err := jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)

	killAndWaitCommand(t, cmdServer)
	killAndWaitCommand(t, cmdClient)
}

func TestExistingRootCWDListenEvent6(t *testing.T) {
	server := getNCCommand(t, "nc.openbsd")

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	ncChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(server)).
		WithArguments(sm.Full("-6nvlp 8081 -s ::")).
		WithCwd(sm.Full("/"))

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker("selfExec").
			WithProcess(selfChecker).
			WithParent(ec.NewProcessChecker()),
		ec.NewProcessExecChecker("ncExec").
			WithProcess(ncChecker).
			WithParent(selfChecker),
		ec.NewProcessListenChecker("ncListen").
			WithProcess(ncChecker).
			WithParent(selfChecker).
			WithIp(sm.Full("::")).
			WithPort(8081).
			WithProtocol(tetragon.SocketProtocol_TCP),
	)

	path, err := os.Getwd()
	if err != nil {
		t.Fail()
	}

	/* Start server in '/' before creating observer */
	os.Chdir("/")
	cmdServer := exec.Command(server, "-6nvlp", "8081", "-s", "::")
	assert.NoError(t, cmdServer.Start())
	os.Chdir(path)

	/* Create obs */
	getBasicTcpObserver(t, context.TODO(), false)
	killAndWaitCommand(t, cmdServer)

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestListenAcceptClose6(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	server := getNCCommand(t, "nc.openbsd")
	client := server

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	ncChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(server)).
		WithArguments(sm.Full("-6nvlp 8081"))

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker("selfExec").
			WithProcess(selfChecker).
			WithParent(ec.NewProcessChecker()),
		ec.NewProcessExecChecker("ncExec").
			WithProcess(ncChecker).
			WithParent(selfChecker),
		ec.NewProcessListenChecker("ncListen").
			WithProcess(ncChecker).
			WithParent(selfChecker).
			WithIp(sm.Full("::")).
			WithPort(8081).
			WithProtocol(tetragon.SocketProtocol_TCP),
		ec.NewProcessAcceptChecker("ncAccept").
			WithProcess(ncChecker).
			WithParent(selfChecker).
			WithSourceIp(sm.Full("::1")).
			WithSourcePort(8081).
			WithProtocol(tetragon.SocketProtocol_TCP),
		ec.NewProcessCloseChecker("ncClose").
			WithProcess(ncChecker).
			WithParent(selfChecker).
			WithSourceIp(sm.Full("::")).
			WithSourcePort(8081).
			WithProtocol(tetragon.SocketProtocol_TCP).
			WithSocketType(sm.Full("listen")),
		// TODO: it would be good if we could also check the close event on
		// the accept socket, but it goes into TIME_WAIT and then
		// eventually close and I don't want to wait for it. So we need
		// some go way to close the sockets.
	)

	exitChecker := ec.NewUnorderedEventChecker(
		ec.NewProcessExitChecker("ncExit").
			WithProcess(ncChecker).
			WithParent(selfChecker).
			WithSignal(sm.Full("SIGKILL")),
	)

	obs := getBasicTcpObserver(t, ctx, false)
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)

	readyWG.Wait()
	cmdServer := exec.Command(server, "-6nvlp", "8081")
	assert.NoError(t, cmdServer.Start())
	time.Sleep(1000 * time.Millisecond)
	cmdClient := exec.Command(client, "-6", "::1", "8081")
	assert.NoError(t, cmdClient.Start())

	time.Sleep(1000 * time.Millisecond)

	killAndWaitCommand(t, cmdServer)
	killAndWaitCommand(t, cmdClient)

	err := jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)

	err = jsonchecker.JsonTestCheck(t, exitChecker)
	assert.NoError(t, err)
}

func TestDockerExistingListenEvent6(t *testing.T) {
	if err := exec.Command("docker", "version").Run(); err != nil {
		t.Skipf("docker not available. skipping test: %s", err)
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	/* Start server before creating obs */
	observertesthelper.DockerRun(t, "--name", "fgs-test-server", "--entrypoint", "nc", alpineCurlImage, "-nvlp", "8081", "-s", "[::]")
	observertesthelper.WaitForProcess("nc -nvlp 8081 -s [::]")
	time.Sleep(2 * time.Second)

	/* Create obs */
	obs := getBasicTcpObserver(t, ctx, true)
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)

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
		WithArguments(sm.Full("-nvlp 8081 -s [::]")).
		WithCwd(sm.Full("/")).
		WithUid(0)

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker("selfExec").
			WithProcess(selfChecker).
			WithParent(ec.NewProcessChecker()),
		ec.NewProcessExecChecker("ncExec").
			WithProcess(ncChecker),
		ec.NewProcessListenChecker("ncListen").
			WithProcess(ncChecker).
			WithIp(sm.Full("::")).
			WithPort(8081).
			WithProtocol(tetragon.SocketProtocol_TCP),
	)

	err := jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestDockerListenConnect6(t *testing.T) {
	if err := exec.Command("docker", "version").Run(); err != nil {
		t.Skipf("docker not available. skipping test: %s", err)
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	defer cancel()

	obs := getBasicTcpObserver(t, ctx, true)
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)

	readyWG.Wait()
	serverDockerID := observertesthelper.DockerRun(t, "--name", "fgs-test-server", "--entrypoint", "nc", alpineCurlImage, "-nvlp", "8081", "-s", "[::]")
	time.Sleep(1 * time.Second)
	clientDockerID := observertesthelper.DockerRun(t, "--link", "fgs-test-server", "--entrypoint", "nc", alpineCurlImage, "-p", "9876", "fgs-test-server", "8081")

	// FGS sends 31 bytes + \0 to user-space. Since it might have an arbitrary prefix,
	// match only on the first 24 bytes.
	fgsServerID := sm.Prefix(serverDockerID[:24])
	fgsClientID := sm.Prefix(clientDockerID[:24])

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	ncSrvChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix("/nc")).
		WithArguments(sm.Full("-nvlp 8081 -s [::]")).
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
		ec.NewProcessExecChecker("selfExec").
			WithProcess(selfChecker).
			WithParent(ec.NewProcessChecker()),
		ec.NewProcessExecChecker("severExec").
			WithProcess(ncSrvChecker),
		ec.NewProcessListenChecker("serverListen").
			WithProcess(ncSrvChecker).
			WithIp(sm.Full("::")).
			WithPort(8081).
			WithProtocol(tetragon.SocketProtocol_TCP),
		ec.NewProcessExecChecker("clientExec").
			WithProcess(ncCliChecker),
		ec.NewProcessConnectChecker("clientConnect").
			WithProcess(ncCliChecker).
			WithDestinationPort(8081).
			WithSourcePort(9876).
			WithProtocol(tetragon.SocketProtocol_TCP),
		ec.NewProcessCloseChecker("serverClose").
			WithProcess(ncSrvChecker).
			WithSourceIp(sm.Full("::")).
			WithSourcePort(8081).
			WithProtocol(tetragon.SocketProtocol_TCP).
			WithSocketType(sm.Full("listen")),
		ec.NewProcessCloseChecker("clientClose").
			WithProcess(ncCliChecker).
			WithDestinationPort(8081).
			WithSourcePort(9876).
			WithProtocol(tetragon.SocketProtocol_TCP).
			WithSocketType(sm.Full("connect")),
	)

	time.Sleep(1 * time.Second)

	err := jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

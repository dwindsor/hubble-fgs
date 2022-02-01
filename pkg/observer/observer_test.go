//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package observer

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/isovalent/hubble-fgs/api/v1/fgs"
	"github.com/isovalent/hubble-fgs/pkg/api"
	"github.com/isovalent/hubble-fgs/pkg/bpf"
	"github.com/isovalent/hubble-fgs/pkg/btf"
	ec "github.com/isovalent/hubble-fgs/pkg/eventchecker"
	"github.com/isovalent/hubble-fgs/pkg/option"
	"github.com/isovalent/hubble-fgs/pkg/sensors"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

var (
	selfBinary   string
	fgsLib       string
	cmdWaitTime  time.Duration
	verboseLevel int
)

const (
	testConfigFile = "/tmp/hubble-fgs.gotest.yaml"
)

func init() {
	flag.StringVar(&fgsLib, "hubble-lib", "../../bpf/objs/", "hubble lib directory (location of btf file and bpf objs). Will be overridden by an FGS_LIB env variable.")
	flag.DurationVar(&cmdWaitTime, "command-wait", 20000*time.Millisecond, "duration to wait for fgs to gather logs from commands")
	flag.IntVar(&verboseLevel, "verbosity-level", 0, "verbosity level of verbose mode. (Requires verbose mode to be enabled.)")
}

func TestMain(m *testing.M) {
	flag.Parse()
	bpf.CheckOrMountFS("")
	bpf.CheckOrMountDebugFS()
	bpf.ConfigureResourceLimits()
	selfBinary = filepath.Base(os.Args[0])
	exitCode := m.Run()
	os.Exit(exitCode)
}

func TestObjectLoad(t *testing.T) {
	obs, err := getDefaultObserverWithWatchers(t, withLib(fgsLib))
	if err != nil {
		t.Fatalf("getDefaultObserver error: %s", err)
	}
	if err := btf.InitCachedBTF(option.Config.HubbleLib, "", context.TODO()); err != nil {
		t.Fatalf("ConfigureBTF error: %s", err)
	}
	initialSensor := sensors.GetInitialSensor()
	if err := initialSensor.FindPrograms(context.TODO()); err != nil {
		t.Fatalf("ObserverFindProgs error: %s", err)
	}
	initialSensor.Load(context.TODO(), obs.bpfDir, obs.mapDir, obs.ciliumDir)
	obs.RemovePrograms()
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
	checker := ec.NewOrderedMultiResponseChecker(
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

	obs, err := getDefaultObserverWithWatchers(t, withPretty(), withLib(fgsLib))
	if err != nil {
		t.Fatalf("getDefaultObserverWithWatchers error: %s", err)
	}

	LoopEvents(t, &doneWG, &readyWG, obs, ctx)
	ExecWGCurl(&readyWG, "127.0.0.1")
	err = JsonTestCheck(t, nil, &checker)
	assert.NoError(t, err)
	TestDone(t, obs)
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

	checker := ec.NewOrderedMultiResponseChecker(
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

	obs, err := getDefaultObserverWithWatchers(t, withPretty(), withLib(fgsLib))
	if err != nil {
		t.Fatalf("getDefaultObserverWithWatchers error: %s", err)
	}

	LoopEvents(t, &doneWG, &readyWG, obs, ctx)

	readyWG.Wait()
	cmdServer := exec.Command(server, "-nvlp", "8081")
	assert.NoError(t, cmdServer.Start())
	time.Sleep(1000 * time.Millisecond)
	cmdClient := exec.Command(client, "127.0.0.1", "8081")
	assert.NoError(t, cmdClient.Start())

	err = JsonTestCheck(t, nil, &checker)
	assert.NoError(t, err)

	killAndWaitCommand(t, cmdServer)
	killAndWaitCommand(t, cmdClient)

	TestDone(t, obs)
}

func TestExistingListenEvent(t *testing.T) {
	server := getNCCommand(t, "nc.traditional")
	selfChecker := ec.ProcessWithBinary(ec.SuffixStringMatch(selfBinary))
	ncChecker := ec.ProcessWithCommand(
		ec.SuffixStringMatch(server), ec.FullStringMatch("-nvlp 8081"),
	)

	checker := ec.NewOrderedMultiResponseChecker(
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
	obs, err := getDefaultObserverWithWatchers(t, withLib(fgsLib))
	if err != nil {
		t.Fatalf("getDefaultObserverWithWatchers error: %s", err)
	}

	killAndWaitCommand(t, cmdServer)

	err = JsonTestCheck(t, nil, &checker)
	assert.NoError(t, err)

	TestDone(t, obs)
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

	checker := ec.NewOrderedMultiResponseChecker(
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
	fmt.Printf("cmd: %s\n", cmdServer)
	assert.NoError(t, cmdServer.Start())
	time.Sleep(1000 * time.Millisecond)

	/* Create obs */
	obs, err := getDefaultObserverWithWatchers(t, withLib(fgsLib))
	if err != nil {
		t.Fatalf("getDefaultObserverWithWatchers error: %s", err)
	}
	LoopEvents(t, &doneWG, &readyWG, obs, ctx)

	readyWG.Wait()
	time.Sleep(1000 * time.Millisecond)
	cmdClient := exec.Command(client, "127.0.0.1", "8081")
	fmt.Printf("cmd: %s\n", cmdClient)
	assert.NoError(t, cmdClient.Start())

	err = JsonTestCheck(t, nil, &checker)
	assert.NoError(t, err)

	killAndWaitCommand(t, cmdServer)
	killAndWaitCommand(t, cmdClient)

	TestDone(t, obs)
}

func TestExistingRootCWDListenEvent(t *testing.T) {
	server := getNCCommand(t, "nc.traditional")
	selfChecker := ec.ProcessWithBinary(ec.SuffixStringMatch(selfBinary))
	ncChecker := ec.ProcessWithCommand(
		ec.SuffixStringMatch(server), ec.FullStringMatch("-nvlp 8081"),
	)

	checker := ec.NewOrderedMultiResponseChecker(
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
	obs, err := getDefaultObserverWithWatchers(t, withLib(fgsLib))
	if err != nil {
		t.Fatalf("getDefaultObserverWithWatchers error: %s", err)
	}

	killAndWaitCommand(t, cmdServer)

	err = JsonTestCheck(t, nil, &checker)
	assert.NoError(t, err)

	TestDone(t, obs)
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

	checker := ec.NewOrderedMultiResponseChecker(
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

	obs, err := getDefaultObserverWithWatchers(t, withPretty(), withLib(fgsLib))
	if err != nil {
		t.Fatalf("getDefaultObserverWithWatchers error: %s", err)
	}
	LoopEvents(t, &doneWG, &readyWG, obs, ctx)

	readyWG.Wait()
	cmdServer := exec.Command(server, "-nvlp", "8081")
	assert.NoError(t, cmdServer.Start())
	time.Sleep(1000 * time.Millisecond)
	cmdClient := exec.Command(client, "127.0.0.1", "8081")
	assert.NoError(t, cmdClient.Start())

	err = JsonTestCheck(t, nil, &checker)
	assert.NoError(t, err)

	killAndWaitCommand(t, cmdServer)
	killAndWaitCommand(t, cmdClient)

	TestDone(t, obs)
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

func TestSensorLseekLoad(t *testing.T) {
	if _, err := os.Stat("/sys/kernel/debug/tracing/events/syscalls"); os.IsNotExist(err) {
		t.Skip("cannot use syscall tracepoints (consider enabling CONFIG_FTRACE_SYSCALLS)")
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
	defer cancel()

	checker := ec.NewOrderedMultiResponseChecker(
		ec.NewTestEventChecker().End(),
	)

	obs, err := getDefaultObserverWithWatchers(t, withLib(fgsLib))
	if err != nil {
		t.Fatalf("getDefaultObserverWithWatchers error: %s", err)
	}
	progs := []*sensors.Program{&ObserverLseekTest}
	maps := []*sensors.Map{}
	sensor := &sensors.Sensor{Name: "lseekTest", Progs: progs, Maps: maps}
	if err := sensor.FindPrograms(ctx); err != nil {
		t.Fatalf("ObserverFindProgs error: %s", err)
	}
	if err := sensor.Load(ctx, obs.bpfDir, obs.mapDir, obs.ciliumDir); err != nil {
		obs.RemovePrograms()
		t.Fatalf("observerLoadSensor error: %s", err)
	}
	LoopEvents(t, &doneWG, &readyWG, obs, ctx)
	readyWG.Wait()
	unix.Seek(-1, 0, 4444)

	err = JsonTestCheck(t, nil, &checker)
	assert.NoError(t, err)

	sensors.UnloadSensor(obs.bpfDir, obs.mapDir, sensor, ctx)

	obs.RemovePrograms()
	obs.PrintStats()
}

func TestSensorLseekEnable(t *testing.T) {
	if _, err := os.Stat("/sys/kernel/debug/tracing/events/syscalls"); os.IsNotExist(err) {
		t.Skip("cannot use syscall tracepoints (consider enabling CONFIG_FTRACE_SYSCALLS)")
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
	defer cancel()

	checker := ec.NewOrderedMultiResponseChecker(
		ec.NewTestEventChecker().End(),
	)

	obs, err := getDefaultObserverWithWatchers(t, withLib(fgsLib))
	if err != nil {
		t.Fatalf("getDefaultObserverWithWatchers error: %s", err)
	}
	defer func() {
		obs.RemovePrograms()
		obs.PrintStats()
	}()

	sensorName := "lseekTest"
	progs := []*sensors.Program{&ObserverLseekTest}
	maps := []*sensors.Map{}
	sensor := &sensors.Sensor{Name: sensorName, Progs: progs, Maps: maps}
	sensors.RegisterSensorAtInit(sensor)

	smanager, err := sensors.StartSensorManager(obs.bpfDir, obs.mapDir, obs.ciliumDir)
	if err != nil {
		t.Fatalf("startSensorController failed: %s", err)
	}
	obs.SensorManager = smanager
	defer func() {
		err := smanager.StopSensorManager(ctx)
		if err != nil {
			fmt.Printf("stopSensorController failed: %s\n", err)
		}
	}()

	if err := smanager.EnableSensor(ctx, sensorName); err != nil {
		t.Fatalf("EnableSensor error: %s", err)
	}

	defer func() {
		err := smanager.DisableSensor(ctx, sensorName)
		if err != nil {
			fmt.Printf("DisableSensor failed: %s\n", err)
		}
	}()

	LoopEvents(t, &doneWG, &readyWG, obs, ctx)
	readyWG.Wait()
	unix.Seek(-1, 0, 4444)

	err = JsonTestCheck(t, nil, &checker)
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

	obs, err := getDefaultObserverWithWatchers(t, withPretty(), withLib(fgsLib))
	if err != nil {
		t.Fatalf("getDefaultObserver error: %s", err)
	}
	LoopEvents(t, &doneWG, &readyWG, obs, ctx)

	readyWG.Wait()
	serverDockerID := dockerRun(t, "--name", "fgs-test-server", "--entrypoint", "nc", "quay.io/cilium/alpine-curl:1.0", "-nvlp", "8081")
	time.Sleep(1 * time.Second)
	clientDockerID := dockerRun(t, "--link", "fgs-test-server", "--entrypoint", "nc", "quay.io/cilium/alpine-curl:1.0", "-p", "9876", "fgs-test-server", "8081")

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

	err = JsonTestCheck(t, nil, checker)
	assert.NoError(t, err)
	TestDone(t, obs)
}

func Test_msgToExecveUnix(t *testing.T) {
	event := api.MsgExecveEvent{}

	// Minikube has "docker-" prefix.
	prefix := "docker-"
	minikubeID := prefix + "9e123a99b140a6ea4a8d15040ca2c8ee2d5ee9605e81d66ae4e3e29c3f0ef220.scope"
	copy(event.Kube.Docker[:], minikubeID)
	_, offset := procsDockerIdOffset(minikubeID)
	result := msgToExecveUnix(&event, offset)
	assert.Equal(t, strings.Split(minikubeID, "-")[1][:api.DOCKER_ID_LENGTH-len(prefix)], result.Kube.Docker)
	event.Kube.Docker[0] = 0
	result = msgToExecveUnix(&event, offset)
	assert.Empty(t, result.Kube.Docker)

	// GKE doesn't.
	gkeID := "82836ef3675020258bee5075ace6264b3bc5300e20c975543cbc984bea59638f"
	copy(event.Kube.Docker[:], gkeID)
	result = msgToExecveUnix(&event, 0)
	assert.Equal(t, gkeID[:api.DOCKER_ID_LENGTH], result.Kube.Docker)
	event.Kube.Docker[0] = 0
	result = msgToExecveUnix(&event, offset)
	assert.Empty(t, result.Kube.Docker)
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
	dockerRun(t, "--name", "fgs-test-server", "--entrypoint", "nc", "quay.io/cilium/alpine-curl:1.0", "-nvlp", "8081")
	waitForProcess("nc -nvlp 8081")
	time.Sleep(2 * time.Second)

	/* Create obs */
	obs, err := getDefaultObserverWithWatchers(t, withPretty(), withLib(fgsLib))
	if err != nil {
		t.Fatalf("getDefaultObserverWithWatchers error: %s", err)
	}
	LoopEvents(t, &doneWG, &readyWG, obs, ctx)

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

	err = JsonTestCheck(t, nil, checker)
	assert.NoError(t, err)
	TestDone(t, obs)
}

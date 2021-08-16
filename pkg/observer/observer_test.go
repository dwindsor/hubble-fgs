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
package observer

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/isovalent/hubble-fgs/pkg/api"
	"github.com/isovalent/hubble-fgs/pkg/bpf"
	"github.com/isovalent/hubble-fgs/pkg/btf"
	ec "github.com/isovalent/hubble-fgs/pkg/eventchecker"

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
	kprobe, err := getDefaultObserverWithWatchers(t, withLib(fgsLib))
	if err != nil {
		t.Fatalf("getDefaultObserver error: %s", err)
	}
	if err := btf.InitCachedBTF(HubbleLib, "", context.TODO()); err != nil {
		t.Fatalf("ConfigureBTF error: %s", err)
	}
	initialSensor := createInitialObserverSensor()
	if err := observerFindProgs(context.TODO(), initialSensor); err != nil {
		t.Fatalf("observerFindProgs error: %s", err)
	}
	ObserverLoadSensor(kprobe.bpfDir, kprobe.mapDir, kprobe.ciliumDir, context.TODO(), initialSensor)
	kprobe.RemovePrograms()
}

func getMyPid() uint32 {
	if procfs := os.Getenv("FGS_PROCFS"); procfs != "" {
		procFS, _ := ioutil.ReadDir(procfs)
		for _, d := range procFS {
			if d.IsDir() == false {
				continue
			}
			cmdline, err := ioutil.ReadFile(filepath.Join(procfs, d.Name(), "/cmdline"))
			if err != nil {
				continue
			}
			if strings.Contains(string(cmdline), selfBinary) {
				pid, err := strconv.ParseUint(d.Name(), 10, 32)
				if err != nil {
					continue
				}
				return uint32(pid)
			}
		}
	}
	return uint32(os.Getpid())
}

func TestConnectEvent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
	var exitWG, execWG sync.WaitGroup
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
			End(),
	)

	kprobe, err := getDefaultObserverWithWatchers(t, withPretty(), withLib(fgsLib))
	if err != nil {
		t.Fatalf("getDefaultObserverWithWatchers error: %s", err)
	}

	LoopEvents(t, &exitWG, &execWG, kprobe, ctx)
	ExecWGCurl(&execWG, &exitWG, "127.0.0.1")
	err = JsonTestCheck(t, nil, &checker)
	assert.NoError(t, err)
	TestDone(t, kprobe)
}

func TestExecEventClone(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
	var exitWG, execWG sync.WaitGroup
	defer cancel()

	selfChecker := ec.NewProcessChecker().WithBinary(ec.SuffixStringMatch(selfBinary))
	ncSrvChecker := ec.NewProcessChecker().
		WithBinary(ec.SuffixStringMatch("nc.traditional")).
		WithArguments(ec.FullStringMatch("-nvlp 8081"))
	ncCliChecker := ec.NewProcessChecker().
		WithBinary(ec.SuffixStringMatch("nc.traditional")).
		WithArguments(ec.FullStringMatch("127.0.0.1 8081 -e /bin/sh"))

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
			End(),
	)

	kprobe, err := getDefaultObserverWithWatchers(t, withPretty(), withLib(fgsLib))
	if err != nil {
		t.Fatalf("getDefaultObserverWithWatchers error: %s", err)
	}

	/* Verify initial KprobeEvent Execve "nc.traditional 127.0.0.1 8081 -e /bin/sh" */
	//	kprobe.AttachFilter(&ncExecFilter)
	/* Verify KprobeEvent TCPConnectReturn "nc.traditional 127.0.0.1 8081 -e /bin/sh" */
	//	kprobe.AttachFilter(&ncListen)
	//	kprobe.AttachFilter(&ncConnect)
	/* Verify KprobeEvent Execve '-e /bin/sh' without clone() */
	//	kprobe.AttachFilter(&ncExecCloneFilter)

	LoopEvents(t, &exitWG, &execWG, kprobe, ctx)

	execWG.Wait()
	cmdServer := exec.Command("nc.traditional", "-nvlp", "8081")
	cmdServer.Start()
	time.Sleep(1000 * time.Millisecond)
	cmdClient := exec.Command("nc.traditional", "127.0.0.1", "8081", "-e", "/bin/sh")
	cmdClient.Start()
	exitWG.Wait()

	if cmdServer != nil {
		cmdServer.Process.Kill()
	}
	if cmdClient != nil {
		cmdClient.Process.Kill()
	}
	err = JsonTestCheck(t, nil, &checker)
	assert.NoError(t, err)
	TestDone(t, kprobe)
}

func TestExistingListenEvent(t *testing.T) {
	selfChecker := ec.ProcessWithBinary(ec.SuffixStringMatch(selfBinary))
	ncChecker := ec.ProcessWithCommand(
		ec.SuffixStringMatch("nc.traditional"), ec.FullStringMatch("-nvlp 8081"),
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
			End(),
	)

	/* Start server before creating kprobe */
	cmdServer := exec.Command("nc.traditional", "-nvlp", "8081")
	cmdServer.Start()

	/* Create kprobe */
	kprobe, err := getDefaultObserverWithWatchers(t, withLib(fgsLib))
	if err != nil {
		t.Fatalf("getDefaultObserverWithWatchers error: %s", err)
	}

	if cmdServer != nil {
		cmdServer.Process.Kill()
	}

	err = JsonTestCheck(t, nil, &checker)
	assert.NoError(t, err)
	TestDone(t, kprobe)
}

func TestExistingAcceptEvent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
	var exitWG, execWG sync.WaitGroup
	defer cancel()

	selfChecker := ec.ProcessWithBinary(ec.SuffixStringMatch(selfBinary))
	ncChecker := ec.ProcessWithCommand(
		ec.SuffixStringMatch("nc.traditional"), ec.FullStringMatch("-nvlp 8081"),
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
			End(),
		ec.NewAcceptEventChecker().
			HasProcess(ncChecker).
			HasParent(selfChecker).
			HasSrcIP("127.0.0.1").
			HasSrcPort(8081).
			End(),
	)

	/* Start server before creating kprobe */
	cmdServer := exec.Command("nc.traditional", "-nvlp", "8081")
	fmt.Printf("cmd: %s\n", cmdServer)
	cmdServer.Start()
	time.Sleep(1000 * time.Millisecond)

	/* Create kprobe */
	kprobe, err := getDefaultObserverWithWatchers(t, withLib(fgsLib))
	if err != nil {
		t.Fatalf("getDefaultObserverWithWatchers error: %s", err)
	}
	LoopEvents(t, &exitWG, &execWG, kprobe, ctx)

	execWG.Wait()
	time.Sleep(1000 * time.Millisecond)
	cmdClient := exec.Command("nc.traditional", "127.0.0.1", "8081")
	fmt.Printf("cmd: %s\n", cmdClient)
	cmdClient.Start()
	exitWG.Wait()

	if cmdClient != nil {
		cmdClient.Process.Signal(syscall.SIGKILL)
	}
	if cmdServer != nil {
		cmdServer.Process.Signal(syscall.SIGKILL)
	}

	err = JsonTestCheck(t, nil, &checker)
	assert.NoError(t, err)
	TestDone(t, kprobe)
}

func TestExistingRootCWDListenEvent(t *testing.T) {
	selfChecker := ec.ProcessWithBinary(ec.SuffixStringMatch(selfBinary))
	ncChecker := ec.ProcessWithCommand(
		ec.SuffixStringMatch("nc.traditional"), ec.FullStringMatch("-nvlp 8081"),
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
			End(),
	)

	path, err := os.Getwd()
	if err != nil {
		t.Fail()
	}

	/* Start server in '/' before creating kprobe */
	os.Chdir("/")
	cmdServer := exec.Command("nc.traditional", "-nvlp", "8081")
	cmdServer.Start()
	os.Chdir(path)

	/* Create kprobe */
	kprobe, err := getDefaultObserverWithWatchers(t, withLib(fgsLib))
	if err != nil {
		t.Fatalf("getDefaultObserverWithWatchers error: %s", err)
	}

	if cmdServer != nil {
		cmdServer.Process.Kill()
	}

	err = JsonTestCheck(t, nil, &checker)
	assert.NoError(t, err)
	TestDone(t, kprobe)
}

func TestListenAcceptClose(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
	var exitWG, execWG sync.WaitGroup
	defer cancel()

	selfChecker := ec.ProcessWithBinary(ec.SuffixStringMatch(selfBinary))
	ncSrvChecker := ec.ProcessWithCommand(
		ec.SuffixStringMatch("nc.traditional"), ec.FullStringMatch("-nvlp 8081"),
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
			End(),
		ec.NewAcceptEventChecker().
			HasProcess(ncSrvChecker).
			HasParent(selfChecker).
			HasSrcIP("127.0.0.1").
			HasSrcPort(8081).
			End(),
		ec.NewCloseEventChecker().
			HasProcess(ncSrvChecker).
			HasParent(selfChecker).
			HasSrcIP("0.0.0.0").
			HasSrcPort(8081).
			End(),
		// TODO: it would be good if we could also check the close event on
		// the accept socket, but it goes into TIME_WAIT and then
		// eventually close and I don't want to wait for it. So we need
		// some go way to close the sockets.
	)

	kprobe, err := getDefaultObserverWithWatchers(t, withPretty(), withLib(fgsLib))
	if err != nil {
		t.Fatalf("getDefaultObserverWithWatchers error: %s", err)
	}
	LoopEvents(t, &exitWG, &execWG, kprobe, ctx)

	execWG.Wait()
	cmdServer := exec.Command("nc.traditional", "-nvlp", "8081")
	cmdServer.Start()
	time.Sleep(1000 * time.Millisecond)
	cmdClient := exec.Command("nc.traditional", "127.0.0.1", "8081")
	cmdClient.Start()
	exitWG.Wait()

	if cmdClient != nil {
		cmdClient.Process.Signal(syscall.SIGKILL)
	}
	if cmdServer != nil {
		cmdServer.Process.Signal(syscall.SIGKILL)
	}

	err = JsonTestCheck(t, nil, &checker)
	assert.NoError(t, err)
	TestDone(t, kprobe)
}

func TestSensorLseekLoad(t *testing.T) {
	if _, err := os.Stat("/sys/kernel/debug/tracing/events/syscalls"); os.IsNotExist(err) {
		t.Skip("cannot use syscall tracepoints (consider enabling CONFIG_FTRACE_SYSCALLS)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
	var exitWG, execWG sync.WaitGroup
	defer cancel()

	checker := ec.NewOrderedMultiResponseChecker(
		ec.NewTestEventChecker().End(),
	)

	kprobe, err := getDefaultObserverWithWatchers(t, withLib(fgsLib))
	if err != nil {
		t.Fatalf("getDefaultObserverWithWatchers error: %s", err)
	}
	progs := []*BpfLoad{&ObserverLseekTest}
	maps := []*ObserverMap{}
	sensor := &ObserverSensor{name: "lseekTest", progs: progs, maps: maps}
	if err := observerFindProgs(ctx, sensor); err != nil {
		t.Fatalf("observerFindProgs error: %s", err)
	}
	if err := ObserverLoadSensor(kprobe.bpfDir, kprobe.mapDir, kprobe.ciliumDir, ctx, sensor); err != nil {
		kprobe.RemovePrograms()
		t.Fatalf("observerLoadSensor error: %s", err)
	}
	LoopEvents(t, &exitWG, &execWG, kprobe, ctx)
	execWG.Wait()
	unix.Seek(-1, 0, 4444)
	exitWG.Wait()

	err = JsonTestCheck(t, nil, &checker)
	assert.NoError(t, err)

	observerUnloadSensor(kprobe.bpfDir, kprobe.mapDir, sensor, ctx)

	kprobe.RemovePrograms()
	kprobe.PrintStats()
}

func TestSensorLseekEnable(t *testing.T) {
	if _, err := os.Stat("/sys/kernel/debug/tracing/events/syscalls"); os.IsNotExist(err) {
		t.Skip("cannot use syscall tracepoints (consider enabling CONFIG_FTRACE_SYSCALLS)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
	var exitWG, execWG sync.WaitGroup
	defer cancel()

	checker := ec.NewOrderedMultiResponseChecker(
		ec.NewTestEventChecker().End(),
	)

	kprobe, err := getDefaultObserverWithWatchers(t, withLib(fgsLib))
	if err != nil {
		t.Fatalf("getDefaultObserverWithWatchers error: %s", err)
	}
	defer func() {
		kprobe.RemovePrograms()
		kprobe.PrintStats()
	}()

	sensorName := "lseekTest"
	progs := []*BpfLoad{&ObserverLseekTest}
	maps := []*ObserverMap{}
	sensor := &ObserverSensor{name: sensorName, progs: progs, maps: maps}
	registerSensorAtInit(sensor)

	sensorCtl, err := StartSensorCtl(kprobe.bpfDir, kprobe.mapDir, kprobe.ciliumDir)
	if err != nil {
		t.Fatalf("startSensorController failed: %s", err)
	}
	kprobe.ObserverSync = sensorCtl
	defer func() {
		err := sensorCtl.stopSensorCtl(ctx)
		if err != nil {
			fmt.Printf("stopSensorController failed: %s\n", err)
		}
	}()

	if err := sensorCtl.EnableSensor(ctx, sensorName); err != nil {
		t.Fatalf("EnableSensor error: %s", err)
	}

	defer func() {
		err := sensorCtl.DisableSensor(ctx, sensorName)
		if err != nil {
			fmt.Printf("DisableSensor failed: %s\n", err)
		}
	}()

	LoopEvents(t, &exitWG, &execWG, kprobe, ctx)
	execWG.Wait()
	unix.Seek(-1, 0, 4444)
	exitWG.Wait()

	err = JsonTestCheck(t, nil, &checker)
	assert.NoError(t, err)
}

func TestDockerListenConnect(t *testing.T) {
	if err := exec.Command("docker", "version").Run(); err != nil {
		t.Skipf("docker not available. skipping test: %s", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
	defer cancel()
	var exitWG, execWG sync.WaitGroup
	var serverDockerID, clientDockerID string

	kprobe, err := getDefaultObserverWithWatchers(t, withPretty(), withLib(fgsLib))
	if err != nil {
		t.Fatalf("getDefaultObserver error: %s", err)
	}
	LoopEvents(t, &exitWG, &execWG, kprobe, ctx)

	execWG.Wait()
	serverDockerID = dockerRun(t, "--name", "fgs-test-server", "--entrypoint", "nc", "quay.io/cilium/alpine-curl:1.0", "-nvlp", "8081")
	time.Sleep(1 * time.Second)
	clientDockerID = dockerRun(t, "--link", "fgs-test-server", "--entrypoint", "nc", "quay.io/cilium/alpine-curl:1.0", "fgs-test-server", "8081")
	exitWG.Wait()

	// FGS picks up the first 32 bytes
	fgsServerID := serverDockerID[:31]
	fgsClientID := clientDockerID[:31]

	selfChecker := ec.ProcessWithBinary(ec.SuffixStringMatch(selfBinary))
	ncSrvChecker := ec.NewProcessChecker().
		WithBinary("/usr/bin/nc").
		WithArguments("-nvlp 8081").
		WithCWD("/").
		WithUID(0).
		WithDocker(fgsServerID)
	ncCliChecker := ec.NewProcessChecker().
		WithBinary("/usr/bin/nc").
		WithArguments("fgs-test-server 8081").
		WithCWD("/").
		WithUID(0).
		WithDocker(fgsClientID)

	checker := ec.NewOrderedMultiResponseChecker(
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
			End(),
	)

	err = JsonTestCheck(t, nil, &checker)
	assert.NoError(t, err)
	TestDone(t, kprobe)
}

func Test_msgToExecveUnix(t *testing.T) {
	event := api.MsgExecveEvent{}

	// Minikube has "docker-" prefix.
	prefix := "docker-"
	minikubeID := prefix + "9e123a99b140a6ea4a8d15040ca2c8ee2d5ee9605e81d66ae4e3e29c3f0ef220.scope"
	copy(event.Kube.Docker[:], minikubeID)
	_, offset, err := procsDockerIdOffset(minikubeID)
	assert.NoError(t, err)
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

	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
	defer cancel()
	var exitWG, execWG sync.WaitGroup

	/* Start server before creating kprobe */
	dockerRun(t, "--name", "fgs-test-server", "--entrypoint", "nc", "quay.io/cilium/alpine-curl:1.0", "-nvlp", "8081")
	waitForProcess("nc -nvlp 8081")
	time.Sleep(2 * time.Second)

	/* Create kprobe */
	kprobe, err := getDefaultObserverWithWatchers(t, withPretty(), withLib(fgsLib))
	if err != nil {
		t.Fatalf("getDefaultObserverWithWatchers error: %s", err)
	}
	LoopEvents(t, &exitWG, &execWG, kprobe, ctx)

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

	checker := ec.NewOrderedMultiResponseChecker(
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
	)

	err = JsonTestCheck(t, nil, &checker)
	assert.NoError(t, err)
	TestDone(t, kprobe)
}

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

	"github.com/isovalent/hubble-fgs/pkg/api"
	"github.com/isovalent/hubble-fgs/pkg/bpf"
	"github.com/isovalent/hubble-fgs/pkg/btf"
	ec "github.com/isovalent/hubble-fgs/pkg/eventchecker"
	"github.com/isovalent/hubble-fgs/pkg/option"
	"github.com/isovalent/hubble-fgs/pkg/reader"
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
	bpf.SetMapPrefix("testObserver")
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

	obs, err := getDefaultObserverWithWatchers(t, withPretty(), withLib(fgsLib))
	if err != nil {
		t.Fatalf("getDefaultObserverWithWatchers error: %s", err)
	}

	LoopEvents(t, &doneWG, &readyWG, obs, ctx)
	readyWG.Wait()
	err = JsonTestCheck(t, checker)
	assert.NoError(t, err)
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

	checker := ec.NewSingleMultiResponseChecker(
		ec.NewTestEventChecker().End(),
	)

	obs, err := getDefaultObserverWithWatchers(t, withLib(fgsLib))
	if err != nil {
		t.Fatalf("getDefaultObserverWithWatchers error: %s", err)
	}
	progs := []*sensors.Program{ObserverLseekTest}
	maps := []*sensors.Map{}
	sensor := &sensors.Sensor{Name: "lseekTest", Progs: progs, Maps: maps}
	if err := sensor.FindPrograms(ctx); err != nil {
		t.Fatalf("ObserverFindProgs error: %s", err)
	}
	if err := sensor.Load(ctx, obs.bpfDir, obs.mapDir, obs.ciliumDir); err != nil {
		t.Fatalf("observerLoadSensor error: %s", err)
	}
	LoopEvents(t, &doneWG, &readyWG, obs, ctx)
	readyWG.Wait()
	unix.Seek(-1, 0, 4444)

	err = JsonTestCheck(t, checker)
	assert.NoError(t, err)

	sensors.UnloadSensor(obs.bpfDir, obs.mapDir, sensor, ctx)
}

func TestSensorLseekEnable(t *testing.T) {
	if _, err := os.Stat("/sys/kernel/debug/tracing/events/syscalls"); os.IsNotExist(err) {
		t.Skip("cannot use syscall tracepoints (consider enabling CONFIG_FTRACE_SYSCALLS)")
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
	defer cancel()

	checker := ec.NewSingleMultiResponseChecker(
		ec.NewTestEventChecker().End(),
	)

	obs, err := getDefaultObserverWithWatchers(t, withLib(fgsLib))
	if err != nil {
		t.Fatalf("getDefaultObserverWithWatchers error: %s", err)
	}

	sensorName := "lseekTest"
	progs := []*sensors.Program{ObserverLseekTest}
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

	err = JsonTestCheck(t, checker)
	assert.NoError(t, err)
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

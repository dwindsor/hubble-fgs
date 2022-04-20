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
	"os"
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
)

var (
	selfBinary   string
	fgsLib       string
	cmdWaitTime  time.Duration
	verboseLevel int
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
	if err := btf.InitCachedBTF(context.TODO(), option.Config.HubbleLib, ""); err != nil {
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

	LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()
	err = JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func Test_msgToExecveUnix(t *testing.T) {
	event := api.MsgExecveEvent{}

	// Minikube has "docker-" prefix.
	prefix := "docker-"
	minikubeID := prefix + "9e123a99b140a6ea4a8d15040ca2c8ee2d5ee9605e81d66ae4e3e29c3f0ef220.scope"
	copy(event.Kube.Docker[:], minikubeID)
	_, offset := procsContainerIdOffset(minikubeID)
	result := msgToExecveUnix(&event, offset)
	assert.Equal(t, strings.Split(minikubeID, "-")[1][:BpfContainerIdLength], result.Kube.Docker)
	event.Kube.Docker[0] = 0
	result = msgToExecveUnix(&event, offset)
	assert.Empty(t, result.Kube.Docker)

	// GKE doesn't.
	gkeID := "82836ef3675020258bee5075ace6264b3bc5300e20c975543cbc984bea59638f"
	copy(event.Kube.Docker[:], gkeID)
	result = msgToExecveUnix(&event, 0)
	assert.Equal(t, gkeID[:BpfContainerIdLength], result.Kube.Docker)
	assert.Equal(t, BpfContainerIdLength, len(result.Kube.Docker))
	event.Kube.Docker[0] = 0
	result = msgToExecveUnix(&event, offset)
	assert.Empty(t, result.Kube.Docker)

	id := "kubepods-burstable-pod29349498_197c_4919_b13f_9a928e7d001b.slice:cri-containerd:0ca2b3cd20e5f55a2bbe8d4aa3f811cf7963b40f0542ad147054b0fcb60fc400"
	copy(event.Kube.Docker[:], id)
	result = msgToExecveUnix(&event, 0)
	assert.Equal(t, id[80:80+BpfContainerIdLength], result.Kube.Docker)
	assert.Equal(t, strings.Split(id, ":")[2][:BpfContainerIdLength], result.Kube.Docker)
	assert.Equal(t, BpfContainerIdLength, len(result.Kube.Docker))

	id = "kubepods-besteffort-pod13cb8437-00ed-40e4-99d8-e17193a58086.slice:cri-containerd:a5a6a3af5d51ad95b915ca948710b90a94abc279e84963b9d22a39f342ce67d9"
	copy(event.Kube.Docker[:], id)
	result = msgToExecveUnix(&event, 0)
	assert.Equal(t, id[81:81+BpfContainerIdLength], result.Kube.Docker)
	assert.Equal(t, strings.Split(id, ":")[2][:BpfContainerIdLength], result.Kube.Docker)
	assert.Equal(t, BpfContainerIdLength, len(result.Kube.Docker))

	id = "cri-containerd-5694f82f44168cc048e014ae14d1b0c8ef673bec49f329dc169911ea638f63c2.scope"
	copy(event.Kube.Docker[:], id)
	result = msgToExecveUnix(&event, 0)
	assert.Equal(t, strings.Split(id, "-")[2][:BpfContainerIdLength], result.Kube.Docker)
	assert.Equal(t, BpfContainerIdLength, len(result.Kube.Docker))

	id = "libpod-01f3c60cfaadbb51e4d5947dd2ef0480d53551cbcee8f3ada8c3723b2bf03bf4"
	copy(event.Kube.Docker[:], id)
	result = msgToExecveUnix(&event, 0)
	assert.Equal(t, strings.Split(id, "-")[1][:BpfContainerIdLength], result.Kube.Docker)
	assert.Equal(t, BpfContainerIdLength, len(result.Kube.Docker))

	id = ":a5a6a3af5d51ad95b915ca948710b90a94abc279e84963b9d22a39f342ce67d9"
	copy(event.Kube.Docker[:], id)
	result = msgToExecveUnix(&event, 0)
	assert.Equal(t, strings.Split(id, ":")[1][:BpfContainerIdLength], result.Kube.Docker)
	assert.Equal(t, BpfContainerIdLength, len(result.Kube.Docker))

	// Empty event so we don't fail tests
	for i := 0; i < api.DOCKER_ID_LENGTH; i++ {
		event.Kube.Docker[i] = 0
	}
	// Not valid
	id = "ba4c34f800cf9f92881fd55cea8e60d"
	copy(event.Kube.Docker[:], id)
	result = msgToExecveUnix(&event, 0)
	assert.Empty(t, result.Kube.Docker)

	// Empty event so we don't fail tests
	for i := 0; i < api.DOCKER_ID_LENGTH; i++ {
		event.Kube.Docker[i] = 0
	}
	id = ":ba4c34f800cf9f92881fd55cea8e60d"
	copy(event.Kube.Docker[:], id)
	result = msgToExecveUnix(&event, 0)
	assert.Empty(t, result.Kube.Docker)
}

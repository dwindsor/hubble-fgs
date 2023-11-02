package exec

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/cilium/ebpf"
	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	api "github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/jsonchecker"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	"github.com/stretchr/testify/assert"

	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"

	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
	"github.com/isovalent/hubble-fgs/pkg/metrics/metricsconfig"
	"github.com/isovalent/hubble-fgs/pkg/sensors"
	"github.com/isovalent/hubble-fgs/pkg/sensors/exec/procevents"
	"github.com/isovalent/hubble-fgs/pkg/testutils"
	"github.com/isovalent/hubble-fgs/pkg/testutils/runner"
)

func TestMain(m *testing.M) {
	ec := runner.TestSensorsRun(m, "SensorExec")
	os.Exit(ec)
}

func Test_msgToExecveKubeUnix(t *testing.T) {
	event := api.MsgExecveEvent{}
	idLength := procevents.BpfContainerIdLength

	// Minikube has "docker-" prefix.
	prefix := "docker-"
	minikubeID := prefix + "9e123a99b140a6ea4a8d15040ca2c8ee2d5ee9605e81d66ae4e3e29c3f0ef220.scope"
	copy(event.Kube.Docker[:], minikubeID)
	kube := msgToExecveKubeUnix(&event, "", "")
	assert.Equal(t, strings.Split(minikubeID, "-")[1][:idLength], kube.Docker)
	event.Kube.Docker[0] = 0
	kube = msgToExecveKubeUnix(&event, "", "")
	assert.Empty(t, kube.Docker)

	// GKE doesn't.
	gkeID := "82836ef3675020258bee5075ace6264b3bc5300e20c975543cbc984bea59638f"
	copy(event.Kube.Docker[:], gkeID)
	kube = msgToExecveKubeUnix(&event, "", "")
	assert.Equal(t, gkeID[:idLength], kube.Docker)
	assert.Equal(t, idLength, len(kube.Docker))
	event.Kube.Docker[0] = 0
	kube = msgToExecveKubeUnix(&event, "", "")
	assert.Empty(t, kube.Docker)

	id := "kubepods-burstable-pod29349498_197c_4919_b13f_9a928e7d001b.slice:cri-containerd:0ca2b3cd20e5f55a2bbe8d4aa3f811cf7963b40f0542ad147054b0fcb60fc400"
	copy(event.Kube.Docker[:], id)
	kube = msgToExecveKubeUnix(&event, "", "")
	assert.Equal(t, id[80:80+idLength], kube.Docker)
	assert.Equal(t, strings.Split(id, ":")[2][:idLength], kube.Docker)
	assert.Equal(t, idLength, len(kube.Docker))

	id = "kubepods-besteffort-pod13cb8437-00ed-40e4-99d8-e17193a58086.slice:cri-containerd:a5a6a3af5d51ad95b915ca948710b90a94abc279e84963b9d22a39f342ce67d9"
	copy(event.Kube.Docker[:], id)
	kube = msgToExecveKubeUnix(&event, "", "")
	assert.Equal(t, id[81:81+idLength], kube.Docker)
	assert.Equal(t, strings.Split(id, ":")[2][:idLength], kube.Docker)
	assert.Equal(t, idLength, len(kube.Docker))

	id = "cri-containerd-5694f82f44168cc048e014ae14d1b0c8ef673bec49f329dc169911ea638f63c2.scope"
	copy(event.Kube.Docker[:], id)
	kube = msgToExecveKubeUnix(&event, "", "")
	assert.Equal(t, strings.Split(id, "-")[2][:idLength], kube.Docker)
	assert.Equal(t, idLength, len(kube.Docker))

	id = "libpod-01f3c60cfaadbb51e4d5947dd2ef0480d53551cbcee8f3ada8c3723b2bf03bf4"
	copy(event.Kube.Docker[:], id)
	kube = msgToExecveKubeUnix(&event, "", "")
	assert.Equal(t, strings.Split(id, "-")[1][:idLength], kube.Docker)
	assert.Equal(t, idLength, len(kube.Docker))

	id = ":a5a6a3af5d51ad95b915ca948710b90a94abc279e84963b9d22a39f342ce67d9"
	copy(event.Kube.Docker[:], id)
	kube = msgToExecveKubeUnix(&event, "", "")
	assert.Equal(t, strings.Split(id, ":")[1][:idLength], kube.Docker)
	assert.Equal(t, idLength, len(kube.Docker))

	// Empty event so we don't fail tests
	for i := 0; i < api.DOCKER_ID_LENGTH; i++ {
		event.Kube.Docker[i] = 0
	}
	// Not valid
	id = "ba4c34f800cf9f92881fd55cea8e60d"
	copy(event.Kube.Docker[:], id)
	kube = msgToExecveKubeUnix(&event, "", "")
	assert.Empty(t, kube.Docker)

	// Empty event so we don't fail tests
	for i := 0; i < api.DOCKER_ID_LENGTH; i++ {
		event.Kube.Docker[i] = 0
	}
	id = ":ba4c34f800cf9f92881fd55cea8e60d"
	copy(event.Kube.Docker[:], id)
	kube = msgToExecveKubeUnix(&event, "", "")
	assert.Empty(t, kube.Docker)
}

func TestUpdateStatsMap(t *testing.T) {
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.PerCPUArray,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		m.Close()
	})

	lookup := func() int64 {
		var sum int64
		var v []int64

		if err := m.Lookup(uint32(0), &v); err != nil {
			t.Fatalf("lookup error: %s", err)
		}

		for _, val := range v {
			sum += val
		}
		return sum
	}

	before := lookup()
	if before != 0 {
		t.Fatalf("wrong initial lookup value '%d'", before)
	}

	if err := sensors.UpdateStatsMap(m, 100); err != nil {
		t.Fatalf("UpdateMap failed: %s", err)
	}

	after := lookup()
	if after != 100 {
		t.Fatalf("wrong final lookup value '%d'", after)
	}
}

// Tests process.process_credentials
func TestExecProcessCredentials(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	obs, err := observertesthelper.GetDefaultObserver(t, ctx, tus.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("Failed to run observer: %s", err)
	}
	metricsconfig.RegisterEEMetrics()
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	testNop := testutils.RepoRootPath("contrib/tester-progs/nop")

	if err := exec.Command(testNop).Run(); err != nil {
		t.Fatalf("Failed to execute test binary: %s\n", err)
	}

	gid := uint32(1879048193)
	if err := syscall.Setegid(int(gid)); err != nil {
		t.Fatalf("setegid(%d) error: %s", gid, err)
	}

	if err := exec.Command(testNop).Run(); err != nil {
		t.Fatalf("Failed to execute test binary: %s\n", err)
	}

	creds := ec.NewProcessCredentialsChecker().
		WithUid(0).WithEuid(0).WithSuid(0).WithFsuid(0).
		WithGid(0).WithEgid(0).WithSgid(0).WithFsgid(0)

	gidCreds := ec.NewProcessCredentialsChecker().
		WithUid(0).WithEuid(0).WithSuid(0).WithFsuid(0).
		WithGid(0).WithEgid(gid).WithSgid(gid).WithFsgid(gid)

	procExecChecker := ec.NewProcessChecker().
		WithBinary(sm.Full(testNop)).WithProcessCredentials(creds).WithBinaryProperties(nil)

	procGidExecChecker := ec.NewProcessChecker().
		WithBinary(sm.Full(testNop)).WithProcessCredentials(gidCreds).WithBinaryProperties(nil)

	execChecker := ec.NewProcessExecChecker("exec").WithProcess(procExecChecker)
	execGidChecker := ec.NewProcessExecChecker("exec").WithProcess(procGidExecChecker)
	exitChecker := ec.NewProcessExitChecker("exit").WithProcess(procExecChecker)
	exitGidChecker := ec.NewProcessExitChecker("exit").WithProcess(procGidExecChecker)

	checker := ec.NewUnorderedEventChecker(execChecker, execGidChecker, exitChecker, exitGidChecker)

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)

	if err = syscall.Setgid(0); err != nil {
		t.Fatalf("Failed to restore gid to 0 :  %s\n", err)
	}
}

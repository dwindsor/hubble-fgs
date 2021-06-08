package observer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/isovalent/hubble-fgs/api/v1/fgs"
	"github.com/isovalent/hubble-fgs/pkg/filters"
	fgsGrpc "github.com/isovalent/hubble-fgs/pkg/grpc"
	"github.com/isovalent/hubble-fgs/pkg/kernels"
	"github.com/isovalent/hubble-fgs/pkg/logger"

	hubbleCilium "github.com/cilium/hubble/pkg/cilium"
	"golang.org/x/sys/unix"
	"gopkg.in/natefinch/lumberjack.v2"
	corev1 "k8s.io/api/core/v1"
)

var (
	observerTestDir = "/sys/fs/bpf/testObserver/"
	exportFile      = "/tmp/hubble-fgs.gotest"
	jsonRetries     = 10
)

type testObserverOptions struct {
	tls         bool
	tlstc       bool
	pretty      bool
	crd         bool
	probes      string
	config      string
	tracepoints []GenericTracepointConf
}

type testExporterOptions struct {
	watcher     fgsGrpc.K8sResourceWatcher
	ciliumState *hubbleCilium.State
}

type testOptions struct {
	observer testObserverOptions
	exporter testExporterOptions
}

type testOption func(*testOptions)

func withTLS() testOption {
	return func(o *testOptions) {
		o.observer.tls = true
	}
}

func withTLSTC() testOption {
	return func(o *testOptions) {
		o.observer.tlstc = true
	}
}

func withPretty() testOption {
	return func(o *testOptions) {
		o.observer.pretty = true
	}
}

func withConfig(config string) testOption {
	return func(o *testOptions) {
		o.observer.config = config
	}
}

func withCRD(config string) testOption {
	return func(o *testOptions) {
		o.observer.config = config
	}
}

func withK8sWatcher(w fgsGrpc.K8sResourceWatcher) testOption {
	return func(o *testOptions) {
		o.exporter.watcher = w
	}
}

func withCiliumState(s *hubbleCilium.State) testOption {
	return func(o *testOptions) {
		o.exporter.ciliumState = s
	}
}

func minKernelVersion(kernel string) bool {
	var uname unix.Utsname

	if err := unix.Uname(&uname); err != nil {
		return true
	}
	//n := bytes.IndexByte(uname.Release[:], 0)
	// vendors like to define kernel 4.14.128-foo but
	// everything after '-' is meaningless from BPF
	// side so toss it out.
	release := strings.Split(string(uname.Release[:]), "-")
	numeric := strings.TrimRight(release[0], "+")
	runningVersion := int(kernels.KernelStringToNumeric(numeric))
	minVersion := int(kernels.KernelStringToNumeric(kernel))
	if minVersion <= runningVersion {
		return true
	}
	return false
}

func loadExporter(t *testing.T, kprobe *ObserverKprobe, opts *testExporterOptions) error {
	ctx, _ := context.WithCancel(context.Background())

	os.Remove(exportFile)

	watcher := opts.watcher
	ciliumState := opts.ciliumState
	processCacheSize := 32768
	processManager, err := fgsGrpc.NewProcessManager(logger.GetLogger(), processCacheSize, watcher, ciliumState, true, true)
	if err != nil {
		return err
	}
	server := fgsGrpc.NewServer(processManager, kprobe)
	writer := lumberjack.Logger{
		Filename:   exportFile,
		MaxSize:    10,
		MaxBackups: 1,
		Compress:   false,
	}
	encoder := json.NewEncoder(&writer)

	// temporarily disable the allow list while we fixup TLS events
	// to include parent reference as well
	f := "" //fmt.Sprintf(`{"pid_set":[%d]}`, getMyPid())
	allowList, err := filters.ParseFilterList(f)
	if err != nil {
		t.Fatalf("observerLoadExporter: %s\n", err)
	}
	denyList, _ := filters.ParseFilterList("")
	req := fgs.GetEventsRequest{AllowList: allowList, DenyList: denyList}
	exporter := fgsGrpc.NewExporter(ctx, &req, server, encoder)
	go exporter.Start()
	kprobe.AddListener(processManager)
	return nil
}

func loadObserver(t *testing.T, kprobe *ObserverKprobe) {
	if err := LoadDefaultSensor(kprobe.bpfDir, kprobe.mapDir, kprobe.ciliumDir,
		kprobe.enableTLSTC, kprobe.enableTLS,
		context.TODO()); err != nil {
		t.Fatalf("LoadDefaultSensor error: %s\n", err)
	}

	if kprobe.configFile != "" {
		genericKprobeSensor, err := getSensorFromTracingPolicyFname(kprobe.configFile)
		if err != nil {
			t.Fatalf("createGenericKprobeSensors error: Could not create kprobe sensor. %s", err)
		}
		if err := ObserverLoadSensor(kprobe.bpfDir, kprobe.mapDir, kprobe.ciliumDir, context.TODO(), genericKprobeSensor); err != nil {
			t.Fatalf("observerLoadSensors error: Could not load kprobe sensors. %s", err)
		}
	}

	kprobe.populateExecve(context.TODO())
}

func loopEvents(t *testing.T, exitWG, execWG *sync.WaitGroup, kprobe *ObserverKprobe, ctx context.Context) {
	exitWG.Add(1)
	execWG.Add(1)
	go func() {
		defer exitWG.Done()
		e, err := kprobe.__runEvents(ctx)
		if err != nil {
			RemovePrograms(kprobe.bpfDir, kprobe.mapDir)
			t.Fatalf("runEvents error: %s", err)
		}
		defer e.CloseAll()
		execWG.Done()
		kprobe.__loopEvents(ctx, e)
	}()
}

func execWGCurl(execWG, exitWG *sync.WaitGroup, args string) {
	execWG.Wait()
	cmd := exec.Command("/usr/bin/curl", args)
	err := cmd.Run()
	fmt.Printf("cmd %v err %v\n", cmd, err)
	exitWG.Wait()
}

// dockerRun starts a new docker container in the background. The container will
// be killed and removed on test cleanup.
// It returns the containerId on success, or an error if spawning the container failed.
func dockerRun(t *testing.T, args ...string) (containerId string) {
	// note: we are not using `--rm` so we can choose to wait on the container
	// with `docker wait`. We remove it manually below in t.Cleanup instead
	args = append([]string{"run", "--detach"}, args...)
	id, err := exec.Command("docker", args...).Output()
	if err != nil {
		t.Fatalf("failed to spawn docker container %v: %s", args, err)
	}

	containerId = strings.TrimSpace(string(id))
	t.Cleanup(func() {
		err := exec.Command("docker", "rm", "--force", containerId).Run()
		if err != nil {
			t.Logf("failed to remove container %s: %s", containerId, err)
		}
	})

	return containerId
}

type fakeK8sWatcher struct {
	OnFindPod func(containerID string) (*corev1.Pod, *corev1.ContainerStatus, bool)
}

func (f *fakeK8sWatcher) FindPod(containerID string) (*corev1.Pod, *corev1.ContainerStatus, bool) {
	if f.OnFindPod == nil {
		panic("FindPod not implemented")
	}
	return f.OnFindPod(containerID)
}

// Used to wait for a process to start, we do a lookup on PROCFS
// because this may be called before kprobe is created.
func waitForProcess(process string) error {
	var b []byte
	b = append(b, 0x00)

	procfs := os.Getenv("FGS_PROCFS")
	if procfs == "" {
		procfs = "/proc/"
	}
	procDir, _ := ioutil.ReadDir(procfs)
	for i := 0; i < 120; i++ {
		for _, d := range procDir {

			cmdline, err := ioutil.ReadFile(filepath.Join(procfs, d.Name(), "/cmdline"))
			if err != nil {
				continue
			}
			cmdTokens := bytes.Split([]byte(cmdline), b)
			cmd := string(bytes.Join(cmdTokens, []byte(" ")))
			if strings.Contains(cmd, process) {
				return nil
			}
		}
		time.Sleep(1 * time.Second)
	}
	return fmt.Errorf("process '%s' did not start", process)
}

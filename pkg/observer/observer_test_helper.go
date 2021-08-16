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

	hubbleV1 "github.com/cilium/hubble/pkg/api/v1"
	hubbleCilium "github.com/cilium/hubble/pkg/cilium"

	"github.com/isovalent/hubble-fgs/api/v1/fgs"
	"github.com/isovalent/hubble-fgs/pkg/bpf"
	"github.com/isovalent/hubble-fgs/pkg/btf"
	"github.com/isovalent/hubble-fgs/pkg/cilium"
	"github.com/isovalent/hubble-fgs/pkg/filters"
	fgsGrpc "github.com/isovalent/hubble-fgs/pkg/grpc"
	"github.com/isovalent/hubble-fgs/pkg/logger"

	"gopkg.in/natefinch/lumberjack.v2"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var (
	observerTestDir = "/sys/fs/bpf/testObserver/"
	exportFile      = "/tmp/hubble-fgs.gotest"
	jsonRetries     = 10
)

const (
	dfltVerbosity = 0
)

type testObserverOptions struct {
	tls    bool
	tlstc  bool
	pretty bool
	crd    bool
	probes string
	config string
	lib    string
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

func withLib(lib string) testOption {
	return func(o *testOptions) {
		o.observer.lib = lib
	}
}

func TestDone(t *testing.T, kprobe *ObserverKprobe) {
	kprobe.RemovePrograms()
	kprobe.PrintStats()
}

// Create a fake Cilium state to avoid the events getting delayed due to missing pod info
func createFakeCiliumState(testPod, testNamespace string) *hubbleCilium.State {
	s := cilium.GetFakeCiliumState()
	s.GetEndpointsHandler().UpdateEndpoint(&hubbleV1.Endpoint{
		ID:           1234,
		PodName:      testPod,
		PodNamespace: testNamespace,
	})
	return s
}

// Create a fake K8s watcher to avoid delayed event due to missing pod info
func createFakeWatcher(testPod, testNamespace string) *fakeK8sWatcher {
	return &fakeK8sWatcher{
		OnFindPod: func(containerID string) (*corev1.Pod, *corev1.ContainerStatus, bool) {
			if containerID == "" {
				return nil, nil, false
			}

			container := corev1.ContainerStatus{
				Name:        containerID,
				Image:       "image",
				ImageID:     "id",
				ContainerID: "docker://" + containerID,
				State: corev1.ContainerState{
					Running: &corev1.ContainerStateRunning{
						StartedAt: v1.Time{
							Time: time.Unix(1, 2),
						},
					},
				},
			}
			pod := corev1.Pod{
				ObjectMeta: v1.ObjectMeta{
					Name:      testPod,
					Namespace: testNamespace,
				},
				Status: corev1.PodStatus{
					ContainerStatuses: []corev1.ContainerStatus{
						container,
					},
				},
			}

			return &pod, &container, true
		},
	}
}

func newDefaultTestOptions(t *testing.T, opts ...testOption) *testOptions {
	// default values
	options := &testOptions{
		observer: testObserverOptions{
			tls:    false,
			tlstc:  false,
			pretty: false,
			crd:    false,
			config: "",
			lib:    "",
		},
		exporter: testExporterOptions{
			watcher:     fgsGrpc.NewFakeK8sWatcher(nil),
			ciliumState: cilium.GetFakeCiliumState(),
		},
	}
	// apply user options
	for _, opt := range opts {
		opt(options)
	}

	return options
}

func newDefaultObserver(t *testing.T, oo *testObserverOptions) *ObserverKprobe {
	return NewObserverKprobe(observerTestDir,
		observerTestDir,
		"", "",
		oo.config, oo.tls, oo.tlstc, oo.pretty, oo.crd,
		0)
}

func getDefaultObserver(t *testing.T, opts ...testOption) (*ObserverKprobe, error) {
	ctx, _ := context.WithCancel(context.Background())
	o := newDefaultTestOptions(t, opts...)

	HubbleLib = os.Getenv("FGS_LIB")
	if HubbleLib == "" {
		HubbleLib = o.observer.lib
	}
	procfs := os.Getenv("FGS_PROCFS")
	if procfs != "" {
		ProcFS = procfs
	}

	kprobe := newDefaultObserver(t, &o.observer)
	if testing.Verbose() {
		Verbosity = dfltVerbosity
	}

	if err := btf.InitCachedBTF(HubbleLib, ctx); err != nil {
		return nil, err
	}

	loadExporter(t, kprobe, &o.exporter)
	loadObserver(t, kprobe)

	kprobe.perfConfig = bpf.DefaultPerfEventConfig()
	kprobe.perfConfig.MapName = observerTestDir + "tcpmon_map"
	return kprobe, nil
}

func getDefaultObserverWithWatchers(t *testing.T, opts ...testOption) (*ObserverKprobe, error) {
	const (
		testPod       = "pod-1"
		testNamespace = "ns-1"
	)

	w := createFakeWatcher(testPod, testNamespace)
	s := createFakeCiliumState(testPod, testNamespace)

	opts = append(opts, withK8sWatcher(w))
	opts = append(opts, withCiliumState(s))
	return getDefaultObserver(t, opts...)
}

func GetDefaultObserverWithFile(t *testing.T, file, lib string) (*ObserverKprobe, error) {
	return getDefaultObserverWithWatchers(t, withConfig(file), withPretty(), withLib(lib))
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
	server := fgsGrpc.NewServer(processManager, kprobe.ObserverSync)
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
	exporter := fgsGrpc.NewExporter(ctx, &req, server, encoder, nil)
	go exporter.Start()
	kprobe.AddListener(processManager)
	return nil
}

func loadObserver(t *testing.T, kprobe *ObserverKprobe) {
	if err := LoadDefaultSensor(kprobe.bpfDir, kprobe.mapDir, kprobe.ciliumDir,
		context.TODO()); err != nil {
		t.Fatalf("LoadDefaultSensor error: %s\n", err)
	}

	if kprobe.configFile != "" {
		sensor, err := getSensorFromTracingPolicyFname(kprobe.configFile)
		if err != nil {
			t.Fatalf("createGenericKprobeSensors error: Could not create kprobe sensor: %s", err)
		}

		if sensor != nil {
			if err := ObserverLoadSensor(kprobe.bpfDir, kprobe.mapDir, kprobe.ciliumDir, context.TODO(), sensor); err != nil {
				t.Fatalf("generic observerLoadSensors error: Could not load kprobe sensors: %s", err)
			}
		}
	}

	kprobe.populateExecve(context.TODO())
}

func LoopEvents(t *testing.T, exitWG, execWG *sync.WaitGroup, kprobe *ObserverKprobe, ctx context.Context) {
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

func ExecWGCurl(execWG, exitWG *sync.WaitGroup, args string) {
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

func WriteConfigFile(fileName, config string) error {
	out, err := os.Create(fileName)
	if err != nil {
		return err
	}
	if _, err := out.Write([]byte(config)); err != nil {
		return err
	}
	return out.Sync()
}

package observer

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"

	"github.com/covalentio/hubble-fgs/api/v1/fgs"
	"github.com/covalentio/hubble-fgs/pkg/filters"
	fgsGrpc "github.com/covalentio/hubble-fgs/pkg/grpc"
	"github.com/covalentio/hubble-fgs/pkg/logger"

	hubbleCilium "github.com/cilium/hubble/pkg/cilium"
	"golang.org/x/sys/unix"
	"gopkg.in/natefinch/lumberjack.v2"
)

var (
	observerTestDir = "/sys/fs/bpf/testObserver/"
	exportFile      = "/tmp/hubble-fgs.gotest"
	jsonRetries     = 4
)

type testObserverOptions struct {
	tls    bool
	tlstc  bool
	pretty bool
	probes string
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

func withProbes(probes string) testOption {
	return func(o *testOptions) {
		o.observer.probes = probes
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
	runningVersion := int(kernelStringToNumeric(numeric))
	minVersion := int(kernelStringToNumeric(kernel))
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
	kprobe.createDir()
	initialSensor := kprobe.createInitialObserverSensor()
	if err := kprobe.observerLoadSensor(context.TODO(), initialSensor); err != nil {
		kprobe.RemovePrograms()
		t.Fatalf("observerLoadProgs error: %s", err)
	}
	if kprobe.genericKprobes != "" {
		kprobe.initKprobeSensors()
		genericKprobeSensor := kprobe.createGenericKprobeSensors(kprobe.genericKprobes, ObserverBTF)
		if err := kprobe.observerLoadSensor(context.TODO(), genericKprobeSensor); err != nil {
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
			kprobe.RemovePrograms()
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

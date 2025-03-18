package parsertest

import (
	"context"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/btf"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/sensors/exec/execvemap"
	"github.com/isovalent/hubble-fgs/pkg/sensors/base"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/exec"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/http"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/layer3"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/sockmap"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/sockops"
)

// Testdata directory. We'll probe for it's location
// by changing working directory upwards towards /.
var testsRoot = "testdata/parser"

// Number of times to execute each test case. Useful to execute each test multiple
// times to make sure no events are left unhandled and that parser's work over multiple
// runs.
var numRunsPerTestcase = 3

const (
	SENS_INITIAL = iota
	SENS_TLS
	SENS_HTTP
	SENS_NOP
)

func init() {
	if os.Geteuid() != 0 {
		panic("This test needs to be run as root")
	}

	bpf.ConfigureResourceLimits()
	bpf.CheckOrMountFS("")
	bpf.CheckOrMountDebugFS()
	bpf.CheckOrMountCgroup2()
	bpf.SetMapPrefix("fgs-parsertest")
	os.Mkdir(bpf.MapPrefixPath(), os.ModeDir)

	// Try to probe for FGS bpf object location
	wd, _ := os.Getwd()
	if _, err := os.Stat("../../bpf/objs"); err == nil {
		option.Config.HubbleLib = path.Clean(path.Join(wd, "../../bpf/objs"))
	} else if _, err := os.Stat("bpf/objs"); err == nil {
		option.Config.HubbleLib = path.Clean(path.Join(wd, "bpf/objs"))
	} else {
		option.Config.HubbleLib = "/var/lib/hubble-fgs"
	}

	// Setup BTF cache
	btf.InitCachedBTF(option.Config.HubbleLib, "")

	// Probe for the testdata. Changing the working directory
	// to keep the test-case filenames short.
	for {
		if _, err := os.Stat(testsRoot); err == nil {
			break
		}
		wd, _ := os.Getwd()
		if wd == "/" {
			panic("could not find testdata/parser")
		}
		os.Chdir("..")
	}
}

func TestMain(m *testing.M) {
	flag.IntVar(&numRunsPerTestcase, "parsertest-runs", numRunsPerTestcase,
		"Number of times to repeat each testcase")
	flag.Parse()
	os.Exit(m.Run())
}

type SensorsHandle struct {
	initSensor   *sensors.Sensor
	parserSensor *sensors.Sensor
	ctx          context.Context
	cancel       context.CancelFunc
}

func (h *SensorsHandle) Close(t *testing.T) {
	h.cancel()

	bpfDir := bpf.MapPrefixPath()
	h.parserSensor.Unload(true)
	h.initSensor.Unload(true)

	// Verify that all pins have been cleared.
	filepath.Walk(bpfDir, func(path string, info fs.FileInfo, _ error) error {
		if info != nil && !info.IsDir() {
			t.Fatalf("FIXME: File '%s' still exists after sensor unload", path)
		}
		return nil
	})
	os.Remove(bpfDir)

	// TODO verify that no fds are leaked
}

func startSensors(cfg int, t *testing.T) SensorsHandle {
	ctx, cancel := context.WithCancel(context.Background())

	// Load the initial sensor.
	initSensor := base.GetInitialSensor()

	err := initSensor.Load(bpf.MapPrefixPath())
	if err != nil {
		t.Fatalf("s.Load: %s\n", err)
	}

	var spec v1alpha1.ParserPolicySpec
	switch cfg {
	case SENS_TLS:
		spec = v1alpha1.ParserPolicySpec{
			Tls: v1alpha1.TlsSpec{
				Enable: true,
				Mode:   "socket",
				Selectors: []v1alpha1.TlsSelector{
					{MatchPorts: []uint32{8888}},
				},
			},
			Udp: v1alpha1.UdpPolicySpec{
				Enable:                   true,
				Cgroup:                   true,
				StatsInterval:            0,
				DeleteIdleSocketInterval: 0,
				Watermarks:               v1alpha1.UdpWatermarksPolicySpec{},
			},
			Tcp: v1alpha1.TcpPolicySpec{
				Enable:        true,
				StatsInterval: 0,
				Watermarks:    v1alpha1.TcpWatermarksPolicySpec{},
			},
		}
	case SENS_HTTP:
		spec = v1alpha1.ParserPolicySpec{
			Http: v1alpha1.HttpSpec{
				Enable: true,
				Selectors: []v1alpha1.HttpSelector{
					{MatchPorts: []uint32{8888}},
				},
			},
			Udp: v1alpha1.UdpPolicySpec{
				Enable:                   true,
				Cgroup:                   true,
				StatsInterval:            0,
				DeleteIdleSocketInterval: 0,
				Watermarks:               v1alpha1.UdpWatermarksPolicySpec{},
			},
			Tcp: v1alpha1.TcpPolicySpec{
				Enable:        true,
				StatsInterval: 0,
				Watermarks:    v1alpha1.TcpWatermarksPolicySpec{},
			},
		}
	case SENS_NOP:
		spec = v1alpha1.ParserPolicySpec{
			Tcp: v1alpha1.TcpPolicySpec{
				Enable:        true,
				StatsInterval: 0,
			},
			Udp: v1alpha1.UdpPolicySpec{
				Enable:                   true,
				Cgroup:                   true,
				StatsInterval:            0,
				DeleteIdleSocketInterval: 0,
				Watermarks:               v1alpha1.UdpWatermarksPolicySpec{},
			},
			Nop: v1alpha1.NopSpec{
				Enable: true,
				Selectors: []v1alpha1.NopSelector{
					{MatchPorts: []uint32{8888}},
				},
			},
		}
	case SENS_INITIAL:
		spec = v1alpha1.ParserPolicySpec{
			Tcp: v1alpha1.TcpPolicySpec{
				Enable:        true,
				StatsInterval: 0,
			},
			Udp: v1alpha1.UdpPolicySpec{
				Enable:                   true,
				Cgroup:                   true,
				StatsInterval:            0,
				DeleteIdleSocketInterval: 1,
				Watermarks:               v1alpha1.UdpWatermarksPolicySpec{},
			},
		}
	default:
		panic(fmt.Sprintf("unimplemented %d", cfg))
	}

	tp := tracingpolicy.GenericTracingPolicy{
		Metadata: v1.ObjectMeta{Name: "name"},
		Spec:     v1alpha1.TracingPolicySpec{Parser: spec},
	}
	sis, err := sensors.SensorsFromPolicy(&tp, policyfilter.PolicyID(0))
	if err != nil {
		t.Fatalf("GetSensorsFromParserPolicy: %s", err)
	}
	parserSensors := make([]*sensors.Sensor, 0, len(sis))
	for _, s := range sis {
		parserSensors = append(parserSensors, s.(*sensors.Sensor))
	}
	parserSensor := sensors.SensorCombine(&tp, "parser", parserSensors...)

	err = parserSensor.Load(bpf.MapPrefixPath())
	if err != nil {
		t.Fatalf("s.Load: %s\n", err)
	}
	return SensorsHandle{initSensor, parserSensor, ctx, cancel}
}

func addSelfToEvecveMap(t *testing.T) {
	m, err := ebpf.LoadPinnedMap(filepath.Join(bpf.MapPrefixPath(), base.GetExecveMap().Name), nil)
	if err != nil {
		t.Fatalf("OpenMap: %s\n", err)
	}
	defer m.Close()

	pid := uint32(os.Getpid())
	ppid := uint32(os.Getppid())

	err = m.Put(
		&execvemap.ExecveKey{Pid: pid},
		&execvemap.ExecveValue{
			Parent:  processapi.MsgExecveKey{Pid: ppid, Pad: 0, Ktime: 0xcacababa},
			Process: processapi.MsgExecveKey{Pid: pid, Pad: 0, Ktime: 0x01020304deadbeef},
		},
	)
	if err != nil {
		t.Fatalf("Map.Put: %s\n", err)
	}
}

func fixupTestCaseForNopSensor(tc *TestCase) {
	var steps []TestStep
	for _, step := range tc.Steps {
		switch step.(type) {
		case *TestStepEvent:
			continue
		case *TestStepEventDump:
			continue
		case *TestStepEvents:
			continue
		}
		steps = append(steps, step)
	}
	tc.Steps = steps
}

func runTests(t *testing.T, sensor int, dir string) {
	handle := startSensors(sensor, t)
	defer handle.Close(t)

	addSelfToEvecveMap(t)

	fs.WalkDir(
		os.DirFS(testsRoot), dir,
		func(relpath string, d fs.DirEntry, err error) error {
			if err != nil {
				t.Fatal(err)
			}

			if d.IsDir() {
				return nil
			}

			brokenTestFailed := false
			ok := true
			for i := 0; i < numRunsPerTestcase && ok && !brokenTestFailed; i++ {
				tc, err := ParseTestCase(path.Join(testsRoot, relpath))
				if err != nil {
					t.Fatal(err)
				}

				// Fixup the NOP sensor so that we are not expecting any events
				if sensor == SENS_NOP {
					fixupTestCaseForNopSensor(tc)
				}

				if os.Getenv("FLAKY_HTTP") != "" {
					tc.Tags["broken"] = struct{}{}
				}

				ok = t.Run(fmt.Sprintf("%s/%d", path.Base(relpath), i+1), func(t *testing.T) {
					err = tc.Run(t, TEST_TIMEOUT)
					if err != nil {
						if tc.IsBroken() {
							brokenTestFailed = true
							t.Skipf("Broken test failed as expected:\n%s", err)
						} else {
							t.Fatal(err)
						}
					} else if tc.IsBroken() {
						t.Log("Broken test succeeded, consider dropping 'broken' tag?")
					}
				})
			}
			return nil
		})

}

func Test_tls(t *testing.T) {
	if v := "5.10.0"; !kernels.MinKernelVersion(v) {
		t.Skipf("Minimum kernel version (%v) not met, skipping", v)
	}
	if runtime.GOARCH != "amd64" {
		t.Skipf("ARM bug breaks with mixed bpf2bpf calls and tail calls, skipping")
	}
	if os.Getenv("FLAKY_HTTP") != "" {
		t.Skipf("Skipping test on flaky kernel")
	}
	runTests(t, SENS_TLS, "tls")
}

func Test_http(t *testing.T) {
	if v := "5.10.0"; !kernels.MinKernelVersion(v) {
		t.Skipf("Minimum kernel version (%v) not met, skipping", v)
	}
	if runtime.GOARCH != "amd64" {
		t.Skipf("ARM bug breaks with mixed bpf2bpf calls and tail calls, skipping")
	}
	if os.Getenv("FLAKY_HTTP") != "" {
		t.Skipf("Skipping test on flaky kernel")
	}
	runTests(t, SENS_HTTP, "http")
}

func Test_http2(t *testing.T) {
	if v := "5.10.0"; !kernels.MinKernelVersion(v) {
		t.Skipf("Minimum kernel version (%v) not met, skipping", v)
	}
	if runtime.GOARCH != "amd64" {
		t.Skipf("ARM bug breaks with mixed bpf2bpf calls and tail calls, skipping")
	}
	if os.Getenv("FLAKY_HTTP") != "" {
		t.Skipf("Skipping test on flaky kernel")
	}
	runTests(t, SENS_HTTP, "http2")
}

func Test_nop(t *testing.T) {
	if v := "5.10.0"; !kernels.MinKernelVersion(v) {
		t.Skipf("Minimum kernel version (%v) not met, skipping", v)
	}
	if os.Getenv("FLAKY_HTTP") != "" {
		t.Skipf("Skipping test on flaky kernel")
	}
	runTests(t, SENS_NOP, "tls")
	runTests(t, SENS_NOP, "http")
	runTests(t, SENS_NOP, "http2")
	runTests(t, SENS_NOP, "tcp")
	runTests(t, SENS_NOP, "udp")
}

func Test_tcp(t *testing.T) {
	if v := "5.10.0"; !kernels.MinKernelVersion(v) {
		t.Skipf("Minimum kernel version (%v) not met, skipping", v)
	}
	runTests(t, SENS_INITIAL, "tcp")
}

func Test_udp(t *testing.T) {
	if v := "5.10.0"; !kernels.MinKernelVersion(v) {
		t.Skipf("Minimum kernel version (%v) not met, skipping", v)
	}
	runTests(t, SENS_INITIAL, "udp")
}

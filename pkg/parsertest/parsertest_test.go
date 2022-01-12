package parsertest

import (
	"context"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/isovalent/hubble-fgs/pkg/api"
	"github.com/isovalent/hubble-fgs/pkg/bpf"
	"github.com/isovalent/hubble-fgs/pkg/btf"
	"github.com/isovalent/hubble-fgs/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/isovalent/hubble-fgs/pkg/kernels"
	"github.com/isovalent/hubble-fgs/pkg/observer"
	"github.com/isovalent/hubble-fgs/pkg/option"
	"github.com/isovalent/hubble-fgs/pkg/sensors"
	"github.com/isovalent/hubble-fgs/pkg/sensors/http"
	"github.com/isovalent/hubble-fgs/pkg/sensors/sockmap"
	"github.com/isovalent/hubble-fgs/pkg/sensors/sockops"
)

const (
	testTimeout = 10 * time.Second
)

// Testdata directory. We'll probe for it's location
// by changing working directory upwards towards /.
var testsRoot = "testdata/parser"

var numRunsPerTestcase = 3

const (
	SENS_INITIAL = iota
	SENS_TLS
	SENS_HTTP
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
	btf.InitCachedBTF(option.Config.HubbleLib, "", context.Background())

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
	sensor *sensors.Sensor
	ctx    context.Context
	cancel context.CancelFunc
}

func (h *SensorsHandle) Close() {
	bpfDir := bpf.MapPrefixPath()
	for _, l := range h.sensor.Progs {
		sensors.RemoveProgram(bpfDir, l)
	}
	for _, m := range h.sensor.Maps {
		if m.FD > 0 {
			syscall.Close(m.FD)
		}
		path := filepath.Join(bpfDir, m.Name)
		if err := os.Remove(path); err != nil {
			log.Fatalf("Failed to remove map %s: %s\n", m.Name, err)
		}
	}
	err := os.Remove(bpfDir)
	if err != nil {
		log.Fatalf("os.Remove(%s): %s\n", bpfDir, err)
	}
}

func startSensors(cfg int, t *testing.T) SensorsHandle {

	sensor := sensors.GetInitialSensor()

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
		}
		tlsSensor, err := sockmap.AddTLSSensor(spec)
		if err != nil {
			t.Fatalf("AddTLSSensor: %s\n", err)
		}
		sensor = sensors.SensorCombine("init+tls", sensor, tlsSensor)

	case SENS_HTTP:
		spec = v1alpha1.ParserPolicySpec{
			Http: v1alpha1.HttpSpec{
				Enable: true,
				Selectors: []v1alpha1.HttpSelector{
					{MatchPorts: []uint32{8888}},
				},
			},
		}

		httpSensor, err := http.AddHTTPSensor(spec)
		if err != nil {
			t.Fatalf("AddHTTPSensor: %s\n", err)
		}
		sensor = sensors.SensorCombine("init+http", sensor, httpSensor)

		// Add the sockops program.
		sensor = sensors.SensorCombine("sensor", sensor,
			sensors.SensorBuilder("sensor",
				[]*sensors.Program{sockops.SockopsEstablished},
				[]*sensors.Map{}))

	case SENS_INITIAL:

	default:
		panic(fmt.Sprintf("unimplemented %d", cfg))
	}

	ctx, cancel := context.WithCancel(context.Background())
	err := sensor.Load(ctx, bpf.MapPrefixPath(), bpf.MapPrefixPath(), "")
	if err != nil {
		t.Fatalf("s.Load: %s\n", err)
	}
	return SensorsHandle{sensor, ctx, cancel}
}

func addSelfToEvecveMap(t *testing.T) {
	m, err := bpf.OpenMap(filepath.Join(bpf.MapPrefixPath(), sensors.ExecveMap.Name))
	if err != nil {
		t.Fatalf("OpenMap: %s\n", err)
	}

	pid := uint32(os.Getpid())
	ppid := uint32(os.Getppid())

	err = m.Update(
		&observer.ExecveKey{Pid: pid},
		&observer.ExecveValue{
			Parent:  api.MsgExecveKey{ppid, 0, 0xcacababa},
			Process: api.MsgExecveKey{pid, 0, 0x01020304deadbeef},
		},
	)
	if err != nil {
		t.Fatalf("Map.Update: %s\n", err)
	}
}

func runTests(t *testing.T, sensor int, dir string) {
	handle := startSensors(sensor, t)
	defer handle.Close()

	dispatcher, err := NewEventDispatcher()
	if err != nil {
		t.Fatal(err)
	}
	defer dispatcher.Close()

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

			for i := 0; i < numRunsPerTestcase; i++ {
				t.Run(fmt.Sprintf("%s/%d", path.Base(relpath), i+1), func(t *testing.T) {
					tc, err := ParseTestCase(path.Join(testsRoot, relpath))
					if err != nil {
						t.Fatal(err)
					}

					err = tc.Run(t, dispatcher, testTimeout)
					if err != nil {
						t.Fatal(err)
					}
				})
			}
			return nil
		})

}

func TestTLS(t *testing.T) {
	if v := "5.8.0"; !kernels.MinKernelVersion(v) {
		t.Skipf("Minimum kernel version (%v) not met, skipping", v)
	}
	runTests(t, SENS_TLS, "tls")
}

func TestHTTP(t *testing.T) {
	if v := "5.8.0"; !kernels.MinKernelVersion(v) {
		t.Skipf("Minimum kernel version (%v) not met, skipping", v)
	}
	runTests(t, SENS_HTTP, "http")
}

func TestHTTP2(t *testing.T) {
	if v := "5.8.0"; !kernels.MinKernelVersion(v) {
		t.Skipf("Minimum kernel version (%v) not met, skipping", v)
	}
	runTests(t, SENS_HTTP, "http2")
}

func TestTCP(t *testing.T) {
	if v := "5.8.0"; !kernels.MinKernelVersion(v) {
		t.Skipf("Minimum kernel version (%v) not met, skipping", v)
	}
	runTests(t, SENS_INITIAL, "tcp")
}

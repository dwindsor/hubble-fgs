package parsertest

import (
	"context"
	"io/fs"
	"log"
	"os"
	"path"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/isovalent/hubble-fgs/pkg/bpf"
	"github.com/isovalent/hubble-fgs/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/isovalent/hubble-fgs/pkg/option"
	"github.com/isovalent/hubble-fgs/pkg/sensors"
	"github.com/isovalent/hubble-fgs/pkg/sensors/http"
	"github.com/isovalent/hubble-fgs/pkg/sensors/sockmap"
)

const (
	// Test-case root directory, relative to this package.
	testsRoot   = "../../testdata/parser"
	testTimeout = 10 * time.Second
)

const (
	FGS_INITIAL = iota
	FGS_TLS
	FGS_HTTP
)

func init() {
	bpf.ConfigureResourceLimits()
	bpf.CheckOrMountFS("")
	bpf.CheckOrMountDebugFS()
	bpf.CheckOrMountCgroup2()
	bpf.SetMapPrefix("fgs-parsertest")
	os.Mkdir(bpf.MapPrefixPath(), os.ModeDir)
	option.Config.HubbleLib = "../../bpf/objs"
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
	if cfg == FGS_TLS {
		spec = v1alpha1.ParserPolicySpec{
			Http: v1alpha1.HttpSpec{
				Enable: false,
				Selectors: []v1alpha1.HttpSelector{
					{MatchPorts: []uint32{1}},
				},
			},
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

	} else if cfg == FGS_HTTP {
		spec = v1alpha1.ParserPolicySpec{
			Http: v1alpha1.HttpSpec{
				Enable: true,
				Selectors: []v1alpha1.HttpSelector{
					{MatchPorts: []uint32{8888}},
				},
			},
			Tls: v1alpha1.TlsSpec{
				Enable: false,
				Mode:   "socket",
				Selectors: []v1alpha1.TlsSelector{
					{MatchPorts: []uint32{1}},
				},
			},
		}

		httpSensor, err := http.AddHTTPSensor(spec)
		if err != nil {
			t.Fatalf("AddHTTPSensor: %s\n", err)
		}
		sensor = sensors.SensorCombine("init+http", sensor, httpSensor)
	}

	ctx, cancel := context.WithCancel(context.Background())
	err := sensor.Load(ctx, bpf.MapPrefixPath(), bpf.MapPrefixPath(), "")
	if err != nil {
		t.Fatalf("s.Load: %s\n", err)
	}
	return SensorsHandle{sensor, ctx, cancel}
}

func runTests(t *testing.T, cfg int, dir string) {
	handle := startSensors(FGS_TLS, t)
	defer handle.Close()

	dispatcher, err := NewEventDispatcher()
	if err != nil {
		t.Fatal(err)
	}

	fs.WalkDir(
		os.DirFS(testsRoot), dir,
		func(relpath string, d fs.DirEntry, err error) error {
			if err != nil {
				t.Fatal(err)
			}

			if d.IsDir() {
				return nil
			}

			t.Run(path.Base(relpath), func(t *testing.T) {
				tc, err := ParseTestCase(path.Join(testsRoot, relpath))
				if err != nil {
					t.Fatal(err)
				}

				err = tc.Run(t, dispatcher, testTimeout)
				if err != nil {
					t.Fatal(err)
				}
			})
			return nil
		})

}

func TestTLS(t *testing.T) {
	runTests(t, FGS_TLS, "tls")
}

// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package bench

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"path"
	"sync"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/api/readyapi"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/btf"
	"github.com/cilium/tetragon/pkg/cilium"
	"github.com/cilium/tetragon/pkg/exporter"
	fgsGrpc "github.com/cilium/tetragon/pkg/grpc"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/process"
	"github.com/cilium/tetragon/pkg/reader/notify"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
	"google.golang.org/protobuf/proto"

	hubblev1 "github.com/cilium/tetragon/pkg/oldhubble/api/v1"
	corev1 "k8s.io/api/core/v1"

	// Imported to allow sensors to be initialized inside init().
	_ "github.com/cilium/tetragon/pkg/sensors"
	"github.com/isovalent/hubble-fgs/pkg/sensors/base"

	// Init sensors for benchmarking
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/exec"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/sockmap"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/tcp"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/udp"
)

//
// Race detection for hubble-tetragon. This is similar to the fgs-bench in that we're
// running hubble-fgs along with some load, but here the goal is to generate lots
// of different types of events to exercise many different parts of hubble-fgs to
// catch race conditions using the Go race detector ("-race").
//

type raceListener struct {
	ready chan bool
}

func (l *raceListener) Notify(msg notify.Message) error {
	switch msg.(type) {
	case *readyapi.MsgTetragonReady:
		l.ready <- true
	}
	return nil
}

func (l *raceListener) Close() error {
	return nil
}

type raceK8sWatcher struct {
}

func (r *raceK8sWatcher) FindContainer(containerID string) (*corev1.Pod, *corev1.ContainerStatus, bool) {
	if containerID == "" {
		return nil, nil, false
	}
	// Return a fake pod, some of the time to simulate the propagation delay.
	if rand.Int31()%3 == 0 {
		return &corev1.Pod{}, &corev1.ContainerStatus{Image: "fake"}, true
	}
	return nil, nil, false
}

func (r *raceK8sWatcher) FindPod(podID string) (*corev1.Pod, error) {
	if podID == "" {
		return nil, errors.New("empty pod ID")
	}

	return &corev1.Pod{}, nil
}

func (r *raceK8sWatcher) GetPodInfo(_, _, _ string, _ uint32) (*tetragon.Pod, *hubblev1.Endpoint) {
	return nil, nil
}

func (r *raceK8sWatcher) FindServiceByIP(ip string) ([]*corev1.Service, error) {
	return nil, fmt.Errorf("service with IP %s not found", ip)
}

func (r *raceK8sWatcher) FindPodInfoByIP(ip string) ([]*v1alpha1.PodInfo, error) {
	return nil, fmt.Errorf("PodInfo with IP %s not found", ip)
}

type raceEncoder struct {
	count int
	enc   *json.Encoder
}

func (re *raceEncoder) Encode(v interface{}) error {
	re.count++
	if re.count%1000 == 0 {
		logger.GetLogger().Infof("FGS RACE: %d events received...", re.count)
	}

	// Also do protobuf marshalling to catch races
	event := v.(*tetragon.GetEventsResponse)
	buf, err := proto.Marshal(event)
	if err != nil {
		panic(err)
	}
	var event2 tetragon.GetEventsResponse
	err = proto.Unmarshal(buf, &event2)
	if err != nil {
		panic(err)
	}

	return re.enc.Encode(v)
}

func startRaceExporter(ctx context.Context, obs *observer.Observer) error {
	var wg sync.WaitGroup

	processCacheSize := 32768
	dataCacheSize := 1024
	option.Config.EnableProcessCred = false
	option.Config.EnableProcessNs = false
	option.Config.EnableCilium = false
	// todo enableProcessAncestors := false

	if _, err := cilium.InitCiliumState(ctx, option.Config.EnableCilium); err != nil {
		return err
	}

	watcher := &raceK8sWatcher{}
	if err := process.InitCache(watcher, processCacheSize); err != nil {
		return err
	}

	if err := observer.InitDataCache(dataCacheSize); err != nil {
		return err
	}

	processManager, err := fgsGrpc.NewProcessManager(
		ctx,
		&wg,
		observer.SensorManager,
		glblHookRunner,
	)
	if err != nil {
		return err
	}

	encoder := &raceEncoder{0, json.NewEncoder(io.Discard)}
	//encoder := &raceEncoder{0, json.NewEncoder(os.Stdout)}

	req := tetragon.GetEventsRequest{AllowList: nil, DenyList: nil, AggregationOptions: nil}
	exporter := exporter.NewExporter(ctx, &req, processManager.Server, encoder, nil, nil)

	if err := base.LoadDefault(
		option.Config.BpfDir,
		option.Config.MapDir); err != nil {
		log.Fatalf("Load Defaults failed: %v", err)
	}

	exporter.Start()
	obs.AddListener(processManager)
	return nil
}

var benchConfig = `
apiVersion: hubble-enterprise.io/v1
metadata:
  name: "race"
spec:
  parser:
    http:
      enable: true
    udp:
      enable: true
      cgroup: true
      statsInterval: 1
      deleteIdleSocketInterval: 60
    tcp:
      enable: true
      statsInterval: 1
    dns:
      enable: false
`

const (
	fgsRaceDir = "/sys/fs/bpf/fgs-race"
)

func runRaceFGS(ctx context.Context, ready chan bool) {
	bpf.ConfigureResourceLimits()
	bpf.CheckOrMountFS("")
	bpf.CheckOrMountDebugFS()
	bpf.CheckOrMountCgroup2()
	bpf.SetMapPrefix("fgs-race")

	option.Config.BpfDir = fgsRaceDir
	option.Config.MapDir = fgsRaceDir

	if _, err := os.Stat("../../bpf/objs"); err == nil {
		option.Config.HubbleLib = "../../bpf/objs"
	} else {
		exePath, err := os.Executable()
		if err != nil {
			logger.GetLogger().Fatal(err)
		}
		option.Config.HubbleLib = path.Join(path.Dir(exePath), "bpf/objs")

		if _, err := os.Stat(option.Config.HubbleLib); err != nil {
			// Running outside the source tree, fall back to default location.
			option.Config.HubbleLib = "/var/lib/hubble-fgs"
		}
	}

	f, err := os.CreateTemp("/tmp", "fgs-race-crd-*.yaml")
	if err != nil {
		logger.GetLogger().Fatal(err)
	}
	defer os.Remove(f.Name())
	f.Write([]byte(benchConfig))
	f.Close()

	option.Config.BpfDir = bpf.MapPrefixPath()
	option.Config.MapDir = bpf.MapPrefixPath()
	obs := observer.NewObserver(f.Name())

	if err := obs.InitSensorManager(nil); err != nil {
		logger.GetLogger().Fatalf("InitSensorManager failed: %v", err)
	}

	if err := btf.InitCachedBTF(option.Config.HubbleLib, ""); err != nil {
		logger.GetLogger().Fatal(err)
	}

	rl := &raceListener{ready}
	obs.AddListener(rl)

	if err := startRaceExporter(ctx, obs); err != nil {
		logger.GetLogger().Fatal(err)
	}

	tp, err := tracingpolicy.PolicyFromYAMLFilename(f.Name())
	if err != nil {
		logger.GetLogger().Fatalf("ReadConfig failed: %v", err)
	}

	startSensors, err := sensors.GetMergedSensorFromParserPolicy(tp)
	if err != nil {
		log.Fatalf("GetSensorsFromParserPolicy error: %v", err)
	}

	if err := startSensors.Load(
		option.Config.BpfDir,
		option.Config.MapDir); err != nil {
		log.Fatalf("Load Start Sensors failed: %v", err)
	}

	if err := obs.Start(ctx); err != nil {
		logger.GetLogger().Fatalf("Starting FGS failed: %v", err)
	}

	<-ctx.Done()
	obs.RemovePrograms()
}

func raceTCPLoad(ctx context.Context) {
	l, err := net.Listen("tcp4", "127.0.0.1:12345")
	if err != nil {
		panic(err)
	}

	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				break
			}
			buf := make([]byte, 100)
			c.Read(buf)
			c.Write(buf)
			c.Close()
		}
	}()

	for ctx.Err() == nil {
		// TODO(JM): execute a loop within docker?
		cmd := exec.Command("/usr/bin/docker", "run", "-i", "--rm", "--network=host", "subfuzion/netcat", "127.0.0.1", "12345")
		cmd.Stderr = os.Stderr
		cmd.Stdout = io.Discard
		p, _ := cmd.StdinPipe()
		p.Write([]byte("hello"))
		p.Close()
		cmd.Start()
		time.Sleep(50 * time.Millisecond)
		cmd.Wait()
	}
	l.Close()
}

func raceUDPLoad(ctx context.Context) {
	laddr, _ := net.ResolveUDPAddr("udp4", "127.0.0.1:0")
	l, err := net.ListenUDP("udp4", laddr)
	if err != nil {
		panic(err)
	}
	go func() {
		for {
			buf := make([]byte, 100)
			_, from, err := l.ReadFrom(buf)
			if err != nil {
				break
			}
			l.WriteTo(buf, from)
		}
	}()

	for ctx.Err() == nil {
		buf := make([]byte, 100)
		raddr, _ := net.ResolveUDPAddr("udp4", l.LocalAddr().String())
		c, err := net.DialUDP("udp4", nil, raddr)
		if err != nil {
			panic(err)
		}
		_, err = c.Write([]byte("hello"))
		if err != nil {
			panic(err)
		}
		_, err = c.Read(buf)
		if err != nil {
			panic(err)
		}
		c.Close()
		time.Sleep(10 * time.Millisecond)
	}
	l.Close()
}

func RunRace() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	go sigHandler(ctx, cancel)

	var wg sync.WaitGroup

	ready := make(chan bool)
	wg.Add(1)
	go func() {
		runRaceFGS(ctx, ready)
		wg.Done()
	}()
	<-ready

	wg.Add(1)
	go func() {
		raceTCPLoad(ctx)
		wg.Done()
	}()

	wg.Add(1)
	go func() {
		raceUDPLoad(ctx)
		wg.Done()
	}()

	wg.Wait()
}

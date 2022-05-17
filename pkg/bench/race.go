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
	"io"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"path"
	"sync"
	"time"

	"github.com/cilium/tetragon/pkg/cilium"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/isovalent/hubble-fgs/api/v1/fgs"
	"github.com/isovalent/hubble-fgs/pkg/api/readyapi"
	"github.com/isovalent/hubble-fgs/pkg/bpf"
	"github.com/isovalent/hubble-fgs/pkg/btf"
	"github.com/isovalent/hubble-fgs/pkg/exporter"
	fgsGrpc "github.com/isovalent/hubble-fgs/pkg/grpc"
	"github.com/isovalent/hubble-fgs/pkg/observer"
	"github.com/isovalent/hubble-fgs/pkg/process"
	"google.golang.org/protobuf/proto"

	hubblev1 "github.com/cilium/hubble/pkg/api/v1"
	corev1 "k8s.io/api/core/v1"

	// Imported to allow sensors to be initialized inside init().
	_ "github.com/isovalent/hubble-fgs/pkg/sensors"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/exec"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/sockmap"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/tcp"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/udp"
)

//
// Race detection for hubble-fgs. This is similar to the fgs-bench in that we're
// running hubble-fgs along with some load, but here the goal is to generate lots
// of different types of events to exercise many different parts of hubble-fgs to
// catch race conditions using the Go race detector ("-race").
//

type raceListener struct {
	ready chan bool
}

func (l *raceListener) Notify(msg interface{}) error {
	switch msg.(type) {
	case *readyapi.MsgFGSReady:
		l.ready <- true
	}
	return nil
}

func (l *raceListener) Close() error {
	return nil
}

type raceK8sWatcher struct {
}

func (r *raceK8sWatcher) FindPod(containerID string) (*corev1.Pod, *corev1.ContainerStatus, bool) {
	if containerID == "" {
		return nil, nil, false
	}
	// Return a fake pod, some of the time to simulate the propagation delay.
	if rand.Int31()%3 == 0 {
		return &corev1.Pod{}, &corev1.ContainerStatus{Image: "fake"}, true
	}
	return nil, nil, false
}

func (r *raceK8sWatcher) GetPodInfo(containerID, binary, args string, nspid uint32) (*fgs.Pod, *hubblev1.Endpoint) {
	return nil, nil
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
	event := v.(*fgs.GetEventsResponse)
	buf, err := proto.Marshal(event)
	if err != nil {
		panic(err)
	}
	var event2 fgs.GetEventsResponse
	err = proto.Unmarshal(buf, &event2)
	if err != nil {
		panic(err)
	}

	return re.enc.Encode(v)
}

func startRaceExporter(ctx context.Context, obs *observer.Observer) error {
	processCacheSize := 32768
	enableProcessCred := false
	enableProcessNs := false
	enableCiliumAPI := false
	enableEventCache := true
	enableProcessAncestors := false

	if _, err := cilium.InitCiliumState(ctx, enableCiliumAPI); err != nil {
		return err
	}
	if err := process.InitCache(ctx, &raceK8sWatcher{}, enableCiliumAPI, processCacheSize); err != nil {
		return err
	}

	processManager, err := fgsGrpc.NewProcessManager(
		cilium.GetFakeCiliumState(),
		observer.SensorManager,
		enableProcessCred,
		enableProcessNs,
		enableEventCache,
		enableCiliumAPI,
		enableProcessAncestors,
	)
	if err != nil {
		return err
	}

	encoder := &raceEncoder{0, json.NewEncoder(io.Discard)}
	//encoder := &raceEncoder{0, json.NewEncoder(os.Stdout)}

	req := fgs.GetEventsRequest{AllowList: nil, DenyList: nil, AggregationOptions: nil}
	exporter := exporter.NewExporter(ctx, &req, processManager.Server, encoder, nil)
	exporter.Start()
	obs.AddListener(processManager)
	return nil
}

var config = `
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

func runRaceFGS(ctx context.Context, ready chan bool) {
	bpf.ConfigureResourceLimits()
	bpf.CheckOrMountFS("")
	bpf.CheckOrMountDebugFS()
	bpf.CheckOrMountCgroup2()
	bpf.SetMapPrefix("fgs-race")

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
	f.Write([]byte(config))
	f.Close()

	obs := observer.NewObserver(
		"/sys/fs/bpf/fgs-race/", "/sys/fs/bpf/fgs-race/", "",
		"",       /* network interfaces */
		f.Name(), /* config */
		10 /* tcp statistics */)

	if err := obs.InitSensorManager(); err != nil {
		logger.GetLogger().Fatalf("InitSensorManager failed: %v", err)
	}

	if err := btf.InitCachedBTF(ctx, option.Config.HubbleLib, ""); err != nil {
		logger.GetLogger().Fatal(err)
	}

	rl := &raceListener{ready}
	obs.AddListener(rl)

	if err := startRaceExporter(ctx, obs); err != nil {
		logger.GetLogger().Fatal(err)
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

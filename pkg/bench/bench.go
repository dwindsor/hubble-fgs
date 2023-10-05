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
	"fmt"
	"log"
	"os"
	"os/signal"
	"path"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"text/template"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/api/readyapi"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/btf"
	"github.com/cilium/tetragon/pkg/cilium"
	"github.com/cilium/tetragon/pkg/exporter"
	fgsGrpc "github.com/cilium/tetragon/pkg/grpc"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/process"
	"github.com/cilium/tetragon/pkg/reader/notify"
	"github.com/cilium/tetragon/pkg/rthooks"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
	"github.com/cilium/tetragon/pkg/watcher"

	"github.com/isovalent/hubble-fgs/pkg/grpc/exec"
	"github.com/isovalent/hubble-fgs/pkg/grpc/httpproto"
	"github.com/isovalent/hubble-fgs/pkg/grpc/layer3"
	"github.com/isovalent/hubble-fgs/pkg/grpc/tls"

	// Imported to allow sensors to be initialized inside init().
	_ "github.com/cilium/tetragon/pkg/sensors"
	"github.com/isovalent/hubble-fgs/pkg/sensors/base"

	// Iinit sensors for benchmarking
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/exec"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/network"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/sockmap"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/tcp"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/udp"
)

var (
	// NB: we use a global runner for now. A better solution would be to
	// have a way to reset the global variable of pkg/rthooks, but this
	// requires OSS changes.
	glblHookRunner = rthooks.GlobalRunner()
)

type Arguments struct {
	TestName           string
	Fgs                bool
	FgsEnableTLS       bool
	FgsEnableHTTP      bool
	FgsEnableTCP       bool
	FgsEnableUDP       bool
	FgsEnableInterface bool
	FgsEnableHistogram bool
	FgsDebug           bool
	FgsJSONEncode      bool
	PrintEvents        bool
	Netns              bool
	FgsEnableBpfStats  bool

	SourceArgs SourceArgs
	Source     SourceName
	Sink       SinkName
	Proxy      ProxyName

	Baseline bool
}

func (args *Arguments) String() string {
	return fmt.Sprintf("sink=%s, source=%s, proxy=%s, source-args={%s}, fgs-tls=%v, json-encode=%v",
		args.Sink, args.Source, args.Proxy, args.SourceArgs.String(), args.FgsEnableTLS, args.FgsJSONEncode)
}

func runFgs(ctx context.Context, sinkPort int, args *Arguments, summary *Summary, ready chan bool) {
	bpf.ConfigureResourceLimits()
	bpf.CheckOrMountFS("")
	bpf.CheckOrMountDebugFS()
	bpf.CheckOrMountCgroup2()

	if args.FgsDebug {
		option.Config.Verbosity = 5
	}

	if _, err := os.Stat("../../bpf/objs"); err == nil {
		option.Config.HubbleLib = "../../bpf/objs"
	} else {
		exePath, err := os.Executable()
		if err != nil {
			log.Fatal(err)
		}
		option.Config.HubbleLib = path.Join(path.Dir(exePath), "bpf/objs")

		if _, err := os.Stat(option.Config.HubbleLib); err != nil {
			// Running outside the source tree, fall back to default location.
			option.Config.HubbleLib = "/var/lib/hubble-fgs"
		}
	}

	configFile := generateCrd(args, sinkPort)
	defer os.Remove(configFile)

	option.Config.BpfDir = bpf.MapPrefixPath()
	option.Config.MapDir = bpf.MapPrefixPath()
	obs := observer.NewObserver(configFile)

	if err := obs.InitSensorManager(nil); err != nil {
		logger.GetLogger().Fatalf("InitSensorManager failed: %v", err)
	}

	if err := btf.InitCachedBTF(option.Config.HubbleLib, ""); err != nil {
		log.Fatal(err)
	}

	listener := &benchmarkListener{
		summary:  summary,
		ctx:      ctx,
		observer: obs,
		ready:    ready,
	}
	obs.AddListener(listener)

	if args.FgsJSONEncode {
		if err := startBenchmarkExporter(ctx, obs, summary); err != nil {
			log.Fatalf("Starting exporter failed: %v", err)
		}
	} else {
		dataCacheSize := 1024

		if err := observer.InitDataCache(dataCacheSize); err != nil {
			log.Fatalf("InitDataCache failed: %v", err)
		}
	}

	tp, err := tracingpolicy.FromFile(configFile)
	if err != nil {
		log.Fatalf("readConfig error: %v", err)
	}
	startSensors, err := sensors.GetMergedSensorFromParserPolicy(tp)
	if err != nil {
		log.Fatalf("GetSensorsFromParserPolicy error: %v", err)
	}

	if err := base.LoadDefault(
		option.Config.BpfDir,
		option.Config.MapDir); err != nil {
		log.Fatalf("Load Defaults failed: %v", err)
	}

	if err := startSensors.Load(
		option.Config.BpfDir,
		option.Config.MapDir); err != nil {
		log.Fatalf("Load Start Sensors failed: %v", err)
	}

	if err := obs.Start(ctx); err != nil {
		log.Fatalf("Starting FGS failed: %v", err)
	}

	<-ctx.Done()
	obs.RemovePrograms()
}

type benchmarkListener struct {
	summary  *Summary
	ready    chan bool
	ctx      context.Context
	observer *observer.Observer
}

func (bl *benchmarkListener) Notify(msg notify.Message) error {
	switch msg.(type) {
	case *readyapi.MsgTetragonReady:
		bl.ready <- true

	case *tls.MsgTLSEventUnix:
		bl.summary.TLSEvents++

	case *exec.MsgExitEventUnix:
		bl.summary.ExitEvents++

	case *exec.MsgExecveEventUnix:
		bl.summary.ExecEvents++

	case *layer3.MsgIPEventUnix:
		bl.summary.TCPEvents++

	case *httpproto.MsgHttpEventUnix:
		bl.summary.HTTPEvents++
	}

	return nil
}

func (bl *benchmarkListener) Close() error {
	return nil
}

type timingEncoder struct {
	totalDuration uint64
	inner         exporter.ExportEncoder
}

func (te *timingEncoder) Encode(v interface{}) error {
	t0 := time.Now()
	err := te.inner.Encode(v)
	atomic.AddUint64(&te.totalDuration, uint64(time.Since(t0)))
	return err
}

func startBenchmarkExporter(ctx context.Context, obs *observer.Observer, summary *Summary) error {
	var wg sync.WaitGroup

	processCacheSize := 32768
	dataCacheSize := 1024
	option.Config.EnableProcessCred = false
	option.Config.EnableProcessNs = false
	option.Config.EnableCilium = false
	option.Config.EnableK8s = false
	//todo; enableProcessAncestors := true

	if _, err := cilium.InitCiliumState(ctx, option.Config.EnableCilium); err != nil {
		return err
	}

	fakeWatcher := watcher.NewFakeK8sWatcher(nil)
	if err := process.InitCache(fakeWatcher, processCacheSize); err != nil {
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

	var encoder exporter.ExportEncoder
	if summary.Args.PrintEvents {
		encoder = json.NewEncoder(os.Stdout)
	} else {
		encoder = json.NewEncoder(&CountingDiscardWriter{})
	}

	timingEncoder := timingEncoder{inner: encoder}
	go func() {
		// FIXME I'm racy, someone might read summary before this is written.
		// Likely not an issue since we wait for slower things to exit.
		<-ctx.Done()
		summary.JSONEncodingDurationNanos = time.Duration(timingEncoder.totalDuration)
	}()

	req := tetragon.GetEventsRequest{AllowList: nil, DenyList: nil, AggregationOptions: nil}
	exporter := exporter.NewExporter(ctx, &req, processManager.Server, &timingEncoder, nil, nil)
	exporter.Start()
	obs.AddListener(processManager)
	return nil
}

func RunBenchmark(args *Arguments) (summary *Summary) {
	var oldBpfStats map[int64]*BpfProgStats

	ctx, cancel := context.WithCancel(context.Background())
	go sigHandler(ctx, cancel)

	summary = newSummary(args)
	summary.StartTime = time.Now()

	// NOTE(JM): Currently the HTTP parser also requires the TLS parser to be loaded.
	args.FgsEnableTLS = args.FgsEnableTLS || args.FgsEnableHTTP
	args.FgsEnableTCP = args.FgsEnableTLS || args.FgsEnableHTTP || args.FgsEnableTCP

	if args.FgsEnableBpfStats {
		EnableBpfStats()
		oldBpfStats = GetBpfStats()
	}

	if args.Netns {
		if err := CreateVeth(); err != nil {
			summary.Error = fmt.Sprintf("CreateInterface failed: %s", err)
			cancel()
			return
		}
		args.SourceArgs.NetNs = true
		args.SourceArgs.DestinationIP = "15.0.0.2"
	} else {
		args.SourceArgs.NetNs = false
		args.SourceArgs.DestinationIP = "127.0.0.1"
	}

	// Start the sink.
	log.Printf("Starting sink %t '%s'...\n", args.Netns, args.Sink)
	sinkPort, sinkStats, err := sinks[args.Sink].Start(ctx, args.Netns)
	if err != nil {
		summary.Error = fmt.Sprintf("Sink %s failed: %s", args.Sink, err)
		cancel()
		return
	}

	// Start FGS if requested.
	fgsFinished := make(chan bool, 1)
	if !args.Baseline {
		ready := make(chan bool)
		log.Printf("Starting FGS...\n")
		go func() {
			runFgs(ctx, sinkPort, args, summary, ready)
			fgsFinished <- true
		}()
		// Wait for FGS to initialize.
		<-ready
	} else {
		fgsFinished <- true
	}
	summary.SetupDurationNanos = time.Since(summary.StartTime)

	// Start an optional proxy between the sink and source. If no proxy required it
	// passes the sink port through.
	log.Printf("Starting proxy '%s'...\n", args.Proxy)
	targetPort, proxyStats, err := proxies[args.Proxy].Start(ctx, sinkPort)
	if err != nil {
		summary.Error = fmt.Sprintf("Proxy %s failed: %s", args.Proxy, err)
		cancel()
		return
	}

	// Run the source and wait for it to terminate
	cpuUsageBefore := GetCPUUsage(CPU_USAGE_ALL_THREADS)
	log.Printf("Starting source '%s'...\n", args.Source)
	sourceStats, err := sources[args.Source].Run(ctx, targetPort, args.SourceArgs)
	if err != nil {
		summary.Error = fmt.Sprintf("Source %s failed: %s", args.Source, err)
		cancel()
		return
	}
	// TODO(JM): Slightly inaccurate as the source may terminate before FGS has processed all events
	cpuUsageAfter := GetCPUUsage(CPU_USAGE_ALL_THREADS)

	summary.SourceStats = sourceStats
	if args.FgsEnableBpfStats {
		summary.BpfStats = GetBpfStatsSince(oldBpfStats)
	}
	summary.EndTime = time.Now()
	summary.TestDurationNanos = summary.EndTime.Sub(summary.StartTime)

	// Now that the source finished, cancel the context to stop everything and collect stats.
	cancel()
	if proxyStats != nil {
		summary.ProxyStats = <-proxyStats
	}
	summary.SinkStats = <-sinkStats

	// Wait for FGS to finish cleaning up.
	<-fgsFinished

	if !args.Baseline {
		summary.FgsCPUUsage = cpuUsageAfter.Sub(cpuUsageBefore)
		if !summary.SinkStats.Forked {
			summary.FgsCPUUsage = summary.FgsCPUUsage.Sub(summary.SinkStats.CPUUsage)
		}
		if !summary.SourceStats.Forked {
			summary.FgsCPUUsage = summary.FgsCPUUsage.Sub(summary.SourceStats.CPUUsage)
		}

		// Roughly validate the event counters
		if summary.Error == "" {
			if args.FgsEnableTLS && strings.Contains(string(args.Source), "tls") {
				if summary.TLSEvents < 1 {
					summary.Error += "No TLS events received! "
				}
			}

			if args.FgsEnableHTTP && strings.Contains(string(args.Source), "http") {
				if summary.HTTPEvents < 1 {
					summary.Error += "No HTTP events received! "
				}
			}

			if summary.TCPEvents < 1 {
				summary.Error += "No TCP events received! "
			}
		}
	}

	log.Printf("Benchmark finished: %.2f per sec, %d error(s)", sourceStats.ActualRate, sourceStats.Errors)
	return
}

func sigHandler(ctx context.Context, cancel context.CancelFunc) {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	select {
	case <-ctx.Done():
		close(sigs)
		return
	case sig := <-sigs:
		log.Printf("Signal '%s' received, stopping...\n", sig)
		cancel()
		return
	}
}

func generateCrd(args *Arguments, sinkPort int) string {
	tmpl := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "benchmark-spec"
spec:
  parser:
    http:
      enable: {{.FgsHttp}}
      selectors:
      - matchPorts:
        - 80
        {{.MatchPortHTTP}}
    tls:
      enable: {{.FgsTls}}
      mode: socket
      selectors:
      - matchPorts:
        - 443
        {{.MatchPortTLS}}
    tcp:
      enable: {{.FgsTcp}}
      histogram:
        enable: {{.FgsHistograms}}
        min: 0
        max: 100000
    udp:
      enable: {{.FgsUdp}}
`

	f, err := os.CreateTemp("/tmp", "fgs-bench-crd-*.yaml")
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	var matchPortHTTP, matchPortTLS string

	if strings.Contains(string(args.Source), "tls") {
		matchPortTLS = fmt.Sprintf("- %d", sinkPort)
	}
	if strings.Contains(string(args.Source), "http") {
		matchPortHTTP = fmt.Sprintf("- %d", sinkPort)
	}

	templateArgs :=
		struct {
			FgsHttp, FgsTls             bool
			FgsTcp, FgsUdp              bool
			FgsInterface                bool
			FgsHistograms               bool
			MatchPortHTTP, MatchPortTLS string
		}{
			FgsHttp:       args.FgsEnableHTTP,
			FgsTls:        args.FgsEnableTLS,
			FgsTcp:        args.FgsEnableTCP,
			FgsUdp:        args.FgsEnableUDP,
			FgsInterface:  args.FgsEnableInterface,
			FgsHistograms: args.FgsEnableHistogram,
			MatchPortHTTP: matchPortHTTP,
			MatchPortTLS:  matchPortTLS,
		}

	err = template.Must(template.New("crd").Parse(tmpl)).Execute(f, templateArgs)
	if err != nil {
		log.Fatal(err)

	}
	return f.Name()
}

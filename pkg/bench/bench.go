//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

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
	"sync/atomic"
	"syscall"
	"text/template"
	"time"

	"github.com/isovalent/hubble-fgs/api/v1/fgs"
	"github.com/isovalent/hubble-fgs/pkg/api"
	"github.com/isovalent/hubble-fgs/pkg/bpf"
	"github.com/isovalent/hubble-fgs/pkg/btf"
	"github.com/isovalent/hubble-fgs/pkg/cilium"
	fgsGrpc "github.com/isovalent/hubble-fgs/pkg/grpc"
	"github.com/isovalent/hubble-fgs/pkg/logger"
	"github.com/isovalent/hubble-fgs/pkg/observer"
	"github.com/isovalent/hubble-fgs/pkg/option"

	// Imported to allow sensors to be initialized inside init().
	_ "github.com/isovalent/hubble-fgs/pkg/sensors"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/sockmap"
)

type BenchArguments struct {
	TestName      string
	Fgs           bool
	FgsEnableTLS  bool
	FgsEnableHTTP bool
	FgsDebug      bool
	FgsJSONEncode bool
	PrintEvents   bool

	SourceArgs SourceArgs
	Source     sourceName
	Sink       sinkName
	Proxy      proxyName

	Baseline bool
}

func (args *BenchArguments) String() string {
	return fmt.Sprintf("sink=%s, source=%s, proxy=%s, source-args={%s}, fgs-tls=%v, json-encode=%v",
		args.Sink, args.Source, args.Proxy, args.SourceArgs.String(), args.FgsEnableTLS, args.FgsJSONEncode)
}

func runFgs(sinkPort int, args *BenchArguments, summary *BenchSummary, ctx context.Context, ready chan bool) {
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

	obs := observer.NewObserver(
		"/sys/fs/bpf/tcpmon/", "/sys/fs/bpf/tcpmon/", "",
		"", /* network interfaces */
		configFile,
		args.FgsDebug /* debug */, false, /* enable-crd */
		0 /* tcp statistics */)

	if err := btf.InitCachedBTF(option.Config.HubbleLib, "", ctx); err != nil {
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
		err := startBenchmarkExporter(ctx, obs, summary)
		if err != nil {
			log.Fatalf("Starting exporter failed: %v", err)
		}
	}

	if err := obs.Start(ctx); err != nil {
		log.Fatalf("Starting FGS failed: %v", err)
	}

	<-ctx.Done()
	obs.RemovePrograms()
}

type benchmarkListener struct {
	summary  *BenchSummary
	ready    chan bool
	ctx      context.Context
	observer *observer.Observer
}

func (bl *benchmarkListener) Notify(msg interface{}) error {
	switch msg.(type) {
	case *api.MsgFGSReady:
		bl.ready <- true

	case *api.MsgTLSEventUnix:
		bl.summary.TLSEvents++

	case *api.MsgExitEventUnix:
		bl.summary.ExitEvents++

	case *api.MsgExecveEventUnix:
		bl.summary.ExecEvents++

	case *api.MsgIPv4EventUnix:
		bl.summary.TCPEvents++

	case *api.MsgHttpEventUnix:
		bl.summary.HTTPEvents++
	}

	return nil
}

func (bl *benchmarkListener) Close() error {
	return nil
}

type timingEncoder struct {
	totalDuration uint64
	inner         fgsGrpc.ExportEncoder
}

func (te *timingEncoder) Encode(v interface{}) error {
	t0 := time.Now()
	err := te.inner.Encode(v)
	atomic.AddUint64(&te.totalDuration, uint64(time.Since(t0)))
	return err
}

func startBenchmarkExporter(ctx context.Context, obs *observer.Observer, summary *BenchSummary) error {
	processCacheSize := 32768
	enableProcessCred := false
	enableCiliumAPI := false
	enableEventCache := false

	processManager, err := fgsGrpc.NewProcessManager(
		logger.GetLogger(),
		processCacheSize,
		fgsGrpc.NewFakeK8sWatcher(nil),
		cilium.GetFakeCiliumState(),
		enableProcessCred,
		enableEventCache,
		enableCiliumAPI,
	)
	if err != nil {
		return err
	}
	server := fgsGrpc.NewServer(processManager, obs.SensorManager)

	var encoder fgsGrpc.ExportEncoder
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

	req := fgs.GetEventsRequest{AllowList: nil, DenyList: nil, AggregationOptions: nil}
	exporter := fgsGrpc.NewExporter(ctx, &req, server, &timingEncoder, nil)
	go exporter.Start()
	obs.AddListener(processManager)
	return nil
}

func RunBenchmark(args *BenchArguments) (summary *BenchSummary) {
	ctx, cancel := context.WithCancel(context.Background())
	go sigHandler(ctx, cancel)

	summary = newBenchSummary(args)
	summary.StartTime = time.Now()

	// NOTE(JM): Currently the HTTP parser also requires the TLS parser to be loaded.
	args.FgsEnableTLS = args.FgsEnableTLS || args.FgsEnableHTTP

	EnableBpfStats()
	oldBpfStats := GetBpfStats()

	// Start the sink.
	log.Printf("Starting sink '%s'...\n", args.Sink)
	sinkPort, sinkStats, err := sinks[args.Sink].Start(ctx)
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
			runFgs(sinkPort, args, summary, ctx, ready)
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
	summary.BpfStats = GetBpfStatsSince(oldBpfStats)
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

func generateCrd(args *BenchArguments, sinkPort int) string {
	tmpl := `
apiVersion: hubble-enterprise.io/v1
metadata:
  name: "benchmark spec"
spec:
  description: "parser spec"
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
			MatchPortHTTP, MatchPortTLS string
		}{
			FgsHttp:       args.FgsEnableHTTP,
			FgsTls:        args.FgsEnableTLS,
			MatchPortHTTP: matchPortHTTP,
			MatchPortTLS:  matchPortTLS,
		}

	err = template.Must(template.New("crd").Parse(tmpl)).Execute(f, templateArgs)
	if err != nil {
		log.Fatal(err)

	}
	return f.Name()
}

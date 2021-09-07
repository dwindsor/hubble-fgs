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
	"path"
	"strings"
	"syscall"
	"text/template"

	"log"
	"os"
	"os/signal"
	"time"

	"github.com/isovalent/hubble-fgs/pkg/api"
	"github.com/isovalent/hubble-fgs/pkg/bpf"
	"github.com/isovalent/hubble-fgs/pkg/btf"
	"github.com/isovalent/hubble-fgs/pkg/observer"
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

func RunBenchmark(args *BenchArguments) *BenchSummary {
	// NOTE(JM): Currently the HTTP parser also requires the TLS parser to be loaded.
	args.FgsEnableTLS = args.FgsEnableTLS || args.FgsEnableHTTP
	
	summary := newBenchSummary(args)
	summary.StartTime = time.Now()
	ctx, cancel := context.WithCancel(context.Background())
	go sigHandler(ctx, cancel)

	cpuUsageBefore := GetCPUUsage(CPU_USAGE_ALL_THREADS)
	runBenchmark(ctx, cancel, args, summary)
	cpuUsageAfter := GetCPUUsage(CPU_USAGE_ALL_THREADS)

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

			/* TODO(JM): Disabled due to HTTP parser broken on localhost connections.
			 * (skb non-linear and data not pulled)

			if args.FgsEnableHTTP && strings.Contains(string(args.Source), "http") {
				if summary.HTTPEvents < 1 {
					summary.Error += "No HTTP events received! "
				}
			}
			*/

			if summary.TCPEvents < 1 {
				summary.Error += "No TCP events received! "
			}
		}
	}

	return summary
}

func runFgs(sinkPort int, args *BenchArguments, summary *BenchSummary, ctx context.Context, ready chan bool) {
	bpf.ConfigureResourceLimits()
	bpf.CheckOrMountFS("")
	bpf.CheckOrMountDebugFS()
	bpf.CheckOrMountCgroup2()

	if _, err := os.Stat("../../bpf/objs"); err == nil {
		observer.HubbleLib = "../../bpf/objs"
	} else {
		exePath, err := os.Executable()
		if err != nil {
			log.Fatal(err)
		}
		observer.HubbleLib = path.Join(path.Dir(exePath), "bpf/objs")

		if _, err := os.Stat(observer.HubbleLib); err != nil {
			// Running outside the source tree, fall back to default location.
			observer.HubbleLib = "/var/lib/hubble-fgs"
		}
	}

	configFile := generateCrd(args, sinkPort)
	defer os.Remove(configFile)

	kprobe := observer.NewObserverKprobe("/sys/fs/bpf/tcpmon/", "/sys/fs/bpf/tcpmon/", "",
		"", /* network interfaces */
		configFile,
		args.FgsDebug /* debug */, false, /* enable-crd */
		0 /* tcp statistics */)

	if err := btf.InitCachedBTF(observer.HubbleLib, ctx); err != nil {
		log.Fatal(err)
	}

	err := startBenchmarkListener(summary, ready, kprobe, ctx)
	if err != nil {
		log.Fatalf("Starting FGS failed: %v", err)
	}

	<-ctx.Done()
	kprobe.RemovePrograms()
}

type benchmarkListener struct {
	summary *BenchSummary
	ready   chan bool
	ctx     context.Context
	kprobe  *observer.ObserverKprobe
	encoder *json.Encoder

	cpuUsageWhenReady CPUUsage
}

func (bl *benchmarkListener) Notify(msg interface{}) error {
	if bl.summary.Args.FgsJSONEncode {
		t0 := time.Now()
		err := bl.encoder.Encode(msg)
		bl.summary.JSONEncodingDurationNanos += time.Since(t0)
		if err != nil {
			log.Printf("JSON encoding error: %v", err)
		}
	}

	switch msg.(type) {
	case *api.MsgFGSReady:
		bl.cpuUsageWhenReady = GetCPUUsage(CPU_USAGE_THIS_THREAD)
		bl.ready <- true

	case *api.MsgTLSEventUnix:
		bl.summary.TLSEvents++

	case *api.MsgExitEventUnix:
		bl.summary.ExitEvents++

	case *api.MsgExecveEventUnix:
		bl.summary.ExecEvents++

	case *api.MsgIPv4TcpEventUnix:
		bl.summary.TCPEvents++

	case *api.MsgHttpEventUnix:
		bl.summary.HTTPEvents++
	}

	return nil
}

func (bl *benchmarkListener) Close() error {
	return nil
}

func startBenchmarkListener(summary *BenchSummary, ready chan bool,
	kprobe *observer.ObserverKprobe,
	ctx context.Context) error {

	var encoder *json.Encoder
	if summary.Args.PrintEvents {
		encoder = json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "\t")
	} else {
		encoder = json.NewEncoder(&CountingDiscardWriter{})
	}

	listener := &benchmarkListener{
		summary: summary,
		ctx:     ctx,
		kprobe:  kprobe,
		ready:   ready,
		encoder: encoder,
	}
	kprobe.AddListener(listener)
	return kprobe.Start(ctx)
}

func runBenchmark(ctx context.Context, cancel context.CancelFunc, args *BenchArguments, summary *BenchSummary) {
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
		return
	}

	// Run the source and wait for it to terminate
	log.Printf("Starting source '%s'...\n", args.Source)
	sourceStats, err := sources[args.Source].Run(ctx, targetPort, args.SourceArgs)
	if err != nil {
		summary.Error = fmt.Sprintf("Source %s failed: %s", args.Source, err)
		cancel()
		return
	}

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

	log.Printf("Benchmark finished: %.2f per sec, %d error(s)", sourceStats.ActualRate, sourceStats.Errors)
}

func sigHandler(ctx context.Context, cancel context.CancelFunc) {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	select {
	case <-ctx.Done():
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
      - matchports:
        - 80
        {{.MatchPortHTTP}}
    tls:
      enable: {{.FgsTls}}
      mode: socket
      selectors:
      - matchports:
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
			FgsHttp, FgsTls           bool
			MatchPortHTTP, MatchPortTLS string
		}{
			FgsHttp:      args.FgsEnableHTTP,
			FgsTls:       args.FgsEnableTLS,
			MatchPortHTTP: matchPortHTTP,
			MatchPortTLS:  matchPortTLS,
		}

	err = template.Must(template.New("crd").Parse(tmpl)).Execute(f, templateArgs)
	if err != nil {
		log.Fatal(err)

	}
	return f.Name()
}

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
	"syscall"

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
	FgsEnableTLS  bool
	FgsDebug      bool
	FgsJSONEncode bool

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

func BenchBaseline(args *BenchArguments) *BenchSummary {
	summary := newBenchSummary(args)
	summary.StartTime = time.Now()
	ctx, cancel := context.WithCancel(context.Background())
	go sigHandler(ctx, cancel)

	runConnectionLoad(ctx, cancel, args, summary)
	return summary
}

func BenchFGS(args *BenchArguments, readyCb func()) *BenchSummary {
	summary := newBenchSummary(args)
	ready := make(chan bool)
	finished := make(chan bool)
	ctx, cancel := context.WithCancel(context.Background())
	go sigHandler(ctx, cancel)
	go func() {
		<-ready
		readyCb()
		summary.SetupDurationNanos = time.Since(summary.StartTime)
		runFgsBenchmark(args, summary, ctx, cancel)
		finished <- true
	}()

	runFgs(args.FgsEnableTLS, args.FgsDebug, summary, ctx, cancel, ready)

	// Wait for final summary
	<-finished

	return summary
}

func runFgs(fgsEnableTLS, fgsDebug bool, summary *BenchSummary, ctx context.Context, cancel context.CancelFunc, ready chan bool) {
	bpf.ConfigureResourceLimits()
	bpf.CheckOrMountFS("")
	bpf.CheckOrMountDebugFS()
	if fgsEnableTLS {
		bpf.CheckOrMountCgroup2()
	}

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

	kprobe := observer.NewObserverKprobe("/sys/fs/bpf/tcpmon/", "/sys/fs/bpf/tcpmon/", "",
		"" /* network interfaces */, "", /* config file */
		fgsEnableTLS /* tls */, false, /* tlstc */
		fgsDebug /* debug */, false, /* enable-crd */
		0 /* tcp statistics */)

	defer kprobe.RemovePrograms()

	if err := btf.InitCachedBTF(observer.HubbleLib, ctx); err != nil {
		log.Fatal(err)
	}

	err := startBenchmarkListener(summary, ready, kprobe, ctx, cancel)
	if err != nil {
		log.Fatalf("Starting FGS failed: %v", err)
	}

	<-ctx.Done()
}

type benchmarkListener struct {
	summary *BenchSummary
	ready   chan bool
	ctx     context.Context
	cancel  context.CancelFunc
	kprobe  *observer.ObserverKprobe
	encoder *json.Encoder
	writer  CountingDiscardWriter

	cpuUsageWhenReady CPUUsage
}

func runFgsBenchmark(args *BenchArguments, summary *BenchSummary, ctx context.Context, cancel context.CancelFunc) {
	cpuUsageBefore := GetCPUUsage(CPU_USAGE_ALL_THREADS)
	runConnectionLoad(ctx, cancel, args, summary)
	cpuUsageAfter := GetCPUUsage(CPU_USAGE_ALL_THREADS)
	summary.FgsCPUUsage = cpuUsageAfter.Sub(cpuUsageBefore)
	if !summary.SinkStats.Forked {
		summary.FgsCPUUsage = summary.FgsCPUUsage.Sub(summary.SinkStats.CPUUsage)
	}
	if !summary.SourceStats.Forked {
		summary.FgsCPUUsage = summary.FgsCPUUsage.Sub(summary.SourceStats.CPUUsage)
	}
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
	}

	return nil
}

func (bl *benchmarkListener) Close() error {
	return nil
}

func startBenchmarkListener(summary *BenchSummary, ready chan bool,
	kprobe *observer.ObserverKprobe,
	ctx context.Context, cancel context.CancelFunc) error {
	listener := &benchmarkListener{
		summary: summary,
		ctx:     ctx,
		cancel:  cancel,
		kprobe:  kprobe,
		ready:   ready,
	}
	listener.encoder = json.NewEncoder(&listener.writer)
	kprobe.AddListener(listener)
	return kprobe.Start(ctx)
}

func runConnectionLoad(ctx context.Context, cancel context.CancelFunc, args *BenchArguments, summary *BenchSummary) {
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

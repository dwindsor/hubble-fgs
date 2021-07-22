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
	"runtime"
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

var (
	SupportedModes = []string{"tcp", "tls", "http"}
)

type BenchArguments struct {
	NumSteps      int
	ConnRate      int
	FgsEnableTls  bool
	FgsDebug      bool
	FgsJsonEncode bool
	Mode          string
	Baseline      bool

	RequestResponse bool
	UseNetperf      bool
	ReqSize         int
}

func (args *BenchArguments) String() string {
	return fmt.Sprintf("n=%d, rate=%d, tls=%v, debug=%v, json-encode=%v, mode=%s, rr=%v, netperf=%v, req-size=%v",
		args.NumSteps, args.ConnRate, args.FgsEnableTls,
		args.FgsDebug, args.FgsJsonEncode, args.Mode,
		args.RequestResponse, args.UseNetperf, args.ReqSize)
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

	runFgs(args.FgsEnableTls, args.FgsDebug, summary, ctx, cancel, ready)

	// Wait for final summary
	<-finished

	return summary
}

func runFgs(fgsEnableTls, fgsDebug bool, summary *BenchSummary, ctx context.Context, cancel context.CancelFunc, ready chan bool) {
	bpf.CheckOrMountFS("")
	bpf.CheckOrMountDebugFS()
	if fgsEnableTls {
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
		[]observer.GenericTracepointConf{},
		fgsEnableTls /* tls */, false, /* tlstc */
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

	cpuUsageWhenReady CpuUsage
}

func runFgsBenchmark(args *BenchArguments, summary *BenchSummary, ctx context.Context, cancel context.CancelFunc) {
	cpuUsageBefore := GetCpuUsage(CPU_USAGE_ALL_THREADS)
	runConnectionLoad(ctx, cancel, args, summary)
	cpuUsageAfter := GetCpuUsage(CPU_USAGE_ALL_THREADS)
	summary.FgsCpuUsage =
		cpuUsageAfter.Sub(cpuUsageBefore).Sub(summary.SinkCpuUsage).Sub(summary.SourceCpuUsage)
}

func (bl *benchmarkListener) Notify(msg interface{}) error {
	if bl.summary.Args.FgsJsonEncode {
		t0 := time.Now()
		err := bl.encoder.Encode(msg)
		bl.summary.JsonEncodingDurationNanos += time.Now().Sub(t0)

		if err != nil {
			log.Fatalf("json encode error: %v", err)
		}
	}

	switch msg.(type) {
	case *api.MsgFGSReady:
		bl.cpuUsageWhenReady = GetCpuUsage(CPU_USAGE_THIS_THREAD)
		bl.ready <- true

	case *api.MsgTLSEventUnix:
		bl.summary.TlsEvents++

	case *api.MsgExitEventUnix:
		bl.summary.ExitEvents++

	case *api.MsgExecveEventUnix:
		bl.summary.ExecEvents++

	case *api.MsgIPv4TcpEventUnix:
		bl.summary.TcpEvents++
	}

	return nil
}

func (cl *benchmarkListener) Close() error {
	return nil
}

func startBenchmarkListener(summary *BenchSummary, ready chan bool,
	kprobe *observer.ObserverKprobe,
	ctx context.Context, cancel context.CancelFunc) error {
	runtime.LockOSThread()
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

	sinkReady := make(chan int)
	sinkCpuUsage := make(chan CpuUsage)

	go func() {
		// Lock to specific thread to collect rusage
		runtime.LockOSThread()
		cpuUsageBefore := GetCpuUsage(CPU_USAGE_THIS_THREAD)
		if args.Mode == "tcp" && args.RequestResponse && args.UseNetperf {
			netperfSink(ctx, args.Mode, sinkReady)
		} else {
			sink(ctx, args.Mode, sinkReady)
		}
		sinkCpuUsage <- GetCpuUsage(CPU_USAGE_THIS_THREAD).Sub(cpuUsageBefore)
	}()

	// Lock to specific thread to collect rusage
	runtime.LockOSThread()
	sinkPort := <-sinkReady
	cpuUsageBefore := GetCpuUsage(CPU_USAGE_THIS_THREAD)

	if args.RequestResponse {
		if args.Mode == "tcp" && args.UseNetperf {
			summary.SourceStats = netperfSource(ctx, sinkPort, args.Mode, args.NumSteps, args.ReqSize)
		} else {
			summary.SourceStats = rrSource(ctx, sinkPort, args.Mode, args.NumSteps, args.ReqSize)
		}
	} else {
		summary.SourceStats = source(ctx, sinkPort, args.Mode, args.NumSteps, float64(args.ConnRate))
	}
	summary.SourceCpuUsage = GetCpuUsage(CPU_USAGE_THIS_THREAD).Sub(cpuUsageBefore)
	summary.BpfStats = GetBpfStatsSince(oldBpfStats)
	summary.EndTime = time.Now()
	summary.TestDurationNanos = summary.EndTime.Sub(summary.StartTime)

	// Cancel the context to stop FGS & sink
	cancel()
	summary.SinkCpuUsage = <-sinkCpuUsage
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

//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

// +build linux,bench_tests

package bench

import (
	"context"
	"flag"
	"os"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/spf13/viper"
)

func resultFilename(t *testing.T) string {
	file := strings.ReplaceAll(t.Name(), "/", "_") + ".json"
	return path.Join("..", "..", "results", file)
}

type sourceProxySink struct {
	source string
	proxy  string
	sink   string
}

var benchmarkSourceProxySinks = []sourceProxySink{
	{"http-rr-go", "none", "http-nginx"},
	{"http-crr-go", "none", "http-nginx"},
	{"netperf-crr", "none", "netperf"},
	{"netperf-rr", "none", "netperf"},
	{"tls-crr", "none", "tls-go"},
}

var benchmarkDuration = 5 * time.Second

func TestMain(m *testing.M) {
	flag.DurationVar(&benchmarkDuration, "fgs-bench-duration", benchmarkDuration, "Duration for the FGS benchmark tests")
	flag.Parse()
	os.Exit(m.Run())
}

// NOTE: These are not written as BenchmarkXxx as that tries to find an iteration count `b.N` that
// is stable (or fits within -benchtime). This doesn't make sense for fgs-bench since it already
// has a duration setting and the setup phase may be long to run over and over. Using "testing"
// is useful as it combines with the build and provides test filtering.

func TestBenchBaseline(t *testing.T) {
	for _, srcProxySink := range benchmarkSourceProxySinks {
		t.Run(srcProxySink.source, func(t *testing.T) {
			summary := BenchBaseline(
				&BenchArguments{
					SourceArgs: SourceArgs{Duration: benchmarkDuration},
					Source:     SourceNameOrPanic(srcProxySink.source),
					Proxy:      ProxyNameOrPanic(srcProxySink.proxy),
					Sink:       SinkNameOrPanic(srcProxySink.sink),
					Baseline:   true,
				})
			summary.TestName = t.Name()
			if err := summary.WriteFile(resultFilename(t)); err != nil {
				t.Fatalf("summary.WriteFile failed: %s", err)
			}
			if summary.Error != "" {
				t.Fatalf("test failed: %s", summary.Error)
			}
		})
	}
}

// A separate test to run a baseline HTTP load test with Envoy in between. Not
// in the "benchmarkSourceProxySinks" list as we don't need results with FGS and
// these are fairly large images to download for every PR.
func TestEnvoyOverhead(t *testing.T) {

	if testing.Short() {
		t.Skip("skipping envoy overhead test as running in short mode.")
	}

	source, proxy, sink := "http-rr-go", "envoy", "http-nginx"
	summary := BenchBaseline(
		&BenchArguments{
			SourceArgs: SourceArgs{Duration: benchmarkDuration},
			Source:     SourceNameOrPanic(source),
			Proxy:      ProxyNameOrPanic(proxy),
			Sink:       SinkNameOrPanic(sink),
			Baseline:   true,
		})
	summary.TestName = t.Name()
	if err := summary.WriteFile(resultFilename(t)); err != nil {
		t.Fatalf("summary.WriteFile failed: %s", err)
	}
	if summary.Error != "" {
		t.Fatalf("test failed: %s", summary.Error)
	}

}

func TestFGSNoTLS(t *testing.T) {
	benchmarkFgs(t, &BenchArguments{
		FgsEnableTLS:  false,
		FgsJSONEncode: true,
	})
}

func TestFGSTLS(t *testing.T) {
	benchmarkFgs(t, &BenchArguments{
		FgsEnableTLS:  true,
		FgsJSONEncode: true,
	})
}

func benchmarkFgs(t *testing.T, args *BenchArguments) {
	viper.Set("log-level", "error")
	viper.Set("debug", false)

	summary := newBenchSummary(args)

	fgsCtx, fgsCancel := context.WithCancel(context.Background())
	fgsReady := make(chan bool)
	fgsFinished := make(chan bool)
	go func() {
		runFgs(args.FgsEnableTLS, false, summary, fgsCtx, fgsCancel, fgsReady)
		fgsFinished <- true
	}()

	<-fgsReady
	summary.SetupDurationNanos = time.Since(summary.StartTime)
	for _, srcProxySink := range benchmarkSourceProxySinks {
		t.Run(srcProxySink.source, func(t *testing.T) {
			loadCtx, loadCancel := context.WithCancel(context.Background())
			summary.ResetForNewRun()
			summary.StartTime = time.Now()
			summary.TestName = t.Name()
			args.SourceArgs = SourceArgs{Duration: benchmarkDuration}
			args.Source = SourceNameOrPanic(srcProxySink.source)
			args.Sink = SinkNameOrPanic(srcProxySink.sink)
			args.Proxy = ProxyNameOrPanic(srcProxySink.proxy)
			go sigHandler(loadCtx, loadCancel)
			runFgsBenchmark(args, summary, loadCtx, loadCancel)
			if err := summary.WriteFile(resultFilename(t)); err != nil {
				t.Fatalf("summary.WriteFile failed: %s", err)
			}
			if summary.Error != "" {
				t.Fatalf("test failed: %s", summary.Error)
			}
		})
	}
	fgsCancel()
	<-fgsFinished

}

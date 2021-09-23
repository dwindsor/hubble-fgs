//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

//go:build linux && bench_tests
// +build linux,bench_tests

package bench

import (
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

func checkSummaryForErrors(t *testing.T, summary *BenchSummary) {
	if summary.Error != "" {
		t.Fatalf("test failed: %s", summary.Error)
	}
	if summary.SourceStats.Errors > 0 {
		t.Fatalf("test failed due to source errors (%d), last error was: %s",
			summary.SourceStats.Errors,
			summary.Error)
	}
}

func TestBenchBaseline(t *testing.T) {
	for _, srcProxySink := range benchmarkSourceProxySinks {
		t.Run(srcProxySink.source, func(t *testing.T) {
			summary := RunBenchmark(
				&BenchArguments{
					TestName:   t.Name(),
					SourceArgs: SourceArgs{Duration: benchmarkDuration},
					Source:     SourceNameOrPanic(srcProxySink.source),
					Proxy:      ProxyNameOrPanic(srcProxySink.proxy),
					Sink:       SinkNameOrPanic(srcProxySink.sink),
					Baseline:   true,
				})
			if err := summary.WriteFile(resultFilename(t)); err != nil {
				t.Fatalf("summary.WriteFile failed: %s", err)
			}
			checkSummaryForErrors(t, summary)
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
	summary := RunBenchmark(
		&BenchArguments{
			TestName:   t.Name(),
			SourceArgs: SourceArgs{Duration: benchmarkDuration},
			Source:     SourceNameOrPanic(source),
			Proxy:      ProxyNameOrPanic(proxy),
			Sink:       SinkNameOrPanic(sink),
			Baseline:   true,
		})
	if err := summary.WriteFile(resultFilename(t)); err != nil {
		t.Fatalf("summary.WriteFile failed: %s", err)
	}
	checkSummaryForErrors(t, summary)
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

func TestFGSHTTP(t *testing.T) {
	viper.Set("log-level", "error")
	viper.Set("debug", false)
	summary := RunBenchmark(
		&BenchArguments{
			TestName:   t.Name(),
			SourceArgs: SourceArgs{Duration: benchmarkDuration},
			Source:     SourceNameOrPanic("http-crr-go"),
			Proxy:      ProxyNameOrPanic("none"),
			Sink:       SinkNameOrPanic("http-nginx"),
		})
	if err := summary.WriteFile(resultFilename(t)); err != nil {
		t.Fatalf("summary.WriteFile failed: %s", err)
	}
	checkSummaryForErrors(t, summary)
}

func benchmarkFgs(t *testing.T, args *BenchArguments) {
	viper.Set("log-level", "error")
	viper.Set("debug", false)

	for _, srcProxySink := range benchmarkSourceProxySinks {
		t.Run(srcProxySink.source, func(t *testing.T) {
			args.SourceArgs = SourceArgs{Duration: benchmarkDuration}
			args.Source = SourceNameOrPanic(srcProxySink.source)
			args.Sink = SinkNameOrPanic(srcProxySink.sink)
			args.Proxy = ProxyNameOrPanic(srcProxySink.proxy)
			args.TestName = t.Name()
			summary := RunBenchmark(args)
			if err := summary.WriteFile(resultFilename(t)); err != nil {
				t.Fatalf("summary.WriteFile failed: %s", err)
			}
			checkSummaryForErrors(t, summary)
		})
	}
}

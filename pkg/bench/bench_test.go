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
	"os"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/spf13/viper"
)

func resultFilename(b *testing.B) string {
	// NOTE: working directory is pkg/bench when running with "go test". We're
	// also packaging up the benchmark suite into a binary and running it in CI
	// in which case we're dumping the results to current directory.
	file := strings.ReplaceAll(b.Name(), "/", "_") + ".json"
	if _, err := os.Stat("bench_test.go"); err == nil {
		return path.Join("..", "..", "results", file)
	} else {
		return file
	}
}

func BenchmarkBaseline(b *testing.B) {
	for _, mode := range SupportedModes {
		b.Run(mode, func(b *testing.B) {
			summary := BenchBaseline(
				&BenchArguments{
					NumSteps: b.N,
					ConnRate: 0, // Unlimited
					Mode:     mode,
					Baseline: true,
				})
			summary.TestName = b.Name()
			if err := summary.WriteFile(resultFilename(b)); err != nil {
				b.Fatalf("summary.WriteFile failed: %s", err)
			}
		})
	}
}

func BenchmarkBaselineTcpRequestResponse(b *testing.B) {
	summary := BenchBaseline(
		&BenchArguments{
			NumSteps:        b.N,
			ConnRate:        0, // Unlimited
			Mode:            "tcp",
			Baseline:        true,
			RequestResponse: true,
			UseNetperf:      true,
		})

	summary.TestName = b.Name()
	if err := summary.WriteFile(resultFilename(b)); err != nil {
		b.Fatalf("summary.WriteFile failed: %s", err)
	}
}

func BenchmarkFgsTcpRequestResponse(b *testing.B) {
	benchmarkFgs(b,
		[]string{"tcp"},
		&BenchArguments{
			NumSteps:        1,
			ConnRate:        0, // Unlimited
			Mode:            "tcp",
			FgsEnableTls:    false,
			Baseline:        false,
			RequestResponse: true,
			UseNetperf:      true,
		})
}

func BenchmarkFgsTls_TcpRequestResponse(b *testing.B) {
	benchmarkFgs(b,
		[]string{"tcp"},
		&BenchArguments{
			NumSteps:        1,
			ConnRate:        0, // Unlimited
			Mode:            "tcp",
			FgsEnableTls:    true,
			Baseline:        false,
			RequestResponse: true,
			UseNetperf:      true,
		})
}

func BenchmarkBaselineHttpRequestResponse(b *testing.B) {
	summary := BenchBaseline(
		&BenchArguments{
			NumSteps:        b.N,
			ConnRate:        0, // Unlimited
			Mode:            "http",
			Baseline:        true,
			RequestResponse: true,
			UseNetperf:      false,
		})
	summary.TestName = b.Name()
	if err := summary.WriteFile(resultFilename(b)); err != nil {
		b.Fatalf("summary.WriteFile failed: %s", err)
	}
}

func BenchmarkFgsHttpRequestResponse(b *testing.B) {
	benchmarkFgs(b,
		[]string{"http"},
		&BenchArguments{
			NumSteps:        1,
			ConnRate:        0, // Unlimited
			Mode:            "http",
			FgsEnableTls:    false,
			Baseline:        false,
			RequestResponse: true,
			UseNetperf:      false,
		})
}

func BenchmarkFgsNoTls(b *testing.B) {
	benchmarkFgs(b,
		SupportedModes,
		&BenchArguments{
			NumSteps:     1,
			ConnRate:     0, // Unlimited
			Mode:         "tcp",
			FgsEnableTls: false,
			Baseline:     false,
		})
}

func BenchmarkFgsTls(b *testing.B) {
	benchmarkFgs(b,
		SupportedModes,
		&BenchArguments{
			NumSteps:     1,
			ConnRate:     0, // Unlimited
			Mode:         "tcp",
			FgsEnableTls: true,
			Baseline:     false,
		})
}

func benchmarkFgs(b *testing.B, modes []string, args *BenchArguments) {
	viper.Set("log-level", "error")
	viper.Set("debug", false)

	summary := newBenchSummary(args)

	fgsCtx, fgsCancel := context.WithCancel(context.Background())
	fgsReady := make(chan bool)
	fgsFinished := make(chan bool)
	go func() {
		runFgs(args.FgsEnableTls, false, summary, fgsCtx, fgsCancel, fgsReady)
		fgsFinished <- true
	}()

	<-fgsReady
	summary.SetupDurationNanos = time.Since(summary.StartTime)
	for _, mode := range modes {
		b.Run(mode, func(b *testing.B) {
			loadCtx, loadCancel := context.WithCancel(context.Background())
			summary.ResetForNewRun()
			summary.StartTime = time.Now()
			summary.TestName = b.Name()
			args.Mode = mode
			args.NumSteps = b.N
			go sigHandler(loadCtx, loadCancel)
			runFgsBenchmark(args, summary, loadCtx, loadCancel)
			if err := summary.WriteFile(resultFilename(b)); err != nil {
				b.Fatalf("summary.WriteFile failed: %s", err)
			}
		})
	}
	fgsCancel()
	<-fgsFinished

}

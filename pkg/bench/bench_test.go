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
	"path"
	"strings"
	"testing"
	"time"

	"github.com/spf13/viper"
)

func resultFilename(b *testing.B) string {
	// NOTE: working directory is pkg/bench.
	return path.Join("..", "..", "results", strings.ReplaceAll(b.Name(), "/", "_") + ".json")
}

func BenchmarkBaseline(b *testing.B) {
	for _, mode := range SupportedModes {
		b.Run(mode, func(b *testing.B) {
			summary := BenchBaseline(
				&BenchArguments{
					NumConns: b.N,
					ConnRate: 0, // Unlimited
					Mode:     mode,
				})
			if err := summary.WriteFile(resultFilename(b)); err != nil {
				b.Fatalf("summary.WriteFile failed: %s", err)
			}
		})
	}
}

func BenchmarkFgsNoTls(b *testing.B) {
	benchmarkFgs(b, false)
}

func BenchmarkFgsTls(b *testing.B) {
	benchmarkFgs(b, true)
}

func benchmarkFgs(b *testing.B, fgsTls bool) {
	viper.Set("log-level", "error")
	viper.Set("debug", false)

	args := &BenchArguments{
		NumConns: 1,
		ConnRate: 0, // Unlimited
		Mode:     "tcp",
		FgsEnableTls: fgsTls,
	}

	summary := newBenchSummary(args)

	fgsCtx, fgsCancel := context.WithCancel(context.Background())
	fgsReady := make(chan bool)
	fgsFinished := make(chan bool)
	go func() {
		runFgs(false, false, summary, fgsCtx, fgsCancel, fgsReady)
		fgsFinished <- true
	}()

	<-fgsReady
	summary.SetupDurationNanos = time.Since(summary.StartTime)
	for _, mode := range SupportedModes {
		b.Run(mode, func(b *testing.B) {
			loadCtx, loadCancel := context.WithCancel(context.Background())
			summary.ResetForNewRun()
			summary.StartTime = time.Now()
			args.Mode = mode
			args.NumConns = b.N
			go sigHandler(loadCtx, loadCancel)
			runFgsBenchmark(args, summary, loadCtx, loadCancel)
			if err := summary.WriteFile(resultFilename(b)); err != nil {
				b.Fatalf("summary.WriteFile failed: %s", err)
			}
		})
	}

	fgsCancel()
	<- fgsFinished

}

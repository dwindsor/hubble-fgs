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
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"
)

// Summary of the benchmark results. Serializes to JSON.
// This is updated from multiple places concurrently, but currently
// there is no overlap on writes, so this isn't yet protected by a mutex.
type BenchSummary struct {
	Args *BenchArguments

	TlsEvents, ExitEvents, ExecEvents, TcpEvents int64

	StartTime          time.Time
	EndTime            time.Time
	SetupDurationNanos time.Duration
	TestDurationNanos  time.Duration

	SourceStats SourceStats

	JsonEncodingDurationNanos time.Duration

	FgsCpuUsage    CpuUsage
	SourceCpuUsage CpuUsage
	SinkCpuUsage   CpuUsage

	BpfStats map[int64]*BpfProgStats
}

func (ts *BenchSummary) ResetForNewRun() {
	ts.TlsEvents = 0
	ts.ExitEvents = 0
	ts.ExecEvents = 0
	ts.TcpEvents = 0
	ts.BpfStats = nil
	ts.StartTime = time.Time{}
	ts.EndTime = time.Time{}
	ts.TestDurationNanos = 0
	ts.FgsCpuUsage = CpuUsage{}
	ts.SourceCpuUsage = CpuUsage{}
	ts.SinkCpuUsage = CpuUsage{}
}

func (ts *BenchSummary) Dump() {
	err := json.NewEncoder(os.Stdout).Encode(ts)
	if err != nil {
		log.Fatalf("json.Encode: %v", err)
	}
}

func (ts *BenchSummary) PrettyPrint() {
	fmt.Println("Benchmark summary")
	fmt.Println("-----------------")
	fmt.Printf("Started:           %s\n", ts.StartTime)
	fmt.Printf("Ended:             %s\n", ts.EndTime)
	fmt.Printf("Arguments:         %v\n", ts.Args)
	fmt.Printf("Total duration:    %s\n", ts.EndTime.Sub(ts.StartTime))
	fmt.Printf("Setup duration:    %s\n", ts.SetupDurationNanos)
	fmt.Printf("Test duration:     %s\n", ts.TestDurationNanos)
	fmt.Printf("FGS cpu usage:     %s\n", ts.FgsCpuUsage)
	fmt.Printf("Source cpu usage:  %s\n", ts.SourceCpuUsage)
	fmt.Printf("Sink cpu usage:    %s\n", ts.SinkCpuUsage)
	fmt.Printf("Connection rate:   %.2f per second\n", ts.SourceStats.ActualRate)
	if ts.SourceStats.Errors > 0 {
		fmt.Printf("Connection errors: %d\n", ts.SourceStats.Errors)
		fmt.Printf("Last error:        %s\n", ts.SourceStats.LastError)
	}
	fmt.Println("BPF statistics:")
	for _, bps := range ts.BpfStats {
		fmt.Printf("  %s\n", bps)
	}
}

func (ts *BenchSummary) WriteFile(path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		return err
	}
	defer f.Close()
	return json.NewEncoder(f).Encode(ts)
}

func newBenchSummary(args *BenchArguments) *BenchSummary {
	return &BenchSummary{
		StartTime: time.Now(),
		Args:      args,
	}
}

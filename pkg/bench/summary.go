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

	"github.com/fatih/color"
	"github.com/isovalent/hubble-fgs/pkg/metrics"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// BenchSummary gathers benchmark results. Serializes to JSON.
// This is updated from multiple places concurrently, but currently
// there is no overlap on writes, so this isn't yet protected by a mutex.
type BenchSummary struct {
	Args *BenchArguments

	TLSEvents, HTTPEvents, ExitEvents, ExecEvents, TCPEvents int64

	StartTime          time.Time
	EndTime            time.Time
	SetupDurationNanos time.Duration
	TestDurationNanos  time.Duration

	SinkStats   SinkStats
	SourceStats SourceStats
	ProxyStats  ProxyStats

	JSONEncodingDurationNanos time.Duration

	FgsCPUUsage CPUUsage

	BpfStats map[int64]*BpfProgStats

	Error string
}

func (s *BenchSummary) Dump() {
	err := json.NewEncoder(os.Stdout).Encode(s)
	if err != nil {
		log.Fatalf("json.Encode: %v", err)
	}
}

func getGaugeValue(gauge prometheus.Gauge) int {
	// Yep, this does seem to be the only way to read it.
	var d dto.Metric
	gauge.Write(&d)
	return int(*d.Gauge.Value)
}

func (s *BenchSummary) PrettyPrint() {
	color.Set(color.FgBlue)
	fmt.Println("Benchmark summary")
	fmt.Println("-----------------")
	color.Unset()
	fmt.Printf("Started:           %s\n", s.StartTime)
	fmt.Printf("Ended:             %s\n", s.EndTime)
	fmt.Printf("Arguments:         %v\n", s.Args)
	fmt.Printf("Total duration:    %s\n", s.EndTime.Sub(s.StartTime))
	fmt.Printf("Setup duration:    %s\n", s.SetupDurationNanos)
	fmt.Printf("Test duration:     %s\n", s.TestDurationNanos)
	fmt.Printf("Export duration:   %s\n", s.JSONEncodingDurationNanos)
	fmt.Printf("FGS cpu usage:     %s\n", s.FgsCPUUsage)
	fmt.Printf("Source cpu usage:  %s\n", s.SourceStats.CPUUsage)
	fmt.Printf("Proxy cpu usage:   %s\n", s.ProxyStats.CPUUsage)
	fmt.Printf("Sink cpu usage:    %s\n", s.SinkStats.CPUUsage)
	fmt.Printf("Actual rate:       %.2f per second\n", s.SourceStats.ActualRate)
	fmt.Printf("Latency 50th:      %s\n", s.SourceStats.LatencyP50)
	fmt.Printf("Latency 90th:      %s\n", s.SourceStats.LatencyP90)
	fmt.Printf("Latency 99th:      %s\n", s.SourceStats.LatencyP99)

	if !s.Args.Baseline {
		fmt.Printf("Events:            tls=%d, http=%d, tcp=%d, exit=%d, exec=%d\n",
			s.TLSEvents, s.HTTPEvents, s.TCPEvents,
			s.ExitEvents, s.ExecEvents)
		fmt.Printf("Ring buffer:       received=%d, lost=%d, errors=%d\n",
		           getGaugeValue(metrics.RingBufPerfEventReceived.WithLabelValues()),
		           getGaugeValue(metrics.RingBufPerfEventLost.WithLabelValues()),
		           getGaugeValue(metrics.RingBufPerfEventErrors.WithLabelValues()))
	}

	if s.SourceStats.Errors > 0 {
		color.Set(color.FgRed)
		fmt.Printf("Source Errors:     %d\n", s.SourceStats.Errors)
		fmt.Printf("Last source error: %s\n", s.SourceStats.LastError)
		color.Unset()
	}
	fmt.Println("BPF statistics:")
	for _, bps := range s.BpfStats {
		if bps.RunCnt > 0 {
			fmt.Printf("  %s\n", bps)
		}
	}

	if s.Error != "" {
		color.Set(color.FgRed)
		fmt.Printf("Error:             %s\n", s.Error)
		color.Unset()
	}
}

func (s *BenchSummary) WriteFile(path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		return err
	}
	defer f.Close()
	return json.NewEncoder(f).Encode(s)
}

func newBenchSummary(args *BenchArguments) *BenchSummary {
	return &BenchSummary{
		StartTime: time.Now(),
		Args:      args,
	}
}

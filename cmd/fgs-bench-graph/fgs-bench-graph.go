//go:build !windows

package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/isovalent/hubble-fgs/pkg/bench"
)

var (
	supportedParsers = []string{"tls", "http", "tcp", "udp", "histograms"}
)

type benchmarkNetworkTest struct {
	name     string
	source   string
	sink     string
	parsers  string
	baseline bool
	netns    bool
	summary  *bench.Summary
}

var networkRRBenchmarks = []benchmarkNetworkTest{
	{"baseline", "netperf-rr", "netperf", "", true, true, nil},
	{"fgs", "netperf-rr", "netperf", "", false, true, nil},
	{"tcp", "netperf-rr", "netperf", "tcp", false, true, nil},
	{"udp", "netperf-rr", "netperf", "udp", false, true, nil},
	{"tcpudp", "netperf-rr", "netperf", "tcp,udp", false, true, nil},
}

var networkLoRRBenchmarks = []benchmarkNetworkTest{
	{"baseline", "netperf-rr", "netperf", "", true, false, nil},
	{"fgs", "netperf-rr", "netperf", "", false, false, nil},
	{"tcp", "netperf-rr", "netperf", "tcp", false, false, nil},
	{"udp", "netperf-rr", "netperf", "udp", false, false, nil},
	{"tcp+udp", "netperf-rr", "netperf", "tcp,udp", false, false, nil},
}

var networkStreamBenchmarks = []benchmarkNetworkTest{
	{"baseline", "netperf-stream", "netperf", "", true, true, nil},
	{"fgs", "netperf-stream", "netperf", "", false, true, nil},
	{"tcp", "netperf-stream", "netperf", "tcp", false, true, nil},
	{"udp", "netperf-stream", "netperf", "udp", false, true, nil},
	{"tcpudp", "netperf-stream", "netperf", "tcp,udp", false, true, nil},
}

var networkLoStreamBenchmarks = []benchmarkNetworkTest{
	{"baseline", "netperf-stream", "netperf", "", true, false, nil},
	{"fgs", "netperf-stream", "netperf", "", false, false, nil},
	{"tcp", "netperf-stream", "netperf", "tcp", false, false, nil},
	{"udp", "netperf-stream", "netperf", "udp", false, false, nil},
	{"tcpudp", "netperf-stream", "netperf", "tcp,udp", false, false, nil},
}

var benchmarkDuration = 60 * time.Second

func doBenchmark(output string, tests []benchmarkNetworkTest) error {
	var rawData []*bench.Summary
	var titles []string
	var tcp, udp, iface, hist, tls, http bool

	for _, t := range tests {
		for p := range strings.SplitSeq(t.parsers, ",") {
			switch p {
			case "http":
				http = true
			case "tls":
				tls = true
			case "udp":
				udp = true
			case "tcp":
				tcp = true
			case "histograms":
				hist = true
			case "interface":
				iface = true
			case "":
			default:
				log.Fatalf("Unknown parser: %s, use on of: %s", p, strings.Join(supportedParsers, ", "))
			}
		}
		t.summary = bench.RunBenchmark(
			&bench.Arguments{
				TestName: t.name,
				SourceArgs: bench.SourceArgs{
					Duration:       benchmarkDuration,
					WithConfidence: true,
				},
				Source:             bench.SourceNameOrPanic(t.source),
				Proxy:              "none",
				Sink:               bench.SinkNameOrPanic(t.sink),
				Baseline:           t.baseline,
				Netns:              t.netns,
				FgsEnableTCP:       tcp,
				FgsEnableUDP:       udp,
				FgsEnableTLS:       tls,
				FgsEnableHTTP:      http,
				FgsEnableInterface: iface,
				FgsEnableHistogram: hist,
				FgsEnableBpfStats:  false,
			})

		fmt.Printf("%s: %f %f %f\n", t.name, t.summary.SourceStats.ActualRate, t.summary.SourceStats.CPUPercent.SourceCpuUser, t.summary.SourceStats.CPUPercent.SourceCpuSystem)

		rawData = append(rawData, t.summary)
		titles = append(titles, t.name)
		time.Sleep(1 * time.Second)
	}

	file, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE, 0666)
	if err != nil {
		return fmt.Errorf("file does not exists or cannot be created")
	}
	defer file.Close()

	w := bufio.NewWriter(file)
	for i, r := range rawData {
		fmt.Fprintf(w, "%d %s %f %f %f\n", i, titles[i],
			r.SourceStats.ActualRate,
			r.SourceStats.CPUPercent.SourceCpuUser,
			r.SourceStats.CPUPercent.SourceCpuSystem,
		)
	}
	w.Flush()
	return nil
}

func main() {
	if unix.Getuid() != 0 {
		log.Fatalf("You need to run fgs-bench-graph as root.")
	}
	log.SetOutput(os.Stderr)
	doBenchmark("rr.dat", networkRRBenchmarks)
	doBenchmark("rrlo.dat", networkLoRRBenchmarks)
	doBenchmark("stream.dat", networkStreamBenchmarks)
	doBenchmark("streamlo.dat", networkLoStreamBenchmarks)
}

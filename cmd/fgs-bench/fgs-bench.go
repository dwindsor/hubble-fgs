// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package main

import (
	"flag"
	"log"
	"os"
	"strings"
	"time"

	"github.com/isovalent/hubble-fgs/pkg/bench"
	"github.com/spf13/viper"
	"golang.org/x/sys/unix"
)

// Command-line flags
var (
	duration    *time.Duration
	rate        *int
	debug       *bool
	jsonEncode  *bool
	baseline    *bool
	requestSize *int
	parsers     *string
	printEvents *bool
	netns       *bool

	source *string
	proxy  *string
	sink   *string

	supportedParsers = []string{"tls", "http", "tcp", "udp", "histograms"}
)

func init() {
	duration = flag.Duration("duration", 10*time.Second, "test duration")
	rate = flag.Int("rate", 0, "connections/requests per second, use 0 for unlimited")
	parsers = flag.String("parsers", "", "comma-separated list of FGS parsers to enable:"+strings.Join(supportedParsers, ", "))
	debug = flag.Bool("debug", false, "enable FGS debugging")
	jsonEncode = flag.Bool("json-encode", false, "JSON encode the events and measure overhead")
	baseline = flag.Bool("baseline", false, "run a baseline benchmark without FGS")
	requestSize = flag.Int("req-size", 64, "request size for request-response test")
	printEvents = flag.Bool("print", false, "print events in JSON to stdout")

	source = flag.String("source", "none", "source to use, one of: "+strings.Join(bench.SupportedSources(), ", "))
	proxy = flag.String("proxy", "none", "proxy to use, one of: "+strings.Join(bench.SupportedProxies(), ", "))
	sink = flag.String("sink", "tcp", "sink to use, one of: "+strings.Join(bench.SupportedSinks(), ", "))

	netns = flag.Bool("netns", false, "run source and sink in different network namespaces")
}

func main() {
	if unix.Getuid() != 0 {
		log.Fatalf("You need to run fgs-bench as root.")
	}

	flag.Parse()
	log.SetOutput(os.Stderr)

	if *debug {
		viper.Set("log-level", "debug")
	}

	var tlsParser, httpParser bool
	var tcp, udp, iface, hist bool

	for _, p := range strings.Split(*parsers, ",") {
		switch p {
		case "http":
			httpParser = true
			tcp = true
		case "tls":
			tlsParser = true
			tcp = true
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

	args := &bench.Arguments{
		FgsEnableTLS:       tlsParser,
		FgsEnableHTTP:      httpParser,
		FgsEnableTCP:       tcp,
		FgsEnableUDP:       udp,
		FgsEnableInterface: iface,
		FgsEnableHistogram: hist,
		FgsDebug:           *debug,
		FgsJSONEncode:      *jsonEncode || *printEvents,
		Netns:              *netns,
		PrintEvents:        *printEvents,
		Baseline:           *baseline,
		Source:             bench.SourceNameOrPanic(*source),
		SourceArgs: bench.SourceArgs{
			Duration:   *duration,
			RatePerSec: float64(*rate),
			ReqSize:    *requestSize,
		},
		Proxy: bench.ProxyNameOrPanic(*proxy),
		Sink:  bench.SinkNameOrPanic(*sink),
	}

	summary := bench.RunBenchmark(args)
	summary.PrettyPrint()
	if summary.Error != "" {
		os.Exit(1)
	}
}

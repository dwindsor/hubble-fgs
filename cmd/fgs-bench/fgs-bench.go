//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.
//

package main

import (
	"flag"
	"log"
	"os"
	"os/user"
	"strings"
	"time"

	"github.com/isovalent/hubble-fgs/pkg/bench"
)

// Command-line flags
var (
	duration        *time.Duration
	rate            *int
	fgsTLS          *bool
	noDelay         *bool
	debug           *bool
	jsonEncode      *bool
	baseline        *bool
	requestResponse *bool
	requestSize     *int

	source *string
	proxy  *string
	sink   *string
)

func init() {
	duration = flag.Duration("duration", 10*time.Second, "test duration")

	rate = flag.Int("rate", 0, "connections/requests per second, use 0 for unlimited")
	fgsTLS = flag.Bool("fgs-tls", false, "enable TLS in FGS")
	debug = flag.Bool("debug", false, "enable FGS debugging")
	jsonEncode = flag.Bool("json-encode", false, "JSON encode the events and measure overhead")
	baseline = flag.Bool("baseline", false, "run a baseline benchmark without FGS")
	requestSize = flag.Int("req-size", 64, "request size for request-response test")

	source = flag.String("source", "none", "source to use, one of: "+strings.Join(bench.SupportedSources(), ","))
	proxy = flag.String("proxy", "none", "proxy to use, one of: "+strings.Join(bench.SupportedProxies(), ","))
	sink = flag.String("sink", "tcp", "sink to use, one of: "+strings.Join(bench.SupportedSinks(), ","))
}

func main() {
	u, err := user.Current()
	if err != nil || u.Uid != "0" {
		log.Fatalf("You need to run fgs-bench as root.")
	}

	flag.Parse()
	log.SetOutput(os.Stderr)

	args := &bench.BenchArguments{
		FgsEnableTLS:  *fgsTLS,
		FgsDebug:      *debug,
		FgsJSONEncode: *jsonEncode,
		Baseline:      *baseline,
		Source:        bench.SourceNameOrPanic(*source),
		SourceArgs: bench.SourceArgs{
			Duration:   *duration,
			RatePerSec: float64(*rate),
			ReqSize:    *requestSize,
		},
		Proxy: bench.ProxyNameOrPanic(*proxy),
		Sink:  bench.SinkNameOrPanic(*sink),
	}

	var summary *bench.BenchSummary
	if *baseline {
		summary = bench.BenchBaseline(args)
	} else {
		summary = bench.BenchFGS(args, func() {})
	}

	summary.PrettyPrint()
}

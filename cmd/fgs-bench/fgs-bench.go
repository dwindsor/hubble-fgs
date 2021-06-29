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

	"github.com/isovalent/hubble-fgs/pkg/bench"
)

// Command-line flags
var (
	mode       *string
	numConns   *int
	connRate   *int
	fgsTls     *bool
	noDelay    *bool
	debug      *bool
	jsonEncode *bool
	baseline   *bool
)

func checkMode() {
	for _, m := range bench.SupportedModes {
		if *mode == m {
			return
		}
	}
	log.Fatalf("unknown mode: %s, pick on of: " + strings.Join(bench.SupportedModes, ","))
}

func init() {
	numConns = flag.Int("n", 1000, "number of connections")
	connRate = flag.Int("rate", 100, "connections per second, use 0 for unlimited")
	fgsTls = flag.Bool("fgs-tls", false, "enable TLS in FGS")
	debug = flag.Bool("debug", false, "enable FGS debugging")
	jsonEncode = flag.Bool("json-encode", false, "JSON encode the events and measure overhead")
	baseline = flag.Bool("baseline", false, "run a baseline benchmark without FGS")

	mode = flag.String("mode", "tcp", "connection mode, one of: "+strings.Join(bench.SupportedModes, ","))
}

func main() {
	u, err := user.Current()
	if err != nil || u.Uid != "0" {
		log.Fatalf("You need to run fgs-bench as root.")
	}

	flag.Parse()
	checkMode()
	log.SetOutput(os.Stderr)

	args := &bench.BenchArguments{
		NumConns:      *numConns,
		ConnRate:      *connRate,
		FgsEnableTls:  *fgsTls,
		FgsDebug:      *debug,
		FgsJsonEncode: *jsonEncode,
		Mode:          *mode,
		Baseline:      *baseline,
	}

	var summary *bench.BenchSummary
	if *baseline {
		summary = bench.BenchBaseline(args)
	} else {
		summary = bench.BenchFGS(args, func() {})
	}

	summary.PrettyPrint()
}

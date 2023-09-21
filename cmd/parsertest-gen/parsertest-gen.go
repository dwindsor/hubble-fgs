package main

import (
	"flag"
	"fmt"
	"os"
)

var (
	outFile *string
)

func init() {
	outFile = flag.String("outfile", "", "output filename, if not specified output is written to stdout")
}

func main() {
	var err error

	flag.Parse()

	filename := flag.Arg(0)
	if filename == "" {
		fmt.Fprintf(os.Stderr, "usage: fgs-parsertest [FLAGS] <pdml file>\n")
		flag.PrintDefaults()
		os.Exit(1)
	}

	w := os.Stdout
	if *outFile != "" {
		w, err = os.OpenFile(*outFile, os.O_CREATE|os.O_TRUNC, 0622)
		if err != nil {
			panic(err)
		}
		defer w.Close()
	}

	err = PDMLToTestCase(filename, w)
	if err != nil {
		panic(err)
	}
}

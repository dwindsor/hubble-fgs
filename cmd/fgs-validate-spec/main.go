package main

import (
	"flag"
	"log"

	"github.com/isovalent/hubble-fgs/pkg/bpf"
	"github.com/isovalent/hubble-fgs/pkg/btf"
	"github.com/isovalent/hubble-fgs/pkg/config"
)

var (
	btfFname  string
	specFname string
)

func init() {
	flag.StringVar(&btfFname, "btf-filename", "/sys/kernel/btf/vmlinux", "BTF file for the validation")
	flag.StringVar(&specFname, "spec-filename", "", "tracingPolicy file (yaml) to validate")
}

var ()

func main() {

	flag.Parse()

	if specFname == "" {
		log.Fatalf("spec-file was not defined")
	}

	btfHandle, err := bpf.NewBTF(btfFname)
	if err != nil {
		log.Fatalf("failed to initialize BTF: %s", err)
	}
	defer btfHandle.Close()

	spec, err := config.FileConfigSpec(specFname)
	if err != nil {
		log.Fatal(err)
	}
	for ki := range spec.KProbes {
		if err = btf.ValidateKprobeSpec(btfHandle, &spec.KProbes[ki]); err != nil {
			log.Fatal(err)
		}
	}
}

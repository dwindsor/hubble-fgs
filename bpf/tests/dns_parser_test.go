package bpftests

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf"
)

const (
	programName = "test_dns_parser"
)

func Test_DNSParser(t *testing.T) {
	// load test program
	coll, err := ebpf.LoadCollection("objs/dns_parser_test.o")
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			t.Fatalf("verifier error: %+v\n", ve)
		}
		t.Fatal(err)
	}
	defer coll.Close()

	// get ref to objects
	prog, ok := coll.Programs[programName]
	if !ok {
		t.Fatalf("%s not found", programName)
	}

	code, err := prog.Run(&ebpf.RunOptions{
		Data: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Log(code)
}

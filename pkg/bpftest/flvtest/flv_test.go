// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

//go:build sudo_tests

package flvtest

import (
	"errors"
	"flag"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/stretchr/testify/require"
)

const (
	programName = "test_flv_zero"
	objName     = "flv_test.o"
	testMapName = "tg_flv_zero_test"
)

var verifierLogs = flag.Bool("verlogs", false, "Write the full verifier logs in the ./verifier.log file")

func loadFlvTestCollection(t *testing.T) *ebpf.Collection {
	// load test program
	collSpec, err := ebpf.LoadCollectionSpec(filepath.Join("../../../bpf/tests/objs", objName))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("please run 'make tetragon-bpf-test' to compile the BPF test program: %s", err)
		}
		t.Fatal(err)
	}

	collOpts := ebpf.CollectionOptions{}
	if verifierLogs != nil && *verifierLogs {
		collOpts.Programs = ebpf.ProgramOptions{
			LogLevel: ebpf.LogLevelInstruction,
		}
	}
	coll, err := ebpf.NewCollectionWithOptions(collSpec, collOpts)
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			t.Fatalf("verifier error: %+v\n", ve)
		}
		t.Fatal(err)
	}
	t.Cleanup(func() {
		coll.Close()
	})

	prog, ok := coll.Programs[programName]
	if !ok {
		t.Fatalf("%s not found", programName)
	}

	if verifierLogs != nil && *verifierLogs {
		logFile, err := os.Create("verifier.log")
		if err != nil {
			t.Fatal(err)
		}

		_, err = logFile.WriteString(prog.VerifierLog)
		if err != nil {
			t.Fatal(err)
		}
		logFile.Close()
	}

	return coll
}

type flvZeroTest struct {
	Keep  uint32
	Value [64]byte
}

func TestFlvZeroTail64(t *testing.T) {
	// In production flv_zero_tail64 runs only under the TLS parser, which
	// refuses to load below 5.10 (pkg/sensors/sockmap/sockmap_linux.go).
	if !kernels.MinKernelVersion("5.10") {
		t.Skipf("Minimum kernel version (5.10) not met, skipping")
	}

	coll := loadFlvTestCollection(t)

	prog, ok := coll.Programs[programName]
	if !ok {
		t.Fatalf("%s not found", programName)
	}

	testMap, ok := coll.Maps[testMapName]
	if !ok {
		t.Fatalf("map %s not found", testMapName)
	}

	// Keeps at and around each 8-byte boundary, so every arm of the switch in
	// flv_zero_tail64 runs at least once, and keeps from 64 up, which take the
	// early return ahead of the switch.
	for _, keep := range []uint32{
		0, 1, 7, 8, 9, 15, 16, 23, 24, 31, 32,
		39, 40, 47, 48, 55, 56, 63, 64, 65, 255,
	} {
		key := uint32(0)
		value := flvZeroTest{Keep: keep}
		for i := range value.Value {
			value.Value[i] = 0xff
		}
		require.NoError(t, testMap.Update(key, value, ebpf.UpdateAny))

		_, err := prog.Run(&ebpf.RunOptions{})
		require.NoError(t, err)

		require.NoError(t, testMap.Lookup(key, &value))

		for i := range value.Value {
			want := byte(0)
			if uint32(i) < keep {
				want = 0xff
			}
			require.Equalf(t, want, value.Value[i], "keep=%d byte %d", keep, i)
		}
	}
}

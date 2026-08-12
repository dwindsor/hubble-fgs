// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

// go test -tags sudo_tests -gcflags="" -c ./pkg/sensors/file -o go-tests/file.test
// sudo ./go-tests/file.test --bpf-lib ./bpf/objs/ -test.run TestGlobFSMeBPF

//go:build sudo_tests

package file

import (
	"fmt"
	"math"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/cilium/tetragon/pkg/config"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/option"
	ossTestUtils "github.com/cilium/tetragon/pkg/testutils"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"

	fm "github.com/isovalent/hubble-fgs/pkg/sensors/file/utils"
	"github.com/isovalent/hubble-fgs/pkg/sensors/utils"
)

type StrVal struct {
	Path [1024]byte
	Len  uint32
	Val  int32
	Res  uint64
	Dur  uint64
}

func initGlob(objFile string, patterns map[string][]int32) (*ebpf.Collection, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("runEbpfGlob: rlimit.RemoveMemlock: %s", err)
	}

	option.Config.HubbleLib = tus.Conf().TetragonLib

	objPath, err := config.FindProgramFile(objFile)
	if err != nil {
		return nil, fmt.Errorf("runEbpfGlob: FindProgramFile: %s", err)
	}
	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return nil, fmt.Errorf("runEbpfGlob: ebpf.LoadCollectionSpec: %s", err)
	}

	gd := fm.GenerateAndPopulateData(patterns)

	isFinalsMap, ok := spec.Maps["tg_glob_final"]
	if !ok {
		return nil, fmt.Errorf("runEbpfGlob: failed to find map 'tg_glob_final' in spec")
	}

	isFinalsMap.MaxEntries = uint32(gd.GetFinalStatesMapSize())

	globDfaMap, ok := spec.Maps["tg_glob_dfa"]
	if !ok {
		return nil, fmt.Errorf("runEbpfGlob: failed to find map 'tg_glob_dfa' in spec")
	}

	globDfaMap.MaxEntries = uint32(gd.GetStateTransitionsMapSize())

	col, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{})
	if err != nil {
		return nil, fmt.Errorf("runEbpfGlob: ebpf.NewCollectionWithOptions: %s", err)
	}

	isFinalsDataMap, ok := col.Maps["tg_glob_final"]
	if !ok {
		return nil, fmt.Errorf("runEbpfGlob: failed to find map 'tg_glob_final' in collection")
	}

	err = gd.GenerateFinalStatesMap(isFinalsDataMap)
	if err != nil {
		return nil, fmt.Errorf("runEbpfGlob: failed to call GenerateFinalStatesMap: %s", err)
	}

	globDfaDataMap, ok := col.Maps["tg_glob_dfa"]
	if !ok {
		return nil, fmt.Errorf("runEbpfGlob: failed to find map 'tg_glob_dfa' in collection")
	}

	err = gd.GenerateStateTransitionsMap(globDfaDataMap)
	if err != nil {
		return nil, fmt.Errorf("runEbpfGlob: failed to call GenerateStateTransitionsMap: %s", err)
	}

	return col, nil
}

func runCase(col *ebpf.Collection, path string, val int32) (*StrVal, error) {
	prog, ok := col.Programs["test_glob"]
	if !ok {
		return nil, fmt.Errorf("runEbpfGlob: failed to find program 'test_glob' in collection")
	}

	strMap, ok := col.Maps["tg_string_map"]
	if !ok {
		return nil, fmt.Errorf("runEbpfGlob: failed to find map 'tg_string_map' in collection")
	}

	var zero uint32
	s := StrVal{
		Res: 100,
		Val: val,
	}

	copy(s.Path[:], path)
	s.Len = uint32(len(path))
	if err := strMap.Put(zero, s); err != nil {
		return nil, fmt.Errorf("runEbpfGlob: strMap.Put: %s", err)
	}

	retVal, err := prog.Run(&ebpf.RunOptions{})
	if err != nil {
		return nil, fmt.Errorf("runEbpfGlob: prog.Run: %s", err)
	}

	if retVal != 0 {
		return nil, fmt.Errorf("runEbpfGlob: prog.Run return value is not 0 [value: %d]", retVal)
	}

	var strOut StrVal
	if err := strMap.Lookup(zero, &strOut); err != nil {
		return nil, fmt.Errorf("runEbpfGlob: strMap.Lookup: %s", err)
	}

	if strOut.Res != 1 && strOut.Res != 0 {
		return nil, fmt.Errorf("runEbpfGlob: Error in eBPF: %d", strOut.Res)
	}

	return &strOut, nil
}

func runEbpfGlob(t *testing.T, pattern, str string) (bool, uint64, error) {
	allPatterns := map[string][]int32{
		pattern: {1},
	}
	col, err := initGlob("lsm_test_glob.o", allPatterns)
	if err != nil {
		t.Errorf("initGlob: %s", err)
	}
	defer col.Close()

	strOut, err := runCase(col, str, -2)
	if err != nil {
		t.Errorf("runCase: %s", err)
	}

	return strOut.Res == 1, strOut.Dur, nil
}

func TestInitGlobSmallOpenFDLimit(t *testing.T) {
	if !utils.SupportFmodRet() || !utils.SupportLSM() {
		t.Skip("File monitoring patterns type requires fmod_ret and lsm programs")
	}

	var originalLimit unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &originalLimit); err != nil {
		t.Fatalf("Getrlimit(RLIMIT_NOFILE): %v", err)
	}

	// set temporary low limit for open file descriptors
	// to check for fd leaks
	if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &unix.Rlimit{
		Cur: 128,
		Max: 128,
	}); err != nil {
		t.Fatalf("Setrlimit(RLIMIT_NOFILE): %v", err)
	}

	t.Cleanup(func() {
		if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &originalLimit); err != nil {
			t.Errorf("restore RLIMIT_NOFILE: %v", err)
		}
	})

	// these require 273 states
	allPatterns := map[string][]int32{
		"*.TEMP":         {1},
		"*.backup":       {1},
		"*.bak":          {1},
		"*.old":          {1},
		"*.tmp.*":        {1},
		"*/__pycache__*": {1},
		"*/temp.*":       {1},
	}

	col, err := initGlob("lsm_test_glob.o", allPatterns)
	if err != nil {
		t.Fatalf("initGlob: %v", err)
	}
	defer col.Close()
}

func TestGlobFSMeBPF(t *testing.T) {
	if !utils.SupportFmodRet() || !utils.SupportLSM() {
		t.Skip("File monitoring patterns with FileSystemType type requires fmod_ret and lsm programs")
	}

	ossTestUtils.CaptureLog(t, logger.GetLogger())

	var totalDur, numTests uint64
	minDur := uint64(math.MaxUint64)
	maxDur := uint64(0)

	for _, c := range fm.GlobTestCases {
		res, dur, err := runEbpfGlob(t, c.Pattern, c.Path)
		assert.Equal(t, err, nil, "%w", err)
		if err == nil {
			assert.Equal(t, c.Match, res, "pattern: %s path: %s", c.Pattern, c.Path)
		}

		totalDur += dur
		numTests++
		minDur = min(minDur, dur)
		maxDur = max(maxDur, dur)
	}

	t.Log(t.Name(), "min", time.Duration(minDur)*time.Nanosecond, "max", time.Duration(maxDur)*time.Nanosecond, "avg", time.Duration(totalDur/numTests)*time.Nanosecond)
}

func TestGlobFSMeBPFMulti(t *testing.T) {
	if !utils.SupportFmodRet() || !utils.SupportLSM() {
		t.Skip("File monitoring patterns with FileSystemType type requires fmod_ret and lsm programs")
	}

	ossTestUtils.CaptureLog(t, logger.GetLogger())

	var totalDur, numTests uint64
	minDur := uint64(math.MaxUint64)
	maxDur := uint64(0)

	for _, c := range fm.GlobTestCasesMulti {
		for _, ts := range c.Tests {
			vals := []int32{}
			if len(ts.Values) == 0 {
				vals = append(vals, -1)
			} else {
				vals = append(vals, ts.Values...)
			}

			for _, vl := range vals {
				col, err := initGlob("lsm_test_glob.o", c.Patterns)
				if err != nil {
					t.Errorf("initGlob: %s", err)
				}

				strOut, err := runCase(col, ts.Path, vl)
				if err != nil {
					t.Errorf("runCase: %s", err)
				}

				col.Close()

				assert.Equal(t, strOut.Res, uint64(1), "path: %s res: %d, val: %d", ts.Path, strOut.Res, vl)

				totalDur += strOut.Dur
				numTests++
				minDur = min(minDur, strOut.Dur)
				maxDur = max(maxDur, strOut.Dur)
			}
		}
	}

	t.Log(t.Name(), "min", time.Duration(minDur)*time.Nanosecond, "max", time.Duration(maxDur)*time.Nanosecond, "avg", time.Duration(totalDur/numTests)*time.Nanosecond)
}

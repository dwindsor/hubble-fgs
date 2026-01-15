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
	"os"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/cilium/tetragon/pkg/bpf"
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
	Path [256]byte
	Len  uint32
	Pad  uint32
	Res  uint64
	Dur  uint64
}

func initGlob(objFile string, pattern string) (*ebpf.Collection, error) {
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

	tmpMap, ok := spec.Maps["glob_temp_maps"]
	if !ok {
		return nil, fmt.Errorf("runEbpfGlob: failed to find map 'glob_temp_maps' in spec")
	}

	// resize "glob_temp_maps"
	tmpMap.MaxEntries = 2 * uint32(bpf.GetNumPossibleCPUs())

	col, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{})
	if err != nil {
		return nil, fmt.Errorf("runEbpfGlob: ebpf.NewCollectionWithOptions: %s", err)
	}

	patternMap, ok := col.Maps["tg_pattern_map"]
	if !ok {
		return nil, fmt.Errorf("runEbpfGlob: failed to find map 'tg_pattern_map' in collection")
	}

	tmpBufferMap, ok := col.Maps["glob_temp_maps"]
	if !ok {
		return nil, fmt.Errorf("runEbpfGlob: failed to find map 'glob_temp_maps' in collection")
	}

	for i := range 2 * bpf.GetNumPossibleCPUs() {
		if err := tmpBufferMap.Update(uint32(i), fm.GlobTempVal{}, 0); err != nil {
			return nil, fmt.Errorf("runEbpfGlob: tmpBufferMap.Update: err: %w", err)
		}
	}

	f, err := fm.CompileGlob(pattern)
	if err != nil {
		return nil, fmt.Errorf("runEbpfGlob: CompileGlob: %w", err)
	}

	for i, s := range f.GetStates() {
		idx := uint32(i)
		if err := patternMap.Put(idx, s); err != nil {
			return nil, fmt.Errorf("runEbpfGlob: patternMap.Put: %w", err)
		}
	}

	return col, nil
}

func runCase(col *ebpf.Collection, file *os.File, path string, val int32) (*StrVal, error) {
	prog, ok := col.Programs["security_file_fcntl"]
	if !ok {
		return nil, fmt.Errorf("runEbpfGlob: failed to find program 'security_file_fcntl' in collection")
	}

	strMap, ok := col.Maps["tg_string_map"]
	if !ok {
		return nil, fmt.Errorf("runEbpfGlob: failed to find map 'tg_string_map' in collection")
	}

	var zero uint32
	s := StrVal{
		Res: 100,
	}

	copy(s.Path[:], path)
	s.Len = uint32(len(path))
	if err := strMap.Put(zero, s); err != nil {
		return nil, fmt.Errorf("runEbpfGlob: strMap.Put: %s", err)
	}

	link, err := link.AttachLSM(link.LSMOptions{Program: prog})
	if err != nil {
		return nil, fmt.Errorf("runEbpfGlob: %s", err)
	}
	defer link.Close()

	unix.FcntlInt(file.Fd(), 9999, 8888)

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
	col, err := initGlob("lsm_test_glob.o", pattern)
	if err != nil {
		t.Errorf("initGlob: %s", err)
	}
	defer col.Close()

	file, err := os.CreateTemp("", "tetragon-lsm-check-*")
	if err != nil {
		return false, 0, fmt.Errorf("runEbpfGlob: os.CreateTemp: %w", err)
	}
	defer os.Remove(file.Name())

	strOut, err := runCase(col, file, str, -2)
	if err != nil {
		t.Errorf("runCase: %s", err)
	}

	return strOut.Res == 1, strOut.Dur, nil
}

func TestGlobFSMeBPF(t *testing.T) {
	if !utils.SupportFmodRet() || !utils.SupportLSM() || (probeBpfLoop() != nil) || (probeForEachMapElem() != nil) {
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

	fmt.Println("min", time.Duration(minDur)*time.Nanosecond, "max", time.Duration(maxDur)*time.Nanosecond, "avg", time.Duration(totalDur/numTests)*time.Nanosecond)
}

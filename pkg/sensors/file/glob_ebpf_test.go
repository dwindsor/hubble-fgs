//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

// go test -gcflags="" -c ./pkg/sensors/file -o go-tests/file.test
// sudo ./go-tests/file.test --bpf-lib ./bpf/objs/ -test.run TestGlobFSMeBPF

//go:build sudo_tests

package file

import (
	"fmt"
	"os"
	"path"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/option"
	ossTestUtils "github.com/cilium/tetragon/pkg/testutils"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
	fm "github.com/isovalent/hubble-fgs/pkg/sensors/file/utils"
	"github.com/isovalent/hubble-fgs/pkg/sensors/utils"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

type StrVal struct {
	Path [256]byte
	Len  uint32
	Pad  uint32
	Res  uint64
}

func runEbpfGlob(t *testing.T, pattern, str string) (bool, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return false, fmt.Errorf("runEbpfGlob: rlimit.RemoveMemlock: %w", err)
	}

	ossTestUtils.CaptureLog(t, logger.GetLogger().(*logrus.Logger))
	option.Config.HubbleLib = tus.Conf().TetragonLib

	objFile := "lsm_test_glob.o"
	objPath := path.Join(option.Config.HubbleLib, objFile)
	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return false, fmt.Errorf("runEbpfGlob: ebpf.LoadCollectionSpec: %w", err)
	}

	tmpMap, ok := spec.Maps["glob_temp_maps"]
	if !ok {
		return false, fmt.Errorf("runEbpfGlob: failed to find map 'glob_temp_maps' in spec")
	}

	// resize "glob_temp_maps"
	tmpMap.MaxEntries = 2 * uint32(bpf.GetNumPossibleCPUs())

	col, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{})
	if err != nil {
		return false, fmt.Errorf("runEbpfGlob: ebpf.NewCollectionWithOptions: %w", err)
	}
	defer col.Close()

	strMap, ok := col.Maps["tg_string_map"]
	if !ok {
		return false, fmt.Errorf("runEbpfGlob: failed to find map 'tg_string_map' in collection")
	}

	patternMap, ok := col.Maps["tg_pattern_map"]
	if !ok {
		return false, fmt.Errorf("runEbpfGlob: failed to find map 'tg_pattern_map' in collection")
	}

	tmpBufferMap, ok := col.Maps["glob_temp_maps"]
	if !ok {
		return false, fmt.Errorf("runEbpfGlob: failed to find map 'glob_temp_maps' in collection")
	}

	prog, ok := col.Programs["security_file_fcntl"]
	if !ok {
		return false, fmt.Errorf("runEbpfGlob: failed to find program 'security_file_fcntl' in collection")
	}

	file, err := os.CreateTemp("", "tetragon-lsm-check-*")
	if err != nil {
		return false, fmt.Errorf("runEbpfGlob: os.CreateTemp: %w", err)
	}
	defer os.Remove(file.Name())

	var zero uint32
	s := StrVal{
		Res: 100,
	}

	copy(s.Path[:], str)
	s.Len = uint32(len(str))
	if err := strMap.Put(zero, s); err != nil {
		return false, fmt.Errorf("runEbpfGlob: strMap.Put: %w", err)
	}

	for i := range 2 * bpf.GetNumPossibleCPUs() {
		innerName := fmt.Sprintf("glob_inner_%d", i)
		innerSpec := &ebpf.MapSpec{
			Name:       innerName,
			Type:       ebpf.Hash,
			KeySize:    4,
			ValueSize:  4,
			MaxEntries: 128,
		}
		innerMap, err := ebpf.NewMapWithOptions(innerSpec, ebpf.MapOptions{})
		if err != nil {
			return false, fmt.Errorf("runEbpfGlob: ebpf.NewMapWithOptions: innerMap %s err: %w", innerName, err)
		}
		defer innerMap.Close()

		if err := tmpBufferMap.Update(uint32(i), uint32(innerMap.FD()), 0); err != nil {
			return false, fmt.Errorf("runEbpfGlob: tmpBufferMap.Update: innerMap %s err: %w", innerName, err)
		}
	}

	f, err := fm.CompileGlob(pattern)
	if err != nil {
		return false, fmt.Errorf("runEbpfGlob: CompileGlob: %w", err)
	}

	for i, s := range f.GetStates() {
		idx := uint32(i)
		if err := patternMap.Put(idx, s); err != nil {
			return false, fmt.Errorf("runEbpfGlob: patternMap.Put: %w", err)
		}
	}

	link, err := link.AttachLSM(link.LSMOptions{Program: prog})
	if err != nil {
		return false, fmt.Errorf("runEbpfGlob: %w", err)
	}
	defer link.Close()

	unix.FcntlInt(file.Fd(), 9999, 8888)

	var strOut StrVal
	if err := strMap.Lookup(zero, &strOut); err != nil {
		return false, fmt.Errorf("runEbpfGlob: strMap.Lookup: %w", err)
	}

	if strOut.Res != 1 && strOut.Res != 0 {
		return false, fmt.Errorf("runEbpfGlob: Error in eBPF: %d", strOut.Res)
	}

	return strOut.Res == 1, nil
}

func TestGlobFSMeBPF(t *testing.T) {
	if !utils.SupportFmodRet() || !utils.SupportLSM() || (probeBpfLoop() != nil) || (probeForEachMapElem() != nil) {
		t.Skip("File monitoring patterns with FileSystemType type requires fmod_ret and lsm programs")
	}

	for _, c := range fm.GlobTestCases {
		res, err := runEbpfGlob(t, c.Pattern, c.Path)
		assert.Equal(t, err, nil, "%w", err)
		if err == nil {
			assert.Equal(t, c.Match, res, "pattern: %s path: %s", c.Pattern, c.Path)
		}
	}
}

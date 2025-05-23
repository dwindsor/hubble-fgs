//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

//go:build !windows

package file

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"sync"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/tetragon/api/v1/tetragon"
	ossBTF "github.com/cilium/tetragon/pkg/btf"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/isovalent/hubble-fgs/pkg/api/fileapi"
	fm "github.com/isovalent/hubble-fgs/pkg/sensors/file/utils"
	"github.com/isovalent/hubble-fgs/pkg/sensors/utils"
)

var probeImaFileHashHelper = sync.OnceValue(func() error {
	return _probeProg("probe_bpf_ima_file_hash.o", "bprm_check", func(prog *ebpf.Program) (link.Link, error) {
		return link.AttachLSM(link.LSMOptions{Program: prog})
	})
})
var probeImaEnabled = sync.OnceValues(func() (string, error) {
	return ProbeImaEnabledAlgo(option.Config.HubbleLib, "/bin/true")
})
var probeDpathSecurityFilePermission = sync.OnceValue(func() error {
	return _probeProg("probe_security_file_permission.o", "fmod_security_file_permission", func(prog *ebpf.Program) (link.Link, error) {
		return link.AttachTracing(link.TracingOptions{Program: prog})
	})
})
var probeDpathSecurityPathTruncate = sync.OnceValue(func() error {
	return _probeProg("probe_security_path_truncate.o", "lsm_security_path_truncate", func(prog *ebpf.Program) (link.Link, error) {
		return link.AttachLSM(link.LSMOptions{Program: prog})
	})
})
var probeDpathSecurityFileOpen = sync.OnceValue(func() error {
	return _probeProg("probe_security_file_open.o", "lsm_security_file_open", func(prog *ebpf.Program) (link.Link, error) {
		return link.AttachLSM(link.LSMOptions{Program: prog})
	})
})
var probeDpathSecurityKernelReadFile = sync.OnceValue(func() error {
	return _probeProg("probe_security_kernel_read_file.o", "lsm_security_kernel_read_file", func(prog *ebpf.Program) (link.Link, error) {
		return link.AttachLSM(link.LSMOptions{Program: prog})
	})
})
var probeBpfLoop = sync.OnceValue(func() error {
	return _probeProg("probe_bpf_loop.o", "lsm_security_file_open", func(prog *ebpf.Program) (link.Link, error) {
		return link.AttachLSM(link.LSMOptions{Program: prog})
	})
})
var probeForEachMapElem = sync.OnceValue(func() error {
	return _probeProg("probe_for_each_map_elem.o", "lsm_security_file_open", func(prog *ebpf.Program) (link.Link, error) {
		return link.AttachLSM(link.LSMOptions{Program: prog})
	})
})

func SupportDigests() bool {
	// In order to support digests we need 2 things:
	// 1. The kernel supports LSM programs and has them enabled.
	// 2. The kernel supports the IMA file hash helper
	return utils.SupportLSM() && (probeImaFileHashHelper() == nil)
}

func probeOverlayModule() *btf.Spec {
	spec, err := ossBTF.NewBTF()
	if err != nil {
		return nil
	}

	// We check for struct ovl_entry in the BTF and set this variable.
	var fnType *btf.Struct
	hasOverlaySymbols := (spec.TypeByName("ovl_entry", &fnType) == nil)
	if hasOverlaySymbols {
		logger.GetLogger().Info("btf: Already contains symbols from overlay kmod")
		return nil
	}

	allTypes := []btf.Type{}

	iter := spec.Iterate()
	for iter.Next() {
		allTypes = append(allTypes, iter.Type)
	}

	ovlSpec, err := btf.LoadKernelModuleSpec("overlay")
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			logger.GetLogger().Info("btf: Overlay kmod does not exist. Skipping")
		} else {
			logger.GetLogger().WithError(err).WithField("func", "btf.LoadKernelModuleSpec").Warn("btf: Failed to load symbols from overlay kmod")
		}
		return nil
	}

	iter = ovlSpec.Iterate()
	for iter.Next() {
		allTypes = append(allTypes, iter.Type)
	}

	b, err := btf.NewBuilder(allTypes)
	if err != nil {
		logger.GetLogger().WithError(err).WithField("func", "btf.NewBuilder").Warn("btf: Failed to load symbols from overlay kmod")
		return nil
	}

	raw, err := b.Marshal(nil, nil)
	if err != nil {
		logger.GetLogger().WithError(err).WithField("func", "b.Marshal").Warn("btf: Failed to load symbols from overlay kmod")
		return nil
	}

	mergedSpec, err := btf.LoadSpecFromReader(bytes.NewReader(raw))
	if err != nil {
		logger.GetLogger().WithError(err).WithField("func", "btf.LoadSpecFromReader").Warn("btf: Failed to load symbols from overlay kmod")
		return nil
	}

	logger.GetLogger().Info("btf: Successfully loaded symbols from overlay kmod")
	return mergedSpec
}

func _probeProg(objFile, progName string, lnkFn func(prog *ebpf.Program) (link.Link, error)) error {
	objPath := path.Join(option.Config.HubbleLib, objFile)
	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return err
	}

	col, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{})
	if err != nil {
		return err
	}
	defer col.Close()

	prog, ok := col.Programs[progName]
	if !ok {
		return fmt.Errorf("%s not in collection", progName)
	}

	link, err := lnkFn(prog)
	if err != nil {
		return err
	}
	defer link.Close()

	return nil
}

// This function check if IMA is enabled and works in the context of eBPF. First it checks if
// the kernel supports bpf_ima_file_hash helper and then it compares its return value with the
// Go implementation to get the hash of an executable. This is done by executing the executable
// that provided in the arguments. It also returns the name of the algorithm that the kernel is
// configured to use (i.e. ima_hash= kernel command line parameter).
//
// Arguments:
// objDir: directory that contains all the eBPF object files
// exePath: path to the executable to get the hash from
// exeArgs: arguments to pass to the executable (if needed)
//
// Returns:
// string: the name of the algorithm that the kernel is configured to use (valid if error is nil)
// error: if any error occurs
//
// In contrast with the other probe functions in this file this function is exported as it
// it also used by tetra to probe support in machines that do not run FIM yet.
func ProbeImaEnabledAlgo(objDir string, exePath string, exeArgs ...string) (string, error) {
	objPath := path.Join(objDir, "probe_bpf_ima_file_hash.o")
	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return "", fmt.Errorf("checkLSMHooks: ebpf.LoadCollectionSpec: %w", err)
	}

	col, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{})
	if err != nil {
		return "", fmt.Errorf("checkLSMHooks: ebpf.NewCollectionWithOptions: %w", err)
	}
	defer col.Close()

	filterMap, ok := col.Maps["probe_digests_map"]
	if !ok {
		return "", fmt.Errorf("checkLSMHooks: probe_digests_map map not in collection")
	}

	prog, ok := col.Programs["bprm_check"]
	if !ok {
		return "", fmt.Errorf("checkLSMHooks: bprm_check program not in collection")
	}

	fullExecPath, err := exec.LookPath(exePath)
	if err != nil {
		return "", fmt.Errorf("checkLSMHooks: exec.LookPath: %w", err)
	}

	fileinfo, err := os.Stat(fullExecPath)
	if err != nil {
		return "", fmt.Errorf("checkLSMHooks: os.Stat: %w", err)
	}

	stat, ok := fileinfo.Sys().(*syscall.Stat_t)
	if !ok {
		return "", fmt.Errorf("checkLSMHooks: fileinfo.Sys() is not syscall.Stat_t type")
	}

	key := fileapi.InodeKey{
		Ino:      stat.Ino,
		DevMajor: fm.GetDevMajor(stat.Dev),
		DevMinor: fm.GetDevMinor(stat.Dev),
	}
	var val fileapi.DigestKey
	if err := filterMap.Put(key, val); err != nil {
		return "", fmt.Errorf("checkLSMHooks: filterMap.Put: %w", err)
	}

	link, err := link.AttachLSM(link.LSMOptions{Program: prog})
	if err != nil {
		return "", fmt.Errorf("checkLSMHooks: link.AttachLSM: %w", err)
	}
	defer link.Close()

	if err := exec.Command(fullExecPath, exeArgs...).Run(); err != nil {
		return "", fmt.Errorf("checkLSMHooks: exec.Command: %w", err)
	}

	var valOut fileapi.DigestKey
	if err := filterMap.Lookup(key, &valOut); err != nil {
		return "", fmt.Errorf("checkLSMHooks: filterMap.Lookup: %w", err)
	}

	if valOut.Algo < 0 {
		return "", fmt.Errorf("checkLSMHooks: bpf_ima_file_hash helper returned error: %d", valOut.Algo)
	}

	digestLen := fm.IMA_MAX_DIGEST_SIZE
	if dlen, ok := fm.HashAlgoLen[tetragon.DigestAlgo(valOut.Algo)]; ok {
		digestLen = dlen
	}

	algo, ok := tetragon.DigestAlgo_name[valOut.Algo]
	if !ok {
		return "", fmt.Errorf("checkLSMHooks: Unsupported digest algo: %d", valOut.Algo)
	}

	eBPFHash := fmt.Sprintf("%x", valOut.Digest[:digestLen])

	f, err := os.Open(fullExecPath)
	if err != nil {
		return "", fmt.Errorf("checkLSMHooks: os.Open: %w", err)
	}
	defer f.Close()

	h, err := fm.GetHashAlgo(valOut.Algo)
	if err != nil {
		return "", fmt.Errorf("checkLSMHooks: fm.GetHashAlgo: %w", err)
	}

	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("checkLSMHooks: io.Copy: %w", err)
	}
	goHash := fmt.Sprintf("%x", h.Sum(nil))

	if eBPFHash != goHash {
		return "", fmt.Errorf("checkLSMHooks: Go and eBPF digest mismatch %s, %s", eBPFHash, goHash)
	}

	return algo, nil
}

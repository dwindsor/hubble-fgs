//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package file

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	ossBTF "github.com/cilium/tetragon/pkg/btf"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/isovalent/hubble-fgs/pkg/sensors/utils"
	"golang.org/x/sys/unix"
)

var probeImaFileHashHelper = sync.OnceValue(_probeImaFileHashHelper)
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

//	int BPF_PROG(bprm_check, struct linux_binprm *bprm) {
//	    __u64 data;
//	    bpf_ima_file_hash(bprm->file, &data, sizeof(__u64));
//	    return 0;
//	}
//
// Binary code for the previous program
var testImaFileHashHelper = []byte{
	0x79, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // r1 = *(u64 *)(r1 + 0)
	0x79, 0x11, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // r1 = *(u64 *)(r1 + 64)
	0xbf, 0xa2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // r2 = r10
	0x07, 0x02, 0x00, 0x00, 0xf8, 0xff, 0xff, 0xff, // r2 += -8
	0xb7, 0x03, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, // r3 = 8
	0x85, 0x00, 0x00, 0x00, 0xc1, 0x00, 0x00, 0x00, // call 193
	0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // r0 = 0
	0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exit
}

func _probeImaFileHashHelper() error {
	r := bytes.NewReader(testImaFileHashHelper)

	var insns asm.Instructions
	if err := insns.Unmarshal(r, binary.LittleEndian); err != nil {
		return fmt.Errorf("probeImaFileHashHelper: Cannot Unmarshal instructions: %w", err)
	}

	spec := &ebpf.ProgramSpec{
		Type:         ebpf.LSM,
		AttachType:   ebpf.AttachLSMMac,
		AttachTo:     "bprm_creds_for_exec",
		License:      "GPL",
		Flags:        unix.BPF_F_SLEEPABLE,
		Instructions: insns,
	}

	var prog *ebpf.Program
	var lnk link.Link
	var err error
	prog, err = ebpf.NewProgramWithOptions(spec, ebpf.ProgramOptions{
		LogDisabled: true,
	})
	if err == nil {
		if lnk, err = link.AttachLSM(link.LSMOptions{Program: prog}); err == nil {
			lnk.Close()
		}
		prog.Close()
	}
	return err
}

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

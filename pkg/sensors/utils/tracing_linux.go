// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package utils

import (
	"fmt"
	"os"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/tetragon/pkg/config"
	"golang.org/x/sys/unix"
)

var probeLSM = sync.OnceValue(_probeLSM)
var probeTracingModifyReturn = sync.OnceValue(_probeTracingModifyReturn)
var probeTracingFentry = sync.OnceValue(_probeTracingFentry)

// This function checks if the kernel supports LSM programs and has them enabled.
//
// Before that, we check if the kernel supports LSM programs. Then we use
// "/sys/kernel/security/lsm" to check if LSM is enabled (i.e. this file
// contents contain "bpf" string). The issue with this approach is that we need
// to ask for the users of tetragon to map "/sys/kernel/security/"" inside the
// Tetragon pod. This may arise security concerns.
//
// Using this function, we load a simple LSM program, link that, and run a
// command to call the LSM program. If the LSM program is called, we update a
// map value and then we know that the kernel supports LSM programs and has
// them enabled. To do so, we use a hook into file_fcntl and we do a fcntl
// syscall with some random values. There is no need to check the arguments
// or the inode number in the LSM program as any call to that would be enough
// to show us that we have LSM programs enabled.
//
// Finally, we use sync.OnceValue to ensure that we only call this function once
// and minimise the overheads of calling it.
func _probeLSM() error {
	objPath, err := config.FindProgramFile("bpf_lsm_check.o")
	if err != nil {
		return fmt.Errorf("checkLSMHooks: %w", err)
	}
	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return fmt.Errorf("checkLSMHooks: %w", err)
	}

	col, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{})
	if err != nil {
		return fmt.Errorf("checkLSMHooks: %w", err)
	}
	defer col.Close()

	filterMap, ok := col.Maps["tg_fnctl_map"]
	if !ok {
		return fmt.Errorf("checkLSMHooks: tg_fnctl_map not in collection")
	}

	prog, ok := col.Programs["security_file_fcntl"]
	if !ok {
		return fmt.Errorf("checkLSMHooks: security_file_fcntl not in collection")
	}

	file, err := os.CreateTemp("", "tetragon-lsm-check-*")
	if err != nil {
		return fmt.Errorf("checkLSMHooks: %w", err)
	}
	defer os.Remove(file.Name())

	var zero uint32
	var calls uint64
	if err := filterMap.Put(zero, calls); err != nil {
		return fmt.Errorf("checkLSMHooks: %w", err)
	}

	link, err := link.AttachLSM(link.LSMOptions{Program: prog})
	if err != nil {
		return fmt.Errorf("checkLSMHooks: %w", err)
	}
	defer link.Close()

	unix.FcntlInt(file.Fd(), 9999, 8888)

	var callsOut uint64
	if err := filterMap.Lookup(zero, &callsOut); err != nil {
		return fmt.Errorf("checkLSMHooks: %w", err)
	}

	if callsOut == 0 {
		return fmt.Errorf("checkLSMHooks: Number of calls is not > 0 [%d]", callsOut)
	}
	return nil
}

// This function checks if the kernel supports fmod_ret programs.
//
// There are two things to check it. First, we need to check if the kernel
// supports loading fmod_ret (tracing) programs. Then we need to check if
// we can link them. Using cilium/ebpf features.HaveProgramType(ebpf.Tracing)
// is not enough as it only checks if the kernel supports loading tracing
// programs. We have seen a case in arm64 where the kernel supports loading
// tracing programs but it does not support linking them.
func _probeTracingModifyReturn() error {
	return _probeTracing(ebpf.AttachModifyReturn)
}

func _probeTracingFentry() error {
	return _probeTracing(ebpf.AttachTraceFEntry)
}

func _probeTracing(attachType ebpf.AttachType) error {
	spec := &ebpf.ProgramSpec{
		Type:       ebpf.Tracing,
		AttachType: attachType,
		AttachTo:   "security_file_mprotect",
		License:    "GPL",
		Instructions: asm.Instructions{
			asm.LoadImm(asm.R0, 0, asm.DWord),
			asm.Return(),
		},
	}

	var prog *ebpf.Program
	var lnk link.Link
	var err error
	prog, err = ebpf.NewProgramWithOptions(spec, ebpf.ProgramOptions{
		LogDisabled: true,
	})
	if err == nil {
		if lnk, err = link.AttachTracing(link.TracingOptions{Program: prog}); err == nil {
			lnk.Close()
		}
		prog.Close()
	}
	return err
}

func SupportEnforcement() bool {
	// In order to support enforcement we need one out of these two things:
	// 1. The kernel supports LSM programs and has them enabled.
	// 2. The kernel supports the fmod_ret tracing program type.
	return (probeTracingModifyReturn() == nil) || (probeLSM() == nil)
}

func SupportFentry() bool {
	return probeTracingFentry() == nil
}

func SupportFmodRet() bool {
	return probeTracingModifyReturn() == nil
}

func SupportLSM() bool {
	return probeLSM() == nil
}

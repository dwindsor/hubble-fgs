//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package utils

import (
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/option"
)

var (
	checkCGroupSKBAvailable = sync.OnceValue(_checkCGroupSKBAvailable)
	checkCGroupSKBProbeRead = sync.OnceValue(_checkCGroupSKBProbeRead)
	checkAddAndFetch        = sync.OnceValue(_checkAddAndFetch)
	checkCurrentTaskBTF     = sync.OnceValue(_checkCurrentTaskBTF)
	checkRawHooksAvailable  = sync.OnceValue(_checkRawHooksAvailable)
)

// SkSkbParserRequired returns whether the underlying kernel requires skskb
// parsing.
func SkSkbParserRequired() bool {
	// The skskb parser is only needed on 5.10 and earlier kernels.
	// After 5.10 we can run with only the skskb verdict programs
	// improving performance.
	return !kernels.MinKernelVersion("5.10.0")
}

func EnableV511Progs() bool {
	if option.Config.ForceSmallProgs {
		return false
	}
	kernelVer, _, _ := kernels.GetKernelVersion(option.Config.KernelVersion, option.Config.ProcFS)
	return (int64(kernelVer) >= kernels.KernelStringToNumeric("5.11.0"))
}

// CGRoupSKBAvailable checks if the kernel supports CGroup/SKB programs, has support for large programs,
// and the CGroup/SKB programs have the perf_event_output helper.
func CGroupSKBAvailable() bool {
	return checkCGroupSKBAvailable()
}

func _checkCGroupSKBAvailable() bool {
	err := features.HaveProgramType(ebpf.CGroupSKB)
	if err != nil {
		return false
	}
	err = features.HaveLargeInstructions()
	if err != nil {
		return false
	}
	err = features.HaveProgramHelper(ebpf.CGroupSKB, asm.FnPerfEventOutput)
	return err == nil
}

// SupportCGroupSKBProbeRead checks if the kernel supports the probe_read helper on CGroup/SKB programs.
func SupportCGroupSKBProbeRead() bool {
	return checkCGroupSKBProbeRead()
}

func _checkCGroupSKBProbeRead() bool {
	err := features.HaveProgramHelper(ebpf.CGroupSKB, asm.FnProbeReadKernel)
	return err == nil
}

// SupportAddAndFetch checks if the kernel supports the add_and_fetch instruction.
func SupportAddAndFetch() bool {
	err := checkAddAndFetch()
	return err == nil
}

func _checkAddAndFetch() error {
	// c/ebpf doesn't support setting offsets or constants directly in the helper, so use the helper
	// to create the instruction and then add the offset and constant after.
	addAndFetchInsn := asm.StoreXAdd(asm.R10, asm.R2, asm.DWord)
	addAndFetchInsn.Offset = -8
	addAndFetchInsn.Constant = 1
	spec := &ebpf.ProgramSpec{
		Type:       ebpf.Kprobe,
		AttachType: ebpf.AttachNone,
		AttachTo:   "tcp_connect",
		License:    "GPL",
		Instructions: asm.Instructions{
			asm.LoadImm(asm.R1, 0, asm.DWord),
			asm.LoadImm(asm.R2, 1, asm.DWord),
			asm.StoreMem(asm.R10, -8, asm.R1, asm.DWord),
			addAndFetchInsn,
			asm.LoadImm(asm.R0, 0, asm.DWord),
			asm.Return(),
		},
	}

	var prog *ebpf.Program
	var lnk link.Link
	var err error
	prog, err = ebpf.NewProgramWithOptions(spec, ebpf.ProgramOptions{
		LogDisabled: false,
	})
	if err == nil {
		if lnk, err = link.Kprobe(spec.AttachTo, prog, nil); err == nil {
			lnk.Close()
		}
		prog.Close()
	}
	return err
}

// SupportCurrentTaskBTF checks if the kernel supports the get_current_task_btf helper in CGroup/SKB
func SupportCurrentTaskBTF() bool {
	return checkCurrentTaskBTF()
}

func _checkCurrentTaskBTF() bool {
	err := features.HaveProgramType(ebpf.CGroupSKB)
	if err != nil {
		return false
	}
	err = features.HaveLargeInstructions()
	if err != nil {
		return false
	}
	err = features.HaveProgramHelper(ebpf.CGroupSKB, asm.FnGetCurrentTaskBtf)
	return err == nil
}

// SupportProcessTree checks if the kernel supports the right programs, instructions and helpers to
// allow the process tree functionality to work.
func SupportProcessTree() bool {
	return SupportAddAndFetch() && SupportCurrentTaskBTF()
}

func checkForHook(hook string) error {
	spec := &ebpf.ProgramSpec{
		Type:       ebpf.Kprobe,
		AttachType: ebpf.AttachNone,
		AttachTo:   hook,
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
		LogDisabled: false,
	})
	if err == nil {
		if lnk, err = link.Kprobe(spec.AttachTo, prog, nil); err == nil {
			lnk.Close()
		}
		prog.Close()
	}
	return err
}

// RawHooksAvailable checks if the two hooks we use for raw sockets are available.
func RawHooksAvailable() bool {
	return checkRawHooksAvailable()
}

func _checkRawHooksAvailable() bool {
	err := checkForHook("raw_sk_init")
	if err != nil {
		return false
	}
	err = checkForHook("rawv6_init_sk")
	return err == nil
}

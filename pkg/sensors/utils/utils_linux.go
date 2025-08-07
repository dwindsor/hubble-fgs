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
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/tetragon/pkg/defaults"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/option"
)

var (
	checkCGroupSKBAvailable  = sync.OnceValue(_checkCGroupSKBAvailable)
	checkCGroupSKBProbeRead  = sync.OnceValue(_checkCGroupSKBProbeRead)
	checkAddAndFetch         = sync.OnceValue(_checkAddAndFetch)
	checkCurrentTaskBTF      = sync.OnceValue(_checkCurrentTaskBTF)
	checkFuncByFuncVerif     = sync.OnceValue(_checkFuncByFuncVerif)
	checkGlobalFuncPtrArgs   = sync.OnceValue(_checkGlobalFuncPtrArgs)
	checkRawHooksAvailable   = sync.OnceValue(_checkRawHooksAvailable)
	checkRTTHookAvailable    = sync.OnceValue(_checkRTTHookAvailable)
	checkUDPBindNeedsDummies = sync.OnceValue(_checkUDPBindNeedsDummies)
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
	addAndFetchInsn.Constant = 1 // set BPF_FETCH bit
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
	return SupportAddAndFetch() && SupportCurrentTaskBTF() && SupportGlobalFuncPtrArgs()
}

// SupportFuncByFuncVerif checks if the kernel supports function-by-function verification
func SupportFuncByFuncVerif() bool {
	err := checkFuncByFuncVerif()
	return err == nil
}

func _checkFuncByFuncVerif() error {
	u32 := &btf.Int{Name: "u32", Size: 4, Encoding: btf.Unsigned}
	proto := &btf.FuncProto{Return: u32}
	fn := &btf.Func{Name: "f", Type: proto, Linkage: btf.GlobalFunc}

	builder, err := btf.NewBuilder([]btf.Type{u32, proto, fn})
	if err != nil {
		return err
	}
	raw, err := builder.Marshal(nil, nil)
	if err != nil {
		return err
	}

	// Verifier will complain "load btf: invalid argument: [3] FUNC f ...
	// ... type_id=2 vlen != 0" if functionality doesn't exist
	h, err := btf.NewHandleFromRawBTF(raw)
	if h != nil {
		h.Close()
	}

	return err
}

// SupportGlobalFuncPtrArgs checks if the kernel supports the passing pointer arguments to global eBPF functions
func SupportGlobalFuncPtrArgs() bool {
	err := checkGlobalFuncPtrArgs()
	return err == nil
}

func _checkGlobalFuncPtrArgs() error {
	// BTF could not distinguish between static and global funcs prior to
	// the function-by-function verification implementation, so that check
	// is a pre-requisite for this one
	if err := checkFuncByFuncVerif(); err != nil {
		return err
	}

	u32 := &btf.Int{Name: "u32", Size: 4, Encoding: btf.Unsigned}

	staticFn := &btf.Func{
		Name: "_",
		Type: &btf.FuncProto{
			Return: &btf.Int{Size: 16},
			Params: []btf.FuncParam{},
		},
		Linkage: btf.StaticFunc,
	}

	globalFn := &btf.Func{
		Name: "_",
		Type: &btf.FuncProto{
			Return: &btf.Int{Size: 16},
			Params: []btf.FuncParam{
				{Name: "ptr_arg", Type: &btf.Pointer{Target: u32}},
			},
		},
		Linkage: btf.GlobalFunc,
	}

	// Verifier will complain "Arg#0 type PTR in _() is not supported yet"
	// if we can't pass a pointer arg
	ins := asm.Instructions{
		btf.WithFuncMetadata(asm.LoadImm(asm.R0, 0, asm.DWord), staticFn),
		asm.Mov.Reg(asm.R1, 0),
		asm.Call.Label("fn"),
		asm.Return(),
		btf.WithFuncMetadata(asm.LoadImm(asm.R0, 0, asm.DWord), globalFn).WithSymbol("fn"),
		asm.Return(),
	}

	spec := &ebpf.ProgramSpec{
		Type:         ebpf.Kprobe,
		AttachType:   ebpf.AttachNone,
		AttachTo:     "tcp_connect",
		Instructions: ins,
		License:      "GPL",
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
	defer prog.Close()

	return nil
}

// SupportDNSParser checks if the kernel supports the right capabilities to allow the DNS parsing functionality to work.
func SupportDNSParser() bool {
	return SupportAddAndFetch() && SupportFuncByFuncVerif() && SupportGlobalFuncPtrArgs()
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

// RTTHookAvailable checks if the hook we use for RTT observation is available.
func RTTHookAvailable() bool {
	return checkRTTHookAvailable()
}

func _checkRTTHookAvailable() bool {
	err := checkForHook("tcp_ack_update_rtt")
	return err == nil
}

// UDPBindNeedsDummies checks if the kernel requires CGroup programs to be attached to the bind ops
// to trigger running the bind hooks. Returns true in case of errors.
func UDPBindNeedsDummies() bool {
	return checkUDPBindNeedsDummies()
}

func _checkUDPBindNeedsDummies() bool {
	// Map to store our flag. Our hook will set the entry to 1 if it is triggered.
	mapSpec := &ebpf.MapSpec{
		Name:       "tg_bind_probe",
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: 1,
		Pinning:    ebpf.PinByName,
	}
	tempMapDir := filepath.Join(defaults.DefaultMapRoot, "tg_udp_bind_probe")
	opts := ebpf.MapOptions{
		PinPath: tempMapDir,
	}
	os.MkdirAll(tempMapDir, 0700)
	defer os.Remove(tempMapDir)
	m, err := ebpf.NewMapWithOptions(mapSpec, opts)
	if err != nil {
		logger.GetLogger().Debug("UDPBindNeedsDummies failed NewMapWithOptions", logfields.Error, err)
		return true
	}
	defer m.Unpin()
	defer m.Close()

	// Program that sets the map value to 1 when triggered.
	spec := &ebpf.ProgramSpec{
		Type:       ebpf.Kprobe,
		AttachType: ebpf.AttachNone,
		AttachTo:   "__cgroup_bpf_run_filter_sk",
		License:    "GPL",
		Instructions: asm.Instructions{
			// map fd into r1
			asm.LoadMapPtr(asm.R1, m.FD()),

			// 0 into &FP[-4]
			asm.LoadImm(asm.R2, 0, asm.DWord),
			asm.StoreMem(asm.RFP, -4, asm.R2, asm.Word),

			// &FP[-4] into r2
			asm.Mov.Reg(asm.R2, asm.RFP),
			asm.Add.Imm(asm.R2, -4),

			asm.FnMapLookupElem.Call(),

			// NULL ptr, jump to error
			asm.JEq.Imm(asm.R0, 0, "error"),

			// Write a 1 to the map
			asm.Mov.Imm(asm.R1, 1),
			asm.StoreMem(asm.R0, 0, asm.R1, asm.DWord),

			// return 0
			asm.LoadImm(asm.R0, 0, asm.DWord).WithSymbol("error"),
			asm.Return(),
		},
	}
	prog, err := ebpf.NewProgramWithOptions(spec, ebpf.ProgramOptions{
		LogDisabled: false,
	})
	if err != nil {
		logger.GetLogger().Debug("UDPBindNeedsDummies failed NewProgramWithOptions", logfields.Error, err)
		return true
	}
	defer prog.Close()
	lnk, err := link.Kprobe(spec.AttachTo, prog, nil)
	if err != nil {
		logger.GetLogger().Debug("UDPBindNeedsDummies failed link.Kprobe", logfields.Error, err)
		return true
	}
	defer lnk.Close()

	// Bind a UDP socket to trigger the hook. On older kernels (<v5.13 vanilla) __cgroup_bpf_run_filter_sk would
	// be run for every operation. On newer kernels the hook is only hit if a program is bound to an op.
	// syscall.Socket needs a ForkLock. See https://go.dev/src/syscall/exec_unix.go
	syscall.ForkLock.Lock()
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_UDP)
	if err != nil {
		logger.GetLogger().Debug("UDPBindNeedsDummies failed Socket", logfields.Error, err)
		return true
	}
	syscall.ForkLock.Unlock()
	defer syscall.Close(fd)
	sa := syscall.SockaddrInet4{
		Addr: [4]byte{0, 0, 0, 0},
		Port: 13338,
	}
	err = syscall.Bind(fd, &sa)
	if err != nil {
		logger.GetLogger().Debug("UDPBindNeedsDummies failed Bind", logfields.Error, err)
		return true
	}

	// Read the map value.
	zero := uint32(0)
	value := uint64(0)
	err = m.Lookup(zero, &value)
	if err != nil {
		logger.GetLogger().Debug("UDPBindNeedsDummies failed m.Lookup", logfields.Error, err)
		return true
	}

	return value == 0
}

func LogLayer3Features() string {
	// once we have detected all features, flush the BTF spec
	// we cache all values so calling again a Has* function will
	// not load the BTF again
	defer btf.FlushKernelSpec()
	return fmt.Sprintf("packet: %t, packet_mem: %t, add_and_fetch: %t, current_task_btf: %t, process_tree: %t, "+
		"func_by_func_verif: %t, global_func_ptr_args: %t, raw_sockets: %t, RTT_hook: %t, fentry: %t, udp_bind_needs_dummies: %t",
		CGroupSKBAvailable(), SupportCGroupSKBProbeRead(), SupportAddAndFetch(), SupportCurrentTaskBTF(), SupportProcessTree(),
		SupportFuncByFuncVerif(), SupportGlobalFuncPtrArgs(), RawHooksAvailable(), RTTHookAvailable(), SupportFentry(), UDPBindNeedsDummies())
}

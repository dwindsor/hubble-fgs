//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.
//
package observer

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/isovalent/hubble-fgs/pkg/api"
	"github.com/isovalent/hubble-fgs/pkg/bpf"
	"github.com/isovalent/hubble-fgs/pkg/btf"
	"github.com/isovalent/hubble-fgs/pkg/idtable"
	"github.com/isovalent/hubble-fgs/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/isovalent/hubble-fgs/pkg/logger"
	"github.com/isovalent/hubble-fgs/pkg/selectors"

	. "github.com/isovalent/hubble-fgs/pkg/generictypes"
)

const (
	argReturnCopy = -1
)

var (
	// genericKprobeProgs stores dynamic kprobes added/removed from CRD.
	// Kprobes managed from init config file are pushed through
	// observerAllPrograms.
	genericKprobeProgs = map[string]*BpfLoad{}
)

type observerKprobeSensor struct {
	name      string
	probeType string
}

func init() {
	kprobe := &observerKprobeSensor{
		name: "kprobe sensor",
	}
	RegisterProbeType("generic_kprobe", kprobe)
	RegisterTracingSensorsAtInit(kprobe.name, kprobe)
	RegisterEventHandlerAtInit(api.MSG_OP_GENERIC_KPROBE, handleGenericKprobe)
}

const (
	genericFuncArgsEnum = "generic_func_args_enum"

	kprobeGenericId = "func_id"
	arg0            = "arg0"
	arg1            = "arg1"
	arg2            = "arg2"
	arg3            = "arg3"
	arg4            = "arg4"
	arg5            = "arg5"
	argreturn       = "argreturn"
	is_syscall      = "syscall"
	argm0           = "arg0m"
	argm1           = "arg1m"
	argm2           = "arg2m"
	argm3           = "arg3m"
	argm4           = "arg4m"
	argm5           = "arg5m"
)

const (
	CharBufErrorENOMEM      = -1
	CharBufErrorPageFault   = -2
	CharBufErrorTooLarge    = -3
	CharBufSavedForRetprobe = -4
)

func kprobeCharBufErrorToString(e int32) string {
	switch e {
	case CharBufErrorENOMEM:
		return "CharBufErrorENOMEM"
	case CharBufErrorTooLarge:
		return "CharBufErrorBufTooLarge"
	case CharBufErrorPageFault:
		return "CharBufErrorPageFault"
	}
	return "CharBufErrorUnknown"
}

func kprobeArgMToString(a int) string {
	switch a {
	case 0:
		return argm0
	case 1:
		return argm1
	case 2:
		return argm2
	case 3:
		return argm3
	case 4:
		return argm4
	case 5:
		return argm5
	}
	return ""
}

func kprobeArgToString(a int) string {
	switch a {
	case 0:
		return arg0
	case 1:
		return arg1
	case 2:
		return arg2
	case 3:
		return arg3
	case 4:
		return arg4
	case 5:
		return argreturn
	}
	return ""
}

type kprobeLoadArgs struct {
	filters  [4096]byte
	btf      uintptr
	retprobe bool
	syscall  bool
}

type argPrinters struct {
	ty    int
	index int
}

// internal genericKprobe info
type genericKprobe struct {
	loadArgs          kprobeLoadArgs
	argSigPrinters    []argPrinters
	argReturnPrinters []argPrinters
	funcName          string

	// for kprobes that have a retprobe, we maintain the enter events in
	// the map, so that we can merge them when the return event is
	// generated. The envets are maintained in the map below, using
	// ThreadId as the key.
	pendingEvents map[uint64]pendingEvent

	tableId idtable.EntryID
}

// pendingEvent is an event waiting to be merged with another event.
// This is needed for retprobe probes that generate two events: one at the
// function entry, and one at the function return. We merge these events into
// one, before returning it to the user.
type pendingEvent struct {
	ev          *api.MsgGenericKprobeUnix
	returnEvent bool
}

func (g *genericKprobe) getMapDir(mapDir string) string {
	return path.Join(mapDir, fmt.Sprintf("generickprobe_id:%d_fn:%s", g.tableId.ID, g.funcName)) + "/"
}

func (g *genericKprobe) SetID(id idtable.EntryID) {
	g.tableId = id
}

var (
	// genericKprobeTable is a global table that maintains information for generic kprobes
	genericKprobeTable idtable.Table
)

func genericKprobeTableGet(id idtable.EntryID) (*genericKprobe, error) {
	if entry, err := genericKprobeTable.GetEntry(id); err != nil {
		return nil, fmt.Errorf("getting entry from genericKprobeTable failed with: %w", err)
	} else if val, ok := entry.(*genericKprobe); !ok {
		return nil, fmt.Errorf("getting entry from genericKprobeTable failed with: got invalid type: %T (%v)", entry, entry)
	} else {
		return val, nil
	}
}

func genericKprobeFromBpfLoad(l *BpfLoad) (*genericKprobe, error) {
	if id, ok := l.loaderData.(idtable.EntryID); !ok {
		return nil, fmt.Errorf("invalid loadData type: expecting idtable.EntryID and got: %T (%v)", l.loaderData, l.loaderData)
	} else {
		return genericKprobeTableGet(id)
	}
}

var (
	MaxFilterIntArgs = 8
)

const (
	genericKprobeFilterGT  = 1
	genericKprobeFilterLT  = 2
	genericKprobeFilterEQ  = 3
	genericKprobeFilterNEQ = 4
	// PID ops
	genercKprobeFilterIn    = 5
	genercKprobeFilterNotIn = 6
	// String ops
	genericKprobeFilterStringContains = 7
	genericKprobeFilterStringPrefix   = 8
	genericKprobeFilterStringPostfix  = 9
)

func (k *ObserverKprobe) opFilterStrToType(ty string) (int, error) {
	switch ty {
	case "gt":
		return genericKprobeFilterGT, nil
	case "lt":
		return genericKprobeFilterLT, nil
	case "eq":
		return genericKprobeFilterEQ, nil
	case "neq":
		return genericKprobeFilterNEQ, nil
	case "stringcontains":
		return genericKprobeFilterStringContains, nil
	case "stringprefix":
		return genericKprobeFilterStringPrefix, nil
	case "stringpostfix":
		return genericKprobeFilterStringPostfix, nil
	}

	return 0, fmt.Errorf("Unknown op '%s'", ty)
}

func goStringToAscii(s string) []byte {
	r := []rune(s)

	b := make([]byte, len(s))
	for i := 0; i < len(r); i++ {
		b[i] = byte(r[i])
	}
	return b
}

func opFilterStringSupported(op int) bool {
	switch op {
	case genericKprobeFilterEQ,
		genericKprobeFilterStringPrefix,
		genericKprobeFilterStringPostfix:
		return true
	}
	return false
}

func (k *ObserverKprobe) pidFilterValue(value uint32) (int, error) {
	return int(value), nil
}

func (k *ObserverKprobe) kprobeEventFilterWriteBTF(btf bpf.BTF, ty string, op, value int) error {
	retVal := btf.AddEnumValue(ty+"_type", op)
	if retVal < 0 {
		return fmt.Errorf("Error add enum value '%s_type' failed %d", ty, retVal)
	}

	retVal = btf.AddEnumValue(ty+"_value", value)
	if retVal < 0 {
		return fmt.Errorf("Error add enum value '%s_value' failed %d", ty, retVal)
	}
	return nil
}

// hard coded all our restrictions on filters here for now.
func (k *ObserverKprobe) checkFilterRestrictions(ty, opName string, op int) error {
	switch ty {
	case "notpidset":
	case "nspidset":
	case "notnspidset":
		// Its unclear to me what these filters even mean if
		// its not an equality test. For now skip them and
		// we can come back later if they seem useful.
		if op != genericKprobeFilterEQ && op != genericKprobeFilterNEQ {
			return fmt.Errorf("Event filter '%s' op '%s' unsupported for type", ty, opName)
		}
	}
	return nil
}

func getMetaValue(arg *v1alpha1.KProbeArg) int {
	if arg.SizeArgIndex > 0 {
		return int(arg.SizeArgIndex)
	}
	if arg.ReturnCopy {
		return argReturnCopy
	}
	return 0
}

func (k *ObserverKprobe) assignArgFilter(value []byte, filter *api.KprobeArgs, index uint32) {
	switch int(index) {
	case 0:
		filter.Args0 = value
	case 1:
		filter.Args1 = value
	case 2:
		filter.Args2 = value
	case 3:
		filter.Args3 = value
	case 4:
		filter.Args4 = value
	}
}

func pidOpValue(p v1alpha1.PIDSelector) (uint32, error) {
	return 0, nil
}

func pidFlagValue(p v1alpha1.PIDSelector) (uint32, error) {
	return 0, nil
}

func pidValue(p v1alpha1.PIDSelector) ([]byte, uint32, error) {
	var value []byte

	return value, 0, nil
}

func argIndexValue(a v1alpha1.ArgSelector) (uint32, error) {
	return 0, nil
}

func argOpValue(a v1alpha1.ArgSelector) (uint32, error) {
	return 0, nil
}

func argValue(a v1alpha1.ArgSelector) ([]byte, uint32, error) {
	var value []byte

	return value, 0, nil
}

func addGenericKprobeSensors(kprobes []v1alpha1.KProbeSpec, btfBaseFile string) (*ObserverSensor, error) {
	var progs []*BpfLoad

	btfobj := bpf.BTFNil
	defer func() {
		// if we return early due to an error, make sure that we don't leak the BTF object
		if btfobj != bpf.BTFNil {
			btfobj.Close()
		}
	}()

	for i := range kprobes {
		f := &kprobes[i]
		var argSigPrinters []argPrinters
		var argReturnPrinters []argPrinters
		var setRetprobe, is_syscall bool
		var argRetprobe *v1alpha1.KProbeArg
		var argsBTFSet [api.MaxArgsSupported]bool

		argRetprobe = nil // holds pointer to arg for return handler
		funcName := f.Call

		// Write args into BTF ptr for use with load
		var err error
		btfobj, err = btf.NewBTF()
		if err != nil {
			return nil, err
		}
		ret := btfobj.AddEnum(genericFuncArgsEnum, 4)
		if ret < 0 {
			return nil, fmt.Errorf("Error add enum args (%s) failed %d", genericFuncArgsEnum, ret)
		}

		if err := btf.ValidateKprobeSpec(btfobj, f); err != nil {
			if warn, ok := err.(*btf.ValidationWarn); ok {
				logger.GetLogger().Warnf("kprobe spec validation: %s", warn)
			} else {
				logger.GetLogger().Warnf("invalid or old kprobe spec: %w", err)
			}
		}

		// Parse Arguments
		for j, a := range f.Args {
			argType := GenericTypeFromString(a.Type)
			if argType == GenericInvalidType {
				return nil, fmt.Errorf("Arg(%d) type '%s' unsupported\n", j, a.Type)
			}
			argMValue := getMetaValue(&a)
			if argMValue == argReturnCopy {
				argRetprobe = &f.Args[j]
			}
			retVal := btfobj.AddEnumValue(kprobeArgToString(int(a.Index)), argType)
			if retVal < 0 {
				return nil,
					fmt.Errorf("Error add arg: ArgType %s Index %d failed %d",
						a.Type, int(a.Index), retVal)
			}
			retVal = btfobj.AddEnumValue(kprobeArgMToString(int(a.Index)), argMValue)
			if retVal < 0 {
				return nil, fmt.Errorf("Error add enum value '%s' failed %d", kprobeArgMToString(int(a.Index)), retVal)
			}

			argsBTFSet[a.Index] = true
			argP := argPrinters{index: j, ty: argType}
			argSigPrinters = append(argSigPrinters, argP)
		}

		// Parse ReturnArg, we have two types of return arg parsing. We
		// support populating a kprobe buffer from kretprobe hooks. This
		// is used to capture data that is populated by the function hoooked.
		// For example Read calls supply a buffer to the syscall, but we
		// wont have its contents until kretprobe is run. The other type is
		// the f.Return case. These capture the return value of the function
		// without context from the kprobe hook. The BTF argument 'argreturn'
		// instructs the BPF kretprobe program which type of copy to use. And
		// argReturnPrinters tell golang printer piece how to print the event.
		if f.Return {
			argType := GenericTypeFromString(f.ReturnArg.Type)
			if argType == GenericInvalidType {
				if f.ReturnArg.Type == "" {
					return nil, fmt.Errorf("ReturnArg not specified with Return=true.")
				}
				return nil, fmt.Errorf("ReturnArg type '%s' unsupported", f.ReturnArg.Type)
			}
			retVal := btfobj.AddEnumValue(argreturn, argType)
			if retVal < 0 {
				return nil, fmt.Errorf("Error add enum value '%s'='%d' failed %d\n", argreturn, argType, retVal)
			}
			argsBTFSet[api.ReturnArgIndex] = true
			argP := argPrinters{index: api.ReturnArgIndex, ty: argType}
			argReturnPrinters = append(argReturnPrinters, argP)
		} else if argRetprobe != nil {
			retVal := btfobj.AddEnumValue(argreturn, 0)
			if retVal < 0 {
				return nil, fmt.Errorf("Error add enum value '%s'='0' failed %d\n", argreturn, retVal)
			}
			argsBTFSet[api.ReturnArgIndex] = true
			setRetprobe = true

			argType := GenericTypeFromString(argRetprobe.Type)
			argP := argPrinters{index: int(argRetprobe.Index), ty: argType}
			argReturnPrinters = append(argReturnPrinters, argP)
		}

		// Mark remaining arguments as 'nops' the kernel side will skip
		// copying 'nop' args.
		for j, a := range argsBTFSet {
			if a == false {
				retVal := btfobj.AddEnumValue(kprobeArgToString(j), GenericNopType)
				if retVal < 0 {
					return nil, fmt.Errorf("Error add enum value '%s' failed %d",
						kprobeArgToString(j), retVal)
				}
				retVal = btfobj.AddEnumValue(kprobeArgMToString(j), 0)
				if retVal < 0 {
					return nil, fmt.Errorf("Error add enum value '%s' failed %d",
						kprobeArgToString(j), retVal)
				}
			}
		}

		// Parse Filters into kernel filter logic
		kernelSelectors, err := selectors.InitKernelSelectors(f)
		if err != nil {
			return nil, err
		}

		// Write attributes into BTF ptr for use with load
		is_syscall = f.Syscall
		if !setRetprobe {
			setRetprobe = f.Return
		}

		if is_syscall {
			retVal := btfobj.AddEnumValue("syscall", 1)
			if retVal < 0 {
				return nil, fmt.Errorf("Error add enum value 'syscall = 1' failed %d", retVal)
			}
		} else {
			retVal := btfobj.AddEnumValue("syscall", 0)
			if retVal < 0 {
				return nil, fmt.Errorf("Error add enum value 'syscall = 0' failed %d", retVal)
			}
		}

		has_sigkill := selectors.MatchActionSigKill(f)
		if has_sigkill {
			retVal := btfobj.AddEnumValue("sigkill", 1)
			if retVal < 0 {
				return nil, fmt.Errorf("Error add enum value 'sigkill = 1' failed %d", retVal)
			}
		} else {
			retVal := btfobj.AddEnumValue("sigkill", 0)
			if retVal < 0 {
				return nil, fmt.Errorf("Error add enum value 'sigkill = 0' failed %d", retVal)
			}
		}

		// create a new entry on the table, and pass its id to BPF-side
		// so that we can do the matching at event-generation time
		kprobeEntry := genericKprobe{
			loadArgs: kprobeLoadArgs{
				filters:  kernelSelectors,
				btf:      uintptr(btfobj),
				retprobe: setRetprobe,
				syscall:  is_syscall,
			},
			argSigPrinters:    argSigPrinters,
			argReturnPrinters: argReturnPrinters,
			funcName:          funcName,
			pendingEvents:     map[uint64]pendingEvent{},
			tableId:           idtable.UninitializedEntryID,
		}
		genericKprobeTable.AddEntry(&kprobeEntry)
		ret = btfobj.AddEnumValue(kprobeGenericId, kprobeEntry.tableId.ID)
		if ret < 0 {
			genericKprobeTable.RemoveEntry(kprobeEntry.tableId)
			return nil, fmt.Errorf("Error add enum value failed %d", ret)
		}

		// NB(kkourt): after we insert the kprobeEntry to the global table
		// (genericKprobeTable), the btf object will need to be released when we remove the
		// entry from the table. We set btfobj to nil to indicate this.
		//
		// Currently, however, we do not remove entries from the global table.
		//
		// Removal is done in the sensor controller goroutine.  One option would be to
		// add a sensorRemove method in the observerSensorImpl, so that each sensor does its
		// own cleanup. Note that in that case, we would need to synchronize access to the
		// table because sensorRemove would be called from the sensor controller goroutine.
		//
		// Alternatively, we could construct the btf object at load time (as we do in the
		// tracepoints case) and release it there, which seems like a simpler option.
		btfobj = bpf.BTFNil

		load := &BpfLoad{}
		load.observer__x64_attach = funcName
		load.Observer__program = path.Join(HubbleLib, "bpf_generic_kprobe.o")
		load.observer__label = "kprobe/generic_kprobe"
		load.observer__attach = funcName
		load.observer__prog = "kprobe" + "_" + funcName
		load.retProbe = false
		load.errorFatal = true
		load.probeType = "generic_kprobe"
		load.loadState = bpfLoadStateIdle()
		load.tracefd = -1
		load.loaderData = kprobeEntry.tableId
		progs = append(progs, load)

		if setRetprobe {
			loadret := &BpfLoad{}
			loadret.observer__x64_attach = funcName
			loadret.Observer__program = path.Join(HubbleLib, "bpf_generic_retkprobe.o")
			loadret.observer__label = "kprobe/generic_retkprobe"
			loadret.observer__attach = funcName
			loadret.observer__prog = "kretprobe" + "_" + funcName
			loadret.retProbe = true
			loadret.errorFatal = true
			loadret.probeType = "generic_kprobe"
			loadret.loadState = bpfLoadStateIdle()
			loadret.tracefd = -1
			loadret.loaderData = kprobeEntry.tableId
			progs = append(progs, loadret)
		}

		logger.GetLogger().Infof("Added generic kprobe sensor: %s -> %s", load.Observer__program, load.observer__attach)
	}

	return &ObserverSensor{
		name:  "__generic_kprobe_sensors__",
		progs: progs,
		maps:  []*ObserverMap{},
	}, nil
}

func loadGenericKprobe(bpfDir, mapDir string, version int, p *BpfLoad, btf uintptr, genmapDir string, filters [4096]byte) error {
	err, _ := bpf.LoadGenericKprobeProgram(
		version, Verbosity, btf,
		p.Observer__program,
		p.observer__x64_attach,
		p.observer__label,
		bpfDir+p.observer__prog,
		mapDir,
		genmapDir,
		filters)
	if err != nil {
		err, _ = bpf.LoadGenericKprobeProgram(
			version, Verbosity, btf,
			p.Observer__program,
			p.observer__attach,
			p.observer__label,
			bpfDir+p.observer__prog,
			mapDir,
			genmapDir,
			filters)
	}
	if err == nil {
		logger.GetLogger().Infof("Loaded generic kprobe sensor: %s -> %s", p.Observer__program, p.observer__attach)
	}
	return err
}

func loadGenericKprobeRet(bpfDir, mapDir string, version int, p *BpfLoad, btf uintptr, genmapDir string) error {
	err, _ := bpf.LoadGenericKprobeRetProgram(
		version, Verbosity, btf,
		p.Observer__program,
		p.observer__x64_attach,
		p.observer__label,
		path.Join(bpfDir, p.observer__prog),
		mapDir,
		genmapDir)
	if err != nil {
		err, _ = bpf.LoadGenericKprobeRetProgram(
			version, Verbosity, btf,
			p.Observer__program,
			p.observer__attach,
			p.observer__label,
			path.Join(bpfDir, p.observer__prog),
			mapDir,
			genmapDir)
	}
	return err
}

func loadGenericKprobeSensor(bpfDir, mapDir string, load *BpfLoad, version, verbose int) (error, int) {
	gk, err := genericKprobeFromBpfLoad(load)
	if err != nil {
		return err, 0
	}

	genmapDir := gk.getMapDir(mapDir)
	os.Mkdir(genmapDir, os.ModeDir)

	observerAllPrograms = append(observerAllPrograms, load)
	retprobe := strings.Contains(load.Observer__program, "ret")
	if retprobe {
		return loadGenericKprobeRet(bpfDir, mapDir, version, load, gk.loadArgs.btf, genmapDir), 0
	} else {
		return loadGenericKprobe(bpfDir, mapDir, version, load, gk.loadArgs.btf, genmapDir, gk.loadArgs.filters), 0
	}
}

func handleGenericKprobeString(r *bytes.Reader) string {
	var b int32

	err := binary.Read(r, binary.LittleEndian, &b)
	if err != nil {
		logger.GetLogger().WithError(err).Warnf("StringSz type err")
	}
	outputStr := make([]byte, b)
	err = binary.Read(r, binary.LittleEndian, &outputStr)
	if err != nil {
		logger.GetLogger().WithError(err).Warnf("String with size %d type err", b)
	}

	strVal := string(outputStr[:])
	lenStrVal := len(strVal)
	if lenStrVal > 0 && strVal[lenStrVal-1] == '\x00' {
		strVal = strVal[0 : lenStrVal-1]
	}
	return strVal
}

func ReadArgBytes(r *bytes.Reader, index int) (*api.MsgGenericKprobeArgBytes, error) {
	var bytes, bytes_rd int32
	var arg api.MsgGenericKprobeArgBytes

	if err := binary.Read(r, binary.LittleEndian, &bytes); err != nil {
		return nil, fmt.Errorf("failed to read original size for buffer argument: %w", err)
	}

	arg.Index = uint64(index)
	if bytes == CharBufSavedForRetprobe {
		return &arg, nil
	}
	// bpf-side returned an error
	if bytes < 0 {
		// NB: once we extended arguments to also pass errors, we can change
		// this.
		arg.Value = []byte(kprobeCharBufErrorToString(bytes))
		return &arg, nil
	}
	arg.OrigSize = uint64(bytes)
	if err := binary.Read(r, binary.LittleEndian, &bytes_rd); err != nil {
		return nil, fmt.Errorf("failed to read size for buffer argument: %w", err)
	}

	if bytes_rd > 0 {
		arg.Value = make([]byte, bytes_rd)
		if err := binary.Read(r, binary.LittleEndian, &arg.Value); err != nil {
			return nil, fmt.Errorf("failed to read buffer (size: %d): %w", bytes_rd, err)
		}
	}

	// NB: there are cases (e.g., read()) where it is valid to have an
	// empty (zero-length) buffer.
	return &arg, nil

}

func handleGenericKprobe(r *bytes.Reader) (interface{}, error) {
	m := api.MsgGenericKprobe{}
	err := binary.Read(r, binary.LittleEndian, &m)
	if err != nil {
		logger.GetLogger().WithError(err).Warnf("Failed to read process call msg")
		return nil, fmt.Errorf("Failed to read process call msg")
	}

	gk, err := genericKprobeTableGet(idtable.EntryID{ID: int(m.Id)})
	if err != nil {
		logger.GetLogger().WithError(err).Warnf("Failed to match id:%d", m.Id)
		return nil, fmt.Errorf("Failed to match id")
	}

	unix := &api.MsgGenericKprobeUnix{}
	unix.Common = m.Common
	unix.ProcessKey = m.ProcessKey
	unix.Id = m.Id
	unix.FuncName = gk.funcName

	returnEvent := m.Common.Pad[0] > 0

	var printers []argPrinters
	if returnEvent {
		printers = gk.argReturnPrinters
	} else {
		printers = gk.argSigPrinters
	}
	for _, a := range printers {
		switch a.ty {
		case GenericIntType:
			var output int32
			var arg api.MsgGenericKprobeArgInt

			err := binary.Read(r, binary.LittleEndian, &output)
			if err != nil {
				logger.GetLogger().WithError(err).Warnf("Int type error")
				err = nil
			}

			arg.Index = uint64(a.index)
			arg.Value = output
			unix.Args = append(unix.Args, arg)
		case GenericFileType, GenericFdType:
			var arg api.MsgGenericKprobeArgFile

			arg.Index = uint64(a.index)
			arg.Value = handleGenericKprobeString(r)
			unix.Args = append(unix.Args, arg)
		case GenericPathType:
			var arg api.MsgGenericKprobeArgPath

			arg.Index = uint64(a.index)
			arg.Value = handleGenericKprobeString(r)
			unix.Args = append(unix.Args, arg)
		case GenericFilenameType, GenericStringType:
			var b int32
			var arg api.MsgGenericKprobeArgString

			err := binary.Read(r, binary.LittleEndian, &b)
			if err != nil {
				logger.GetLogger().WithError(err).Warnf("StringSz type err")
				err = nil
			}
			outputStr := make([]byte, b)
			err = binary.Read(r, binary.LittleEndian, &outputStr)
			if err != nil {
				logger.GetLogger().WithError(err).Warnf("String with size %d type err", b)
				err = nil
			}

			arg.Index = uint64(a.index)
			strVal := string(outputStr[:])
			lenStrVal := len(strVal)
			if lenStrVal > 0 && strVal[lenStrVal-1] == '\x00' {
				strVal = strVal[0 : lenStrVal-1]
			}
			arg.Value = strVal
			unix.Args = append(unix.Args, arg)
		case GenericCharBuffer, GenericCharIovec:
			if arg, err := ReadArgBytes(r, a.index); err == nil {
				unix.Args = append(unix.Args, *arg)
			} else {
				logger.GetLogger().WithError(err).Warnf("failed to read bytes argument")
			}
		case GenericSkbType:
			var skb api.MsgGenericKprobeSkb
			var arg api.MsgGenericKprobeArgSkb

			err := binary.Read(r, binary.LittleEndian, &skb)
			if err != nil {
				logger.GetLogger().WithError(err).Warnf("skb type err")
				err = nil
			}

			arg.Index = uint64(a.index)
			arg.Hash = skb.Hash
			arg.Len = skb.Len
			arg.Priority = skb.Priority
			arg.Mark = skb.Mark
			unix.Args = append(unix.Args, arg)
		case GenericSizeType:
			var output uint64
			var arg api.MsgGenericKprobeArgSize

			err := binary.Read(r, binary.LittleEndian, &output)
			if err != nil {
				logger.GetLogger().WithError(err).Warnf("Size type error sizeof %d", m.Common.Size)
				err = nil
			}

			arg.Index = uint64(a.index)
			arg.Value = output
			unix.Args = append(unix.Args, arg)
		default:
			logger.GetLogger().WithError(err).WithField("event", a).Warnf("Unknown type event")
		}
	}

	// there are two events for this probe (entry and return)
	if gk.loadArgs.retprobe {
		// if an event exist already, try to merge them. Otherwise, add
		// the one we have in the map.
		curr := pendingEvent{ev: unix, returnEvent: returnEvent}
		if prev, exists := gk.pendingEvents[m.ThreadId]; exists {
			delete(gk.pendingEvents, m.ThreadId)
			unix = retprobeMerge(prev, curr)
		} else {
			gk.pendingEvents[m.ThreadId] = curr
			unix = nil
			err = fmt.Errorf("pendingEvents")
		}
	}
	return unix, err
}

// retprobeMerge merges the two events: the one from they entry and one from the return
func retprobeMerge(prev pendingEvent, curr pendingEvent) *api.MsgGenericKprobeUnix {
	var retEv, enterEv *api.MsgGenericKprobeUnix

	if prev.returnEvent && !curr.returnEvent {
		retEv = prev.ev
		enterEv = curr.ev
	} else if !prev.returnEvent && curr.returnEvent {
		retEv = curr.ev
		enterEv = prev.ev
	} else if prev.returnEvent && curr.returnEvent {
		logger.GetLogger().Warnf("cannot merge two return events: prev:%+v curr:%+v", prev, curr)
		return nil
	} else {
		logger.GetLogger().Warnf("cannot merge two enter events: prev:%+v curr:%+v", prev, curr)
		return nil
	}

	for _, retArg := range retEv.Args {
		index := retArg.GetIndex()
		if uint64(len(enterEv.Args)) > index {
			enterEv.Args[index] = retArg
		} else {
			enterEv.Args = append(enterEv.Args, retArg)
		}
	}
	return enterEv
}

func (k *observerKprobeSensor) SpecHandler(spec *v1alpha1.TracingPolicySpec) (*ObserverSensor, error) {
	if len(spec.KProbes) > 0 && len(spec.Tracepoints) > 0 {
		return nil, errors.New("tracing policies with both kprobes and tracepoints are not currently supported")
	}
	if len(spec.KProbes) > 0 {
		return addGenericKprobeSensors(spec.KProbes, ObserverBTF)
	}
	return nil, nil
}

func (k *observerKprobeSensor) LoadProbe(
	bpfDir, mapDir, ciliumDir string,
	load *BpfLoad,
	version, verbose int, x64 bool) (error, int) {
	return loadGenericKprobeSensor(bpfDir, mapDir, load, version, Verbosity)
}

package observer

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/covalentio/hubble-fgs/pkg/api"
	"github.com/covalentio/hubble-fgs/pkg/bpf"
	"github.com/covalentio/hubble-fgs/pkg/idtable"
	"github.com/covalentio/hubble-fgs/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/covalentio/hubble-fgs/pkg/selectors"
)

const (
	GenericKprobeNopType    = 0
	GenericKprobeIntType    = 1
	GenericKprobeCharBuffer = 2
	GenericKprobeCharIovec  = 3
	GenericKprobeSizeType   = 4
	GenericKprobeSkbType    = 5
	GenericKprobeStringType = 6

	GenericKprobeS64Type = 10
	GenericKprobeU64Type = 11
	GenericKprobeS32Type = 12
	GenericKprobeU32Type = 13

	GenericKprobeFilenameType = 14
)

const (
	sizeofArgsFilter = 80
	maxArgsSupported = 5
)

const (
	argReturnCopy = -1
)

const (
	nopTypeId     = -1
	invalidTypeId = -2
)

var (
	// genericKprobeProgs stores dynamic kprobes added/removed from CRD.
	// Kprobes managed from init config file are pushed through
	// observerAllPrograms.
	genericKprobeProgs = map[string]*bpfLoad{}
)

func kprobeStrToTypeId(arg string) int {
	switch arg {
	case "string":
		return GenericKprobeStringType
	case "int":
		return GenericKprobeIntType
	case "uint64":
		return GenericKprobeU64Type
	case "uint32":
		return GenericKprobeU32Type
	case "sint64":
		return GenericKprobeS64Type
	case "sint32":
		return GenericKprobeS32Type
	case "skb":
		return GenericKprobeSkbType
	case "size_t":
		return GenericKprobeSizeType
	case "char_buf":
		return GenericKprobeCharBuffer
	case "char_iovec":
		return GenericKprobeCharIovec
	case "filename":
		return GenericKprobeFilenameType
	case "nop":
		return nopTypeId
	default:
		return invalidTypeId
	}
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
	is_syscall      = "syscall"
	argm0           = "arg0m"
	argm1           = "arg1m"
	argm2           = "arg2m"
	argm3           = "arg3m"
	argm4           = "arg4m"
	argm5           = "arg5m"
)

const (
	CharBufErrorENOMEM    = -1
	CharBufErrorPageFault = -2
	CharBufErrorTooLarge  = -3
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
		return arg5
	}
	return ""
}

type kprobeLoadArgs struct {
	filters  [4096]byte
	btf      uintptr
	retprobe bool
	syscall  bool
}

// internal genericKprobe info
type genericKprobe struct {
	loadArgs    kprobeLoadArgs
	argPrinters []int
	funcName    string

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

func genericKprobeFromBpfLoad(l *bpfLoad) (*genericKprobe, error) {
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

func (k *ObserverKprobe) kprobeEventFilterWriteBTF(btf uintptr, ty string, op, value int) error {
	retVal := bpf.AddEnumBtfValue(btf, ty+"_type", op)
	if retVal < 0 {
		return fmt.Errorf("Error add enum value '%s_type' failed %d", ty, retVal)
	}

	retVal = bpf.AddEnumBtfValue(btf, ty+"_value", value)
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

func (k *ObserverKprobe) addGenericKprobeSensors(kprobes []v1alpha1.KProbeSpec, btfBaseFile string) (*observerSensor, error) {
	var progs []*bpfLoad

	for i := range kprobes {
		f := kprobes[i]
		var argPrinters []int
		var is_syscall, is_retprobe bool
		var argsBTFSet [maxArgsSupported]bool

		funcName := f.Call

		// Write args into BTF ptr for use with load
		btf := bpf.GetBTF(btfBaseFile)
		ret := bpf.AddEnumBtf(btf, genericFuncArgsEnum, 4)
		if ret < 0 {
			return nil, fmt.Errorf("Error add enum args (%s) failed %d", genericFuncArgsEnum, ret)
		}

		// Parse Arguments
		for j, a := range f.Args {
			argType := kprobeStrToTypeId(a.Type)
			if argType == invalidTypeId {
				return nil, fmt.Errorf("Arg(%d) type '%s' unsupported\n", j, a.Type)
			}
			argMValue := getMetaValue(&a)
			if argMValue == argReturnCopy {
				is_retprobe = true
			}
			retVal := bpf.AddEnumBtfValue(btf, kprobeArgToString(int(a.Index)), argType)
			if retVal < 0 {
				return nil,
					fmt.Errorf("Error add arg: ArgType %s Index %d failed %d",
						a.Type, int(a.Index), retVal)
			}
			retVal = bpf.AddEnumBtfValue(btf, kprobeArgMToString(int(a.Index)), argMValue)
			if retVal < 0 {
				return nil, fmt.Errorf("Error add enum value '%s' failed %d", kprobeArgMToString(int(a.Index)), retVal)
			}

			argsBTFSet[a.Index] = true
			argPrinters = append(argPrinters, argType)
		}

		// Mark remaining arguments as 'nops' the kernel side will skip
		// copying 'nop' args.
		for j, a := range argsBTFSet {
			if a == false {
				nopType := kprobeStrToTypeId("nop")
				retVal := bpf.AddEnumBtfValue(btf, kprobeArgToString(j), nopType)
				if retVal < 0 {
					return nil, fmt.Errorf("Error add enum value '%s' failed %d",
						kprobeArgToString(j), retVal)
				}
				retVal = bpf.AddEnumBtfValue(btf, kprobeArgMToString(j), 0)
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
		if !is_retprobe {
			is_retprobe = f.Return
		}

		if is_syscall {
			retVal := bpf.AddEnumBtfValue(btf, "syscall", 1)
			if retVal < 0 {
				return nil, fmt.Errorf("Error add enum value 'syscall = 1' failed %d", retVal)
			}
		} else {
			retVal := bpf.AddEnumBtfValue(btf, "syscall", 0)
			if retVal < 0 {
				return nil, fmt.Errorf("Error add enum value 'syscall = 0' failed %d", retVal)
			}
		}

		// create a new entry on the table, and pass its id to BPF-side
		// so that we can do the matching at event-generation time
		kprobeEntry := genericKprobe{
			loadArgs: kprobeLoadArgs{
				filters:  kernelSelectors,
				btf:      btf,
				retprobe: is_retprobe,
				syscall:  is_syscall,
			},
			argPrinters:   argPrinters,
			funcName:      funcName,
			pendingEvents: map[uint64]pendingEvent{},
			tableId:       idtable.UninitializedEntryID,
		}
		genericKprobeTable.AddEntry(&kprobeEntry)
		ret = bpf.AddEnumBtfValue(btf, kprobeGenericId, kprobeEntry.tableId.ID)
		if ret < 0 {
			genericKprobeTable.RemoveEntry(kprobeEntry.tableId)
			return nil, fmt.Errorf("Error add enum value failed %d", ret)
		}

		load := &bpfLoad{}
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

		if is_retprobe {
			loadret := &bpfLoad{}
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

	}

	k.log.Info("Loaded generic kprobe sensor")
	return &observerSensor{
		name:  "__generic_kprobe_sensors__",
		progs: progs,
		maps:  []*ObserverMap{},
	}, nil
}

func (k *ObserverKprobe) loadGenericKprobe(version int, p *bpfLoad, btf uintptr, genmapDir string, filters [4096]byte) error {
	err, _ := bpf.LoadGenericKprobeProgram(
		version, Verbosity, btf,
		p.Observer__program,
		p.observer__x64_attach,
		p.observer__label,
		k.bpfDir+p.observer__prog,
		k.mapDir,
		genmapDir,
		filters)
	if err != nil {
		err, _ = bpf.LoadGenericKprobeProgram(
			version, Verbosity, btf,
			p.Observer__program,
			p.observer__attach,
			p.observer__label,
			k.bpfDir+p.observer__prog,
			k.mapDir,
			genmapDir,
			filters)
	}
	return err
}

func (k *ObserverKprobe) loadGenericKprobeRet(version int, p *bpfLoad, btf uintptr, genmapDir string) error {
	err, _ := bpf.LoadGenericKprobeRetProgram(
		version, Verbosity, btf,
		p.Observer__program,
		p.observer__x64_attach,
		p.observer__label,
		path.Join(k.bpfDir, p.observer__prog),
		k.mapDir,
		genmapDir)
	if err != nil {
		err, _ = bpf.LoadGenericKprobeRetProgram(
			version, Verbosity, btf,
			p.Observer__program,
			p.observer__attach,
			p.observer__label,
			path.Join(k.bpfDir, p.observer__prog),
			k.mapDir,
			genmapDir)
	}
	return err
}

func (k *ObserverKprobe) loadGenericKprobeSensor(load *bpfLoad, version, verbose int) (error, int) {
	gk, err := genericKprobeFromBpfLoad(load)
	if err != nil {
		return err, 0
	}

	genmapDir := gk.getMapDir(k.mapDir)
	os.Mkdir(genmapDir, os.ModeDir)

	observerAllPrograms = append(observerAllPrograms, load)
	retprobe := strings.Contains(load.Observer__program, "ret")
	if retprobe {
		return k.loadGenericKprobeRet(version, load, gk.loadArgs.btf, genmapDir), 0
	} else {
		return k.loadGenericKprobe(version, load, gk.loadArgs.btf, genmapDir, gk.loadArgs.filters), 0
	}
}

func (k *ObserverKprobe) handleGenericKprobe(r *bytes.Reader) {
	m := api.MsgGenericKprobe{}
	err := binary.Read(r, binary.LittleEndian, &m)
	if err != nil {
		k.log.WithError(err).Warnf("Failed to read process call msg")
		return
	}

	gk, err := genericKprobeTableGet(idtable.EntryID{ID: int(m.Id)})
	if err != nil {
		k.log.WithError(err).Warnf("Failed to match id:%d", m.Id)
		return
	}

	unix := &api.MsgGenericKprobeUnix{}
	unix.Common = m.Common
	unix.ProcessKey = m.ProcessKey
	unix.Id = m.Id
	unix.FuncName = gk.funcName

	returnEvent := m.Common.Pad[0] > 0

	for i, arg := range gk.argPrinters {
		if returnEvent && arg != GenericKprobeCharBuffer {
			continue
		}

		switch arg {
		case GenericKprobeIntType:
			var output int32
			var arg api.MsgGenericKprobeArgInt

			err := binary.Read(r, binary.LittleEndian, &output)
			if err != nil {
				k.log.WithError(err).Warnf("Int type error")
			}

			arg.Index = uint64(i)
			arg.Value = output
			unix.Args = append(unix.Args, arg)
		case GenericKprobeFilenameType,
			GenericKprobeStringType:
			var b int32
			var arg api.MsgGenericKprobeArgString

			err := binary.Read(r, binary.LittleEndian, &b)
			if err != nil {
				k.log.WithError(err).Warnf("StringSz type err")
			}
			outputStr := make([]byte, b)
			err = binary.Read(r, binary.LittleEndian, &outputStr)
			if err != nil {
				k.log.WithError(err).Warnf("String with size %d type err", b)
			}

			arg.Index = uint64(i)
			strVal := string(outputStr[:])
			lenStrVal := len(strVal)
			if lenStrVal > 0 && strVal[lenStrVal-1] == '\x00' {
				strVal = strVal[0 : lenStrVal-1]
			}
			arg.Value = strVal
			unix.Args = append(unix.Args, arg)
		case GenericKprobeCharBuffer, GenericKprobeCharIovec:
			var b int32
			var arg api.MsgGenericKprobeArgBytes

			err := binary.Read(r, binary.LittleEndian, &b)
			if err != nil {
				k.log.WithError(err).Warnf("StringCharBuf size err")
			}
			if b > 0 {
				outputBytes := make([]byte, b)
				err = binary.Read(r, binary.LittleEndian, &outputBytes)
				if err != nil {
					k.log.WithError(err).Warnf("StringCharBuf size (%d) type err", b)
				}

				arg.Index = uint64(i)
				arg.Value = outputBytes
				unix.Args = append(unix.Args, arg)
			} else if b == 0 {
				arg.Index = uint64(i)
				// NB: we used to have an error string here, but given things like
				// read() where it is valid to have an empty (zero-length) buffer,
				// we just return an empty byte buffer.
				arg.Value = []byte{}
				unix.Args = append(unix.Args, arg)
			} else {
				arg.Index = uint64(i)
				// NB: once we extended arguments to also pass errors, we can change
				// this.
				arg.Value = []byte(kprobeCharBufErrorToString(b))
				unix.Args = append(unix.Args, arg)
			}
		case GenericKprobeSkbType:
			var skb api.MsgGenericKprobeSkb
			var arg api.MsgGenericKprobeArgSkb

			err := binary.Read(r, binary.LittleEndian, &skb)
			if err != nil {
				k.log.WithError(err).Warnf("skb type err")
			}

			arg.Index = uint64(i)
			arg.Hash = skb.Hash
			arg.Len = skb.Len
			arg.Priority = skb.Priority
			arg.Mark = skb.Mark
			unix.Args = append(unix.Args, arg)
		case GenericKprobeSizeType:
			var output uint64
			var arg api.MsgGenericKprobeArgSize

			err := binary.Read(r, binary.LittleEndian, &output)
			if err != nil {
				k.log.WithError(err).Warnf("Size type error sizeof %d", m.Common.Size)
			}

			arg.Index = uint64(i)
			arg.Value = output
			unix.Args = append(unix.Args, arg)
		}
	}

	// there are two events for this probe (entry and return)
	if gk.loadArgs.retprobe {
		// if an event exist already, try to merge them. Otherwise, add
		// the one we have in the map.
		curr := pendingEvent{ev: unix, returnEvent: returnEvent}
		if prev, exists := gk.pendingEvents[m.ThreadId]; exists {
			delete(gk.pendingEvents, m.ThreadId)
			unix = k.retprobeMerge(prev, curr)
		} else {
			gk.pendingEvents[m.ThreadId] = curr
			unix = nil
		}
	}

	if unix != nil {
		k.observerListenersKprobe(unix)
	}
}

// retprobeMerge merges the two events: the one from they entry and one from the return
func (k *ObserverKprobe) retprobeMerge(prev pendingEvent, curr pendingEvent) *api.MsgGenericKprobeUnix {
	var retEv, enterEv *api.MsgGenericKprobeUnix

	if prev.returnEvent && !curr.returnEvent {
		retEv = prev.ev
		enterEv = curr.ev
	} else if !prev.returnEvent && curr.returnEvent {
		retEv = curr.ev
		enterEv = prev.ev
	} else if prev.returnEvent && curr.returnEvent {
		k.log.Warnf("cannot merge two return events: prev:%+v curr:%+v", prev, curr)
		return nil
	} else {
		k.log.Warnf("cannot merge two enter events: prev:%+v curr:%+v", prev, curr)
		return nil
	}

	retArg, ok := retEv.Args[0].(api.MsgGenericKprobeArgBytes)
	if !ok {
		k.log.Warnf("failed to merge retprobe: prev:%+v next:%+v", prev, curr)
		return nil
	}
	if uint64(len(enterEv.Args)) > retArg.Index {
		enterEv.Args[retArg.Index] = retArg
		return enterEv
	} else {
		k.log.Warnf("failed to merge retprobe: prev:%+v next:%+v", prev, curr)
		return nil
	}
}

func (k *ObserverKprobe) observerListenersKprobe(msg *api.MsgGenericKprobeUnix) {
	for listener, _ := range k.listeners {
		if err := listener.Notify(msg); err != nil {
			k.log.Debug("Write failure removing Listener")
			k.RemoveListener(listener)
		}
	}
}

func (k *ObserverKprobe) removeGenericKprobeSensor(kprobeConfig *v1alpha1.TracingPolicySpec) {
	for _, f := range kprobeConfig.KProbes {
		p := genericKprobeProgs[f.Call]
		if p != nil {
			k.removeProgram(p)
		} else {
			k.log.Warn("Attempted to remove unloaded program: %s\n", f.Call)
		}
	}
}

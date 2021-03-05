package observer

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"path"
	"strconv"
	"strings"

	"github.com/covalentio/hubble-fgs/pkg/api"
	"github.com/covalentio/hubble-fgs/pkg/bpf"
	"github.com/covalentio/hubble-fgs/pkg/config"
)

const (
	GenericKprobeStringType = 1
	GenericKprobeIntType    = 2
	GenericKprobeSkbType    = 3
	GenericKprobeSizeType   = 4
	GenericKprobeCharBuffer = 5
	GenericKprobeCharIovec  = 6
)

const (
	sizeofArgsFilter = 80
)

const (
	nopTypeId     = -1
	invalidTypeId = -2
)

func kprobeStrToTypeId(arg string) int {
	switch arg {
	case "string":
		return GenericKprobeStringType
	case "int":
		return GenericKprobeIntType
	case "skb":
		return GenericKprobeSkbType
	case "size_t":
		return GenericKprobeSizeType
	case "char_buf":
		return GenericKprobeCharBuffer
	case "char_iovec":
		return GenericKprobeCharIovec
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
	args     api.KprobeArgs
	btf      uintptr
	retprobe bool
	syscall  bool
}

var (
	// A map of BTF images. generic_kprobe_name -> btf
	genericKprobeLoadArgs map[string]kprobeLoadArgs
	genericKprobeId       map[uint64][]int
	genericKprobeName     map[uint64]string
)

var (
	MaxFilterIntArgs = 8
)

func (k *ObserverKprobe) initKprobeSensors() {
	genericKprobeLoadArgs = make(map[string]kprobeLoadArgs, 1)
	genericKprobeId = make(map[uint64][]int, 1)
	genericKprobeName = make(map[uint64]string, 1)
}

const (
	genericKprobeFilterGT = 1
	genericKprobeFilterLT = 2
	genericKprobeFilterEQ = 3
)

func (k *ObserverKprobe) opFilterStrToType(ty string) (int, error) {
	switch ty {
	case "gt":
		return genericKprobeFilterGT, nil
	case "lt":
		return genericKprobeFilterLT, nil
	case "eq":
		return genericKprobeFilterEQ, nil
	}
	return 0, fmt.Errorf("Unknown op '%s'", ty)
}

func (k *ObserverKprobe) createArgFilter(argType int, filters []config.Filter) []byte {
	b := make([]byte, sizeofArgsFilter)

	switch argType {
	// syntax int filters: [lt,gt,eq] int1 | [lt,gt,eq] int2 | ... | [lt,gt,eq] intN
	case GenericKprobeIntType:
		if len(filters) > MaxFilterIntArgs {
			k.log.Warn("Warning: createArgFilter too many filter, argType %d filterStr %s\n", argType, filters)
		}
		// Byte buffer layout: #Entries, opType1 opValue1, opType2 opValue2, ...
		off := 0
		binary.LittleEndian.PutUint32(b[off:], uint32(len(filters)))
		off += 4

		for _, f := range filters {
			operation, _ := k.opFilterStrToType(f.Op)
			binary.LittleEndian.PutUint32(b[off:], uint32(operation))

			v, err := strconv.Atoi(f.Value)
			if err != nil {
				k.log.Warn("invalid filterArg type %d filter %s\n", argType, f)
			} else {
				binary.LittleEndian.PutUint32(b[off+4:], uint32(v))
			}
			off += 8
		}
	case GenericKprobeStringType:
	case GenericKprobeSkbType:
	case GenericKprobeSizeType:
	case GenericKprobeCharBuffer:
	case GenericKprobeCharIovec:
	}

	return b
}

func (k *ObserverKprobe) pidFilterStrToValue(value string) (int, error) {
	v, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("Invalid filter value error %s\n", err)
	}
	return v, nil
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
		if op != genericKprobeFilterEQ {
			return fmt.Errorf("Event filter '%s' op '%s' unsupported for type", ty, opName)
		}
	}
	return nil
}

func (k *ObserverKprobe) kprobeProcessFilters(btf uintptr, filters []config.Filter) error {
	availableFilters := map[string]bool{
		"nspid":       false,
		"pid":         false,
		"pidset":      false,
		"notpidset":   false,
		"nspidset":    false,
		"notnspidset": false,
	}

	for _, filter := range filters {
		_type := filter.Type
		op, err := k.opFilterStrToType(filter.Op)
		if err != nil {
			return fmt.Errorf("Error filter op '%s': %s", _type, err)
		}
		value, err := k.pidFilterStrToValue(filter.Value)
		if err != nil {
			return fmt.Errorf("Error filter value '%s': %s", _type, err)
		}

		if _, ok := availableFilters[_type]; !ok {
			return fmt.Errorf("Unknown event filter '%s'", _type)
		}
		availableFilters[_type] = true
		if err := k.checkFilterRestrictions(_type, filter.Op, op); err != nil {
			return err
		}
		if err := k.kprobeEventFilterWriteBTF(btf, _type, op, value); err != nil {
			return err
		}
	}
	// All enums need to be fully populated or otherwise BPF side
	// may try to access an enum that does not exist and fail
	// verification.
	for key, value := range availableFilters {
		if !value {
			k.kprobeEventFilterWriteBTF(btf, key, 0, 0)
		}
	}
	return nil
}

func (k *ObserverKprobe) createGenericKprobeSensors(btfBaseFile, configFile string) (*observerSensor, error) {
	var progs []*bpfLoad

	kprobeConfig, err := config.FileConfigYaml(configFile)
	if err != nil {
		return nil, err
	}

	for i, f := range kprobeConfig.Spec.Kprobe.Function {
		var entry kprobeLoadArgs
		var argPrinters []int
		var is_syscall, is_retprobe bool

		argFilters := api.KprobeArgs{
			Args0: make([]byte, sizeofArgsFilter),
			Args1: make([]byte, sizeofArgsFilter),
			Args2: make([]byte, sizeofArgsFilter),
			Args3: make([]byte, sizeofArgsFilter),
			Args4: make([]byte, sizeofArgsFilter),
		}

		funcName := f.Call

		// Write args into BTF ptr for use with load
		btf := bpf.GetBTF(btfBaseFile)
		ret := bpf.AddEnumBtf(btf, genericFuncArgsEnum, 4)
		if ret < 0 {
			return nil, fmt.Errorf("Error add enum args (%s) failed %d", genericFuncArgsEnum, ret)
		}
		ret = bpf.AddEnumBtfValue(btf, kprobeGenericId, i)
		if ret < 0 {
			return nil, fmt.Errorf("Error add enum value failed %d", ret)
		}

		// NB: bpf side handles 5 args. if there are less than 5 args
		// defined, fill the rest with nop args.
		if len(f.Args) < 5 {
			nop := config.Arg{
				Type: "nop",
			}
			for j := len(f.Args); j < 6; j++ {
				f.Args = append(f.Args, nop)
			}
		}

		// Argument format 'aType=filters$metadata'
		for j, a := range f.Args {
			argType := kprobeStrToTypeId(a.Type)
			if argType == invalidTypeId {
				return nil, fmt.Errorf("Arg(%d) type '%s' unsupported\n", j, a.Type)
			}

			// Associate any metadata with the argument
			var argMValue int
			switch meta := a.Meta; meta {
			case "":
				argMValue = 0

			case "ret":
				argMValue = -1

			default:
				argMValue, err = strconv.Atoi(meta)
				if err != nil {
					return nil, fmt.Errorf("Error filter meta %s invalid: %s\n", meta, err)
				}
			}

			if len(a.Filters) > 0 {
				argF := k.createArgFilter(argType, a.Filters)
				switch j { // this is a bit ugly fixup tbd
				case 0:
					argFilters.Args0 = argF
				case 1:
					argFilters.Args1 = argF
				case 2:
					argFilters.Args2 = argF
				case 3:
					argFilters.Args3 = argF
				case 4:
					argFilters.Args4 = argF
				}
			}

			retVal := bpf.AddEnumBtfValue(btf, kprobeArgToString(j), argType)
			if retVal < 0 {
				return nil, fmt.Errorf("Error add enum value '%s' failed %d", kprobeArgToString(j), retVal)
			}
			retVal = bpf.AddEnumBtfValue(btf, kprobeArgMToString(j), argMValue)
			if retVal < 0 {
				return nil, fmt.Errorf("Error add enum value '%s' failed %d", kprobeArgMToString(j), retVal)
			}

			argPrinters = append(argPrinters, argType)
		}

		// Write attributes into BTF ptr for use with load
		is_syscall = f.Syscall
		is_retprobe = f.Return

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
		if err := k.kprobeProcessFilters(btf, f.Filters); err != nil {
			return nil, fmt.Errorf("Error creating process filters: %s", err)
		}

		entry.args = argFilters
		entry.btf = btf
		entry.retprobe = is_retprobe
		entry.syscall = is_syscall
		genericKprobeLoadArgs[funcName] = entry
		genericKprobeId[uint64(i)] = argPrinters
		genericKprobeName[uint64(i)] = funcName

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
			progs = append(progs, loadret)
		}

		progs = append(progs, load)
	}

	// some maps we might want to use
	maps := []*ObserverMap{
		//	&ObserverTCPMonMap,
		//	&ObserverExecveMap,
		//	&ObserverSocketMap,
		//	&ObserverExecveStats,
		//	&ObserverSocketStats,
	}

	k.log.Info("Loaded generic kprobe sensor")
	return &observerSensor{
		name:  "__generic_kprobe_sensors__",
		progs: progs,
		maps:  maps,
	}, nil
}

func (k *ObserverKprobe) loadGenericKprobeSensor(load *bpfLoad, version, verbose int, x64 bool) (error, int) {
	var attach string

	btf := genericKprobeLoadArgs[load.observer__attach].btf
	args := genericKprobeLoadArgs[load.observer__attach].args
	// we don't actually need retprobe here but might be useful in the future for dbg?
	retprobe := genericKprobeLoadArgs[load.observer__attach].retprobe

	observerAllPrograms = append(observerAllPrograms, load)

	if x64 {
		attach = load.observer__x64_attach
	} else {
		attach = load.observer__attach
	}
	retprobe = strings.Contains(load.Observer__program, "ret")
	return bpf.LoadKprobeArgsProgram(
		version, verbose, btf,
		load.Observer__program,
		attach,
		load.observer__label,
		k.bpfDir+load.observer__prog,
		k.mapDir,
		retprobe,
		args)
}

func (k *ObserverKprobe) handleGenericKprobe(r *bytes.Reader) {
	m := api.MsgGenericKprobe{}
	unix := &api.MsgGenericKprobeUnix{}
	err := binary.Read(r, binary.LittleEndian, &m)
	if err != nil {
		k.log.WithError(err).Warnf("Failed to read process call msg")
		return
	}

	unix.Common = m.Common
	unix.ProcessKey = m.ProcessKey
	unix.Id = m.Id
	unix.FuncName = genericKprobeName[m.Id]

	retProbe := m.Common.Pad[0]

	printerArgs := genericKprobeId[m.Id]
	for i, arg := range printerArgs {
		if retProbe > 0 && arg != GenericKprobeCharBuffer {
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
		case GenericKprobeStringType:
			var b int32
			var arg api.MsgGenericKprobeArgString

			err := binary.Read(r, binary.LittleEndian, &b)
			if err != nil {
				k.log.WithError(err).Warnf("StringSz type err")
			}
			outputStr := make([]byte, b)
			err = binary.Read(r, binary.LittleEndian, &outputStr)
			if err != nil {
				k.log.WithError(err).Warnf("String type err")
			}

			arg.Index = uint64(i)
			arg.Value = string(outputStr[:])
			unix.Args = append(unix.Args, arg)
		case GenericKprobeCharBuffer, GenericKprobeCharIovec:
			var b int32
			var arg api.MsgGenericKprobeArgString

			err := binary.Read(r, binary.LittleEndian, &b)
			if err != nil {
				k.log.WithError(err).Warnf("StringCharBuf size err")
			}
			if b > 0 {
				outputStr := make([]byte, b)
				err = binary.Read(r, binary.LittleEndian, &outputStr)
				if err != nil {
					k.log.WithError(err).Warnf("StringCharBuf size (%d) type err", b)
				}

				arg.Index = uint64(i)
				arg.Value = string(outputStr[:])
				unix.Args = append(unix.Args, arg)
			} else if b == 0 {
				arg.Index = uint64(i)
				arg.Value = "return value expected"
				unix.Args = append(unix.Args, arg)
			} else {
				arg.Index = uint64(i)
				arg.Value = kprobeCharBufErrorToString(b)
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

	k.observerListenersKprobe(unix)
}

func (k *ObserverKprobe) observerListenersKprobe(msg *api.MsgGenericKprobeUnix) {
	for listener, _ := range k.listeners {
		if err := listener.Notify(msg); err != nil {
			k.log.Debug("Write failure removing Listener")
			k.RemoveListener(listener)
		}
	}
}

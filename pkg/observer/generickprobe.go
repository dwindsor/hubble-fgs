package observer

import (
	"bytes"
	"encoding/binary"
	"strconv"
	"strings"

	"github.com/covalentio/hubble-fgs/pkg/api"
	"github.com/covalentio/hubble-fgs/pkg/bpf"
)

const (
	GenericKprobeStringType = 1
	GenericKprobeIntType    = 2
	GenericKprobeSkbType    = 3
	GenericKprobeSizeType   = 4
	GenericKprobeCharBuffer = 5
)

const (
	sizeofArgsFilter = 80
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
	default:
		return -1
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

type kprobeArgs struct {
	args0 []byte
	args1 []byte
	args2 []byte
	args3 []byte
	args4 []byte
}

type kprobeLoadArgs struct {
	args     kprobeArgs
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

func (k *ObserverKprobe) opFilterStrToType(ty string) int {
	switch ty {
	case "gt":
		return genericKprobeFilterGT
	case "lt":
		return genericKprobeFilterLT
	case "eq":
		return genericKprobeFilterEQ
	default:
		k.log.Warn("genericKprobe Filter type unknown %s", ty)
	}
	return 0
}

func (k *ObserverKprobe) createArgFilter(argType int, filter string) []byte {
	b := make([]byte, sizeofArgsFilter)

	switch argType {
	// syntax int filters: [lt,gt,eq] int1 | [lt,gt,eq] int2 | ... | [lt,gt,eq] intN
	case GenericKprobeIntType:
		fs := strings.Split(filter, "|")
		if len(fs) > MaxFilterIntArgs {
			k.log.Warn("Warning: createArgFilter too many filter, argType %d filterStr %s\n", argType, filter)
		} else {
			// Byte buffer layout: #Entries, opType1 opValue1, opType2 opValue2, ...
			off := 0
			binary.LittleEndian.PutUint32(b[off:], uint32(len(fs)))
			off += 4

			for _, f := range fs {
				opVal := strings.Split(f, " ")

				operation := k.opFilterStrToType(opVal[0])
				binary.LittleEndian.PutUint32(b[off:], uint32(operation))

				v, err := strconv.Atoi(opVal[1])
				if err != nil {
					k.log.Warn("invalid filterArg type %d filter %s\n", argType, f)
				} else {
					binary.LittleEndian.PutUint32(b[off+4:], uint32(v))
				}

				off += 8
			}
		}
	case GenericKprobeStringType:
	case GenericKprobeSkbType:
	case GenericKprobeSizeType:
	case GenericKprobeCharBuffer:
	}

	return b
}

func (k *ObserverKprobe) pidFilterStrToValue(value string) int {
	v, err := strconv.Atoi(value)
	if err != nil {
		k.log.Warn("genericKprobe Filter value error %s\n", err)
		return 0
	}
	return v
}

func (k *ObserverKprobe) createGenericKprobeSensors(sensorList, btfBaseFile string) *observerSensor {
	var progs []*bpfLoad

	if sensorList == "" {
		return nil
	}

	sensors := strings.Split(sensorList, ",")
	// sensors <- function(arg1:arg2:arg3:arg4:arg5)[attributes]
	for i, s := range sensors {
		var entry kprobeLoadArgs
		var argPrinters []int
		var is_syscall, is_retprobe bool

		nspid_filter := int(0)
		nspid_type := int(0)
		pid_filter := int(0)
		pid_type := int(0)
		pidset_value := int(0)

		argFilters := kprobeArgs{
			args0: make([]byte, sizeofArgsFilter),
			args1: make([]byte, sizeofArgsFilter),
			args2: make([]byte, sizeofArgsFilter),
			args3: make([]byte, sizeofArgsFilter),
			args4: make([]byte, sizeofArgsFilter),
		}

		funcSplit := strings.Split(s, "(")
		filterSplit := strings.Split(funcSplit[1], ")")
		funcName := funcSplit[0]
		args := strings.Split(filterSplit[0], ":")
		attributes := strings.Split(s, "[")
		if len(attributes) > 1 {
			attributes = strings.Split(attributes[1], "]")
		} else {
			attributes = nil
		}

		// Write args into BTF ptr for use with load
		btf := bpf.GetBTF(btfBaseFile)
		ret := bpf.AddEnumBtf(btf, genericFuncArgsEnum, 4)
		if ret < 0 {
			k.log.Warn("error add enum args %d", ret)
		}
		ret = bpf.AddEnumBtfValue(btf, kprobeGenericId, i)
		if ret < 0 {
			k.log.Warn("error add enum gen id value %d", ret)
		}

		// Argument format 'aType=filters$metadata'
		for j, f := range args {
			fext := strings.Split(f, "#")
			filters := strings.Split(fext[0], "=")
			argType := kprobeStrToTypeId(filters[0])

			// Associate any metadata with the argument
			argMValue := 0
			if len(fext) > 1 {
				var err error

				switch fext[1] {
				case "ret":
					argMValue = -1
				default:
					argMValue, err = strconv.Atoi(fext[1])
					if err != nil {
						k.log.Warn("error strconv.Atoi %s, %s\n", fext[1], err)
					}
				}
			}

			if len(filters) > 1 {
				argF := k.createArgFilter(argType, filters[1])
				switch j { // this is a bit ugly fixup tbd
				case 0:
					argFilters.args0 = argF
				case 1:
					argFilters.args1 = argF
				case 2:
					argFilters.args2 = argF
				case 3:
					argFilters.args3 = argF
				case 4:
					argFilters.args4 = argF
				}
			}

			retVal := bpf.AddEnumBtfValue(btf, kprobeArgToString(j), argType)
			if retVal < 0 {
				k.log.Warn("error add enum btf arg value %d", retVal)
			}
			retVal = bpf.AddEnumBtfValue(btf, kprobeArgMToString(j), argMValue)
			if retVal < 0 {
				k.log.Warn("error add enum btf argM value %d", retVal)
			}

			argPrinters = append(argPrinters, argType)
		}

		// Write attributes into BTF ptr for use with load
		if attributes != nil {
			attrsSplit := strings.Split(attributes[0], ":")
			for _, f := range attrsSplit {
				_f := strings.Split(f, " ")
				switch _f[0] {
				// Inform datapath that this kprobe is a syscall
				case "syscall":
					is_syscall = true
				case "ret":
					is_retprobe = true
				case "nspid":
					nspid_type = k.opFilterStrToType(_f[1])
					nspid_filter = k.pidFilterStrToValue(_f[2])
				case "pid":
					pid_type = k.opFilterStrToType(_f[1])
					pid_filter = k.pidFilterStrToValue(_f[2])
				case "pidset":
					pidset_value = k.pidFilterStrToValue(_f[1])
				}
			}
		}

		if is_syscall {
			retVal := bpf.AddEnumBtfValue(btf, "syscall", 1)
			if retVal < 0 {
				k.log.Warn("error setting enum btf value \"syscall\" %d", retVal)
			}
		} else {
			retVal := bpf.AddEnumBtfValue(btf, "syscall", 0)
			if retVal < 0 {
				k.log.Warn("error clearing enum btf value \"syscall\" %d", retVal)
			}
		}
		retVal := bpf.AddEnumBtfValue(btf, "nspid_type", nspid_type)
		if retVal < 0 {
			k.log.Warn("error setting enum btf value \"nspid_type\" %d", retVal)
		}
		retVal = bpf.AddEnumBtfValue(btf, "nspid_value", nspid_filter)
		if retVal < 0 {
			k.log.Warn("error setting enum btf value \"nspid_value\" %d", retVal)
		}

		retVal = bpf.AddEnumBtfValue(btf, "pid_type", pid_type)
		if retVal < 0 {
			k.log.Warn("error setting enum btf value \"pid_type\" %d", retVal)
		}
		retVal = bpf.AddEnumBtfValue(btf, "pid_value", pid_filter)
		if retVal < 0 {
			k.log.Warn("error setting enum btf value \"pid_value\" %d", retVal)
		}

		retVal = bpf.AddEnumBtfValue(btf, "pidset_value", pidset_value)
		if retVal < 0 {
			k.log.Warn("error setting enum btf value \"pidset_value\" %d", retVal)
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
		load.Observer__program = HubbleLib + "bpf_generic_kprobe.o"
		load.observer__label = "kprobe/generic_kprobe"
		load.observer__attach = funcName
		load.observer__prog = "kfprobe" + "_" + funcName
		load.retProbe = false
		load.errorFatal = true
		load.probeType = "generic_kprobe"
		load.loadState = bpfLoadStateIdle()
		load.tracefd = -1

		if is_retprobe {
			loadret := &bpfLoad{}
			loadret.observer__x64_attach = funcName
			loadret.Observer__program = HubbleLib + "bpf_generic_retkprobe.o"
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
	}
}

func (k *ObserverKprobe) loadGenericKprobeSensor(load *bpfLoad, version, verbose int, x64 bool) (error, int) {
	var attach string

	btf := genericKprobeLoadArgs[load.observer__attach].btf
	args := genericKprobeLoadArgs[load.observer__attach].args
	// we don't actually need retprobe here but might be useful in the future for dbg?
	retprobe := genericKprobeLoadArgs[load.observer__attach].retprobe

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
		args.args0)
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
		case GenericKprobeCharBuffer:
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

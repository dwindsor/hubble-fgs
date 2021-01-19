package observer

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/covalentio/hubble-fgs/pkg/api"
	"github.com/covalentio/hubble-fgs/pkg/bpf"
)

const (
	GenericKprobeStringType = 1
	GenericKprobeIntType    = 2
	GenericKprobeSkbType    = 3
	GenericKprobeSizeType   = 4
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
)

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

var (
	// A map of BTF images. generic_kprobe_name -> btf
	genericKprobeBtf  map[string]uintptr
	genericKprobeId   map[uint64][]int
	genericKprobeName map[uint64]string
)

func (k *ObserverKprobe) initKprobeSensors() {
	genericKprobeBtf = make(map[string]uintptr, 1)
	genericKprobeId = make(map[uint64][]int, 1)
	genericKprobeName = make(map[uint64]string, 1)
}

func (k *ObserverKprobe) createGenericKprobeSensors(sensorList, btfBaseFile string) *observerSensor {
	var progs []*bpfLoad

	if sensorList == "" {
		return nil
	}

	sensors := strings.Split(sensorList, ",")
	// sensors <- function(arg1:arg2:arg3:arg4:arg5)[attributes]
	for i, s := range sensors {
		var argPrinters []int
		var is_syscall bool

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

		for j, f := range args {
			argType := kprobeStrToTypeId(f)
			retVal := bpf.AddEnumBtfValue(btf, kprobeArgToString(j), argType)
			if retVal < 0 {
				k.log.Warn("error add enum btf value %d", retVal)
			}
			argPrinters = append(argPrinters, argType)
		}

		// Write attributes into BTF ptr for use with load
		if attributes != nil {
			attrsSplit := strings.Split(attributes[0], ":")
			for _, f := range attrsSplit {
				switch f {
				// Inform datapath that this kprobe is a syscall
				case "syscall":
					is_syscall = true
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

		genericKprobeBtf[funcName] = btf
		genericKprobeId[uint64(i)] = argPrinters
		genericKprobeName[uint64(i)] = funcName

		load := &bpfLoad{}
		load.Observer__program = HubbleLib + "bpf_generic_kprobe.o"
		load.observer__x64_attach = funcName
		load.observer__attach = funcName
		load.observer__label = "kprobe/generic_kprobe"
		load.observer__prog = "kfprobe" + "_" + funcName
		load.retProbe = false
		load.errorFatal = true
		load.probeType = "generic_kprobe"
		load.loadState = bpfLoadStateIdle()
		load.tracefd = -1

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

	return &observerSensor{
		name:  "__generic_kprobe_sensors__",
		progs: progs,
		maps:  maps,
	}
}

func (k *ObserverKprobe) loadGenericKprobeSensor(load *bpfLoad, version, verbose int, x64 bool) (error, int) {
	var attach string

	btf := genericKprobeBtf[load.observer__attach]
	if x64 {
		attach = load.observer__x64_attach
	} else {
		attach = load.observer__attach
	}
	return bpf.LoadKprobeProgram(
		version, verbose, btf,
		load.Observer__program,
		attach,
		load.observer__label,
		k.bpfDir+load.observer__prog,
		k.mapDir,
		load.retProbe)
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

	printerArgs := genericKprobeId[m.Id]
	for i, arg := range printerArgs {
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
			var b uint32
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
				k.log.WithError(err).Warnf("Size type error")
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

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
)

func kprobeStrToTypeId(arg string) int {
	switch arg {
	case "string":
		return GenericKprobeStringType
	case "int":
		return GenericKprobeIntType
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
	genericKprobeBtf map[string]uintptr
	genericKprobeId  map[uint64][]int
)

func (k *ObserverKprobe) initKprobeSensors() {
	genericKprobeBtf = make(map[string]uintptr, 1)
	genericKprobeId = make(map[uint64][]int, 1)
}

func (k *ObserverKprobe) createGenericKprobeSensors(sensorList, btfBaseFile string) *observerSensor {
	var progs []*bpfLoad

	fmt.Printf("loading sensors %s btfBase %s\n", sensorList, btfBaseFile)
	sensors := strings.Split(sensorList, ",")
	// sensors <- function(arg1:arg2:arg3:arg4:arg5)
	for i, s := range sensors {
		var argPrinters []int

		funcSplit := strings.Split(s, "(")
		fmt.Printf("funcSplit %s\n", funcSplit)
		filterSplit := strings.Split(funcSplit[1], ")")
		funcName := funcSplit[0]
		args := strings.Split(filterSplit[0], ":")

		// Write args into BTF ptr for use with load
		btf := bpf.GetBTF(btfBaseFile)
		ret := bpf.AddEnumBtf(btf, genericFuncArgsEnum, 4)
		if ret < 0 {
			fmt.Printf("error add enum args %d\n", ret)
		}
		ret = bpf.AddEnumBtfValue(btf, kprobeGenericId, i)
		if ret < 0 {
			fmt.Printf("error add enum gen id value %d\n", ret)
		}

		for j, f := range args {
			argType := kprobeStrToTypeId(f)
			retVal := bpf.AddEnumBtfValue(btf, kprobeArgToString(j), argType)
			if retVal < 0 {
				fmt.Printf("error add enum btf value %d\n", retVal)
			}
			argPrinters = append(argPrinters, argType)
		}
		genericKprobeBtf[funcName] = btf
		genericKprobeId[uint64(i)] = argPrinters

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
		&ObserverTCPMonMap,
		&ObserverExecveMap,
		&ObserverSocketMap,
		&ObserverExecveStats,
		&ObserverSocketStats,
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
	err := binary.Read(r, binary.LittleEndian, &m)
	if err != nil {
		k.log.WithError(err).Warnf("Failed to read process call msg")
		return
	}

	printerArgs := genericKprobeId[m.Id]
	fmt.Printf("%d(", m.Id)
	for _, arg := range printerArgs {
		switch arg {
		case GenericKprobeIntType:
			var output uint32

			err := binary.Read(r, binary.LittleEndian, &output)
			if err != nil {
				k.log.WithError(err).Warnf("Int type error")
			}
			fmt.Printf("%i", output)
		case GenericKprobeStringType:
			var b uint32

			err := binary.Read(r, binary.LittleEndian, &b)
			if err != nil {
				k.log.WithError(err).Warnf("StringSz type err")
			}
			fmt.Printf("[%d]", b)
			outputStr := make([]byte, b)
			err = binary.Read(r, binary.LittleEndian, &outputStr)
			if err != nil {
				k.log.WithError(err).Warnf("String type err")
			}

			fmt.Printf("%s,", outputStr)
		}
	}
	fmt.Printf(")\n")
}

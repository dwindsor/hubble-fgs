// Copyright 2021 Authors of Hubble
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package observer

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"path"

	"github.com/covalentio/hubble-fgs/pkg/api"
	"github.com/covalentio/hubble-fgs/pkg/bpf"
	"github.com/covalentio/hubble-fgs/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/covalentio/hubble-fgs/pkg/tracepoint"
)

const (
	// NB: this should match the size of ->args[] of the output message
	genericTP_OutputSize = 9000
	// maximum arguments that bpf-side supports
	genericTP_MaxArgs = 5
)

var (
	// Tracepoint information (genericTracepoint) is needed at load time
	// and at the time we process the perf event from bpf-side. We keep
	// this information on a table index by a (unique) tracepoint id.
	genericTracepointTable = tracepointTable{}
)

// genericTracepoint is the internal representation of a tracepoint
type genericTracepoint struct {
	Info *tracepoint.Tracepoint
	args []genericTracepointArg

	Filters    []v1alpha1.PIDFilter
	ArgFilters []v1alpha1.ArgFilter

	// index to access this on genericTracepointTable
	tableIdx int
}

// genericTracepointArg is the internal representation of an output value of a
// generic tracepoint.
type genericTracepointArg struct {
	CtxOffset int    // offset within tracepoint ctx
	ArgIdx    uint32 // index in genericTracepoint.args
	TpIdx     int    // index in the tracepoint arguments

	// Meta field: the user defines the meta argument in terms of the
	// tracepoint arguments (MetaTp), but we have to translate it to
	// the ebpf-side arguments (MetaArgIndex).
	// MetaTp
	//  0  -> no metadata information
	//  >0 -> metadata are in the MetaTp of the tracepoint args (1-based)
	//  -1 -> metadata are in retprobe
	MetaTp  int
	MetaArg int

	// this is true if the argument is need to be read, but it's not going
	// to be part of the output. This is needed for arguments that hold
	// metadata but are not part of the output.
	nopTy bool

	// format of the field
	format *tracepoint.TracepointFieldFormat

	// bpf generic type
	genericTypeId int

	argFiltersConf []v1alpha1.ArgFilter
}

// tracepointTable is, for now, an array.
type tracepointTable struct {
	arr []*genericTracepoint
}

// addTracepoint adds a tracepoint to the table, and sets its .tableIdx field
// to be the index to retrieve it from the table.
func (t *tracepointTable) addTracepoint(tp *genericTracepoint) {
	idx := len(t.arr)
	t.arr = append(t.arr, tp)
	tp.tableIdx = idx
}

// getTracepoint retrieves a tracepoint from the table using its id
func (t *tracepointTable) getTracepoint(idx int) (*genericTracepoint, error) {
	if idx < len(t.arr) {
		return t.arr[idx], nil
	} else {
		return nil, fmt.Errorf("tracepoint table: invalid id:%d (len=%d)", idx, len(t.arr))
	}
}

// GenericTracepointConf is the configuration for a generic tracepoint. This is
// a caller-defined structure that configures a tracepoint.
type GenericTracepointConf = v1alpha1.TracepointSpec

// GenericTracepointConfArg represents an argument of a generic tracepoint
//
// This points to the index of the argument.
// (Another option might be to specify this by name)
type GenericTracepointConfArg v1alpha1.TracepointArg

// getTracepointMetaArg is a temporary helper to find meta values while tracepoint
// converts into new CRD and config formats.
func getTracepointMetaValue(arg *GenericTracepointConfArg) int {
	if arg.SizeArgIndex > 0 {
		return int(arg.SizeArgIndex)
	}
	if arg.ReturnCopy {
		return -1
	}
	return 0
}

// NB: making this a method of GenericTracepointConfArg means that we can have
// this as an interface (e.g,. for implementing output by name)
func (conf *GenericTracepointConfArg) configureTracepointArg(tp *genericTracepoint) error {
	if conf.Index >= uint32(len(tp.Info.Format.Fields)) {
		return fmt.Errorf("tracepoint %s/%s has %d fields but field %d was requested",
			tp.Info.Subsys, tp.Info.Event, len(tp.Info.Format.Fields), conf.Index)
	}
	field := tp.Info.Format.Fields[conf.Index]

	metaTpIndex := getTracepointMetaValue(conf)

	argIdx := uint32(len(tp.args))
	tp.args = append(tp.args, genericTracepointArg{
		CtxOffset:     int(field.Offset),
		ArgIdx:        argIdx,
		TpIdx:         int(conf.Index),
		MetaTp:        metaTpIndex,
		nopTy:         false,
		format:        &field,
		genericTypeId: invalidTypeId,
	})
	return nil
}

func (o *genericTracepointArg) String() string {
	return fmt.Sprintf("genericTracepointArg{CtxOffset: %d format: %+v}", o.CtxOffset, o.format)
}

func (out *genericTracepointArg) setGenericTypeId() error {
	ret, err := out.getGenericTypeId()
	out.genericTypeId = ret
	return err
}

// getGenericTypeId: returns the generic type Id of a tracepoint argument
// if such an id cannot be termined, it returns an invalidTypeId and an error
func (out *genericTracepointArg) getGenericTypeId() (int, error) {

	if out.format == nil {
		return invalidTypeId, errors.New("format is nil")
	}

	if out.format.Field == nil {
		err := out.format.ParseField()
		if err != nil {
			return invalidTypeId, fmt.Errorf("failed to parse field: %w", err)
		}
	}

	switch ty := out.format.Field.Type.(type) {
	case tracepoint.IntTy:
		if out.format.Size == 4 && out.format.IsSigned {
			return GenericKprobeS32Type, nil
		} else if out.format.Size == 4 && !out.format.IsSigned {
			return GenericKprobeU32Type, nil
		} else if out.format.Size == 8 && out.format.IsSigned {
			return GenericKprobeS64Type, nil
		} else if out.format.Size == 8 && !out.format.IsSigned {
			return GenericKprobeU64Type, nil
		}
	case tracepoint.PointerTy:
		// char *
		intTy, ok := ty.Ty.(tracepoint.IntTy)
		if !ok {
			return invalidTypeId, fmt.Errorf("cannot handle pointer type to %T", ty)
		}
		if intTy.Base == tracepoint.IntTyChar {
			// NB: there is no way to determine if this is a string
			// or a buffer without user information or something we
			// build manually ourselves. For now, we only deal with
			// buffers and expect a metadata argument.
			if out.MetaTp == 0 {
				return invalidTypeId, errors.New("no metadata field for buffer")
			}
			return GenericKprobeCharBuffer, nil
		}

	case tracepoint.SizeTy:
		return GenericKprobeSizeType, nil
	}

	return invalidTypeId, fmt.Errorf("Unknown type: %T", out.format.Field.Type)
}

// createGenericTracepoint creates the genericTracepoint information based on
// the user-provided configuration
func createGenericTracepoint(conf *GenericTracepointConf) (*genericTracepoint, error) {
	tp := tracepoint.Tracepoint{
		Subsys: conf.Subsystem,
		Event:  conf.Event,
	}

	if err := tp.LoadFormat(); err != nil {
		return nil, fmt.Errorf("tracepoint %s/%s not supported: %w", tp.Subsys, tp.Event, err)
	}

	ret := &genericTracepoint{
		Info:       &tp,
		Filters:    conf.Filters.PIDs,
		ArgFilters: conf.Filters.Args,
	}

	for i, _ := range conf.Args {
		arg := GenericTracepointConfArg{
			Index:        conf.Args[i].Index,
			SizeArgIndex: conf.Args[i].SizeArgIndex,
			ReturnCopy:   conf.Args[i].ReturnCopy,
		}
		if err := arg.configureTracepointArg(ret); err != nil {
			return nil, err
		}
	}

	getOrAppend := func(metaTp int) (*genericTracepointArg, error) {
		tpIdx := metaTp - 1
		for i := range ret.args {
			if ret.args[i].TpIdx == tpIdx {
				return &ret.args[i], nil
			}
		}

		if tpIdx >= len(ret.Info.Format.Fields) {
			return nil, fmt.Errorf(
				"tracepoint %s/%s has %d fields but field %d was requested in a metadata argument",
				ret.Info.Subsys, ret.Info.Event, len(ret.Info.Format.Fields), tpIdx)
		}
		field := ret.Info.Format.Fields[tpIdx]
		argIdx := uint32(len(ret.args))
		ret.args = append(ret.args, genericTracepointArg{
			CtxOffset:     int(field.Offset),
			ArgIdx:        argIdx,
			TpIdx:         tpIdx,
			MetaTp:        0,
			MetaArg:       0,
			nopTy:         true,
			format:        &field,
			genericTypeId: invalidTypeId,
		})
		return &ret.args[argIdx], nil
	}

	for idx := 0; idx < len(ret.args); idx += 1 {
		meta := ret.args[idx].MetaTp
		if meta == 0 || meta == -1 {
			ret.args[idx].MetaArg = meta
			continue
		}
		if a, err := getOrAppend(meta); err != nil {
			return nil, err
		} else {
			ret.args[idx].MetaArg = int(a.ArgIdx) + 1
		}
	}

	genericTracepointTable.addTracepoint(ret)
	return ret, nil
}

// createGenericTracepointSensor will create a sensor that can be loaded based on a generic tracepoint configuration
func (k *ObserverKprobe) createGenericTracepointSensor(confs []GenericTracepointConf) (*observerSensor, error) {

	tracepoints := make([]*genericTracepoint, 0, len(confs))
	for _, conf := range confs {
		tp, err := createGenericTracepoint(&conf)
		if err != nil {
			return nil, err
		}
		tracepoints = append(tracepoints, tp)
	}

	maps := []*ObserverMap{}
	progs := make([]*bpfLoad, 0, len(tracepoints))
	for _, tp := range tracepoints {
		attach := fmt.Sprintf("%s/%s", tp.Info.Subsys, tp.Info.Event)
		prog0 := bpfLoad{
			Observer__program:    path.Join(HubbleLib, "bpf_generic_tracepoint.o"),
			observer__x64_attach: attach,
			observer__attach:     attach,
			observer__label:      "tracepoint/generic_tracepoint",
			observer__prog:       fmt.Sprintf("tracepoint-%s-%s", tp.Info.Subsys, tp.Info.Event),
			retProbe:             false,
			errorFatal:           true,
			probeType:            "generic_tracepoint",
			loadState:            bpfLoadStateIdle(),
			tracefd:              -1,
			loaderData:           tp.tableIdx,
		}
		progs = append(progs, &prog0)
	}

	return &observerSensor{
		name:  "generic_tracepoint_sensor",
		progs: progs,
		maps:  maps,
	}, nil
}

func (k *ObserverKprobe) loadGenericTracepointSensor(load *bpfLoad, btfFile string, version, verbose int, x64 bool) (error, int) {

	btfCtxOffsetFn := func(i int) string {
		return fmt.Sprintf("t_arg%d_ctx_off", i)
	}

	tpIdx, ok := load.loaderData.(int)
	if !ok {
		return fmt.Errorf("loaderData for genericTracepoint %s is %T (%v) (not an int).", load.Observer__program, load.loaderData, load.loaderData), 0
	}

	tp, err := genericTracepointTable.getTracepoint(tpIdx)
	if err != nil {
		return fmt.Errorf("Could not find generic tracepoint information for %s: %w", load.observer__attach, err), 0
	}

	btfObj := bpf.GetBTF(btfFile)
	defer bpf.FreeBTF(btfObj)
	btfAddEnumValue := func(s string, val int) error {
		if ret := bpf.AddEnumBtfValue(btfObj, s, val); ret < 0 {
			return fmt.Errorf("failed to add %s=%d BTF value (error=%d)", s, val, ret)
		}
		return nil
	}

	ret := bpf.AddEnumBtf(btfObj, genericFuncArgsEnum, 4)
	if ret < 0 {
		return fmt.Errorf("failed to add %s=%d BTF enum (ret=%d)", genericFuncArgsEnum, 4, ret), 0
	}

	if err := btfAddEnumValue(kprobeGenericId, tp.tableIdx); err != nil {
		return err, 0
	}

	// iterate over output arguments
	for i := range tp.args {
		tpArg := &tp.args[i]
		if err := btfAddEnumValue(btfCtxOffsetFn(i), tpArg.CtxOffset); err != nil {
			return err, 0
		}

		err := tpArg.setGenericTypeId()
		if err != nil {
			return fmt.Errorf("output argument %v unsupported: %w\n", &tpArg, err), 0
		}

		if err := btfAddEnumValue(kprobeArgToString(i), tpArg.genericTypeId); err != nil {
			return err, 0
		}

		if err := btfAddEnumValue(kprobeArgMToString(i), tpArg.MetaArg); err != nil {
			return err, 0
		}

		k.log.Infof("configured argument #%d: %+v (type:%d)", i, tpArg, tpArg.genericTypeId)
	}

	// nop args
	for i := len(tp.args); i < genericTP_MaxArgs; i++ {
		if err := btfAddEnumValue(btfCtxOffsetFn(i), 0); err != nil {
			return err, 0
		}

		if err := btfAddEnumValue(kprobeArgToString(i), nopTypeId); err != nil {
			return err, 0
		}

		if err := btfAddEnumValue(kprobeArgMToString(i), 0); err != nil {
			return err, 0
		}
	}

	// TBD tp filters
	argFilters := make([]byte, 4096) //k.initKernelSelectors(tp.Selectors)

	var attach string
	if x64 {
		attach = load.observer__x64_attach
	} else {
		attach = load.observer__attach
	}

	return bpf.LoadTracepointArgsProgram(
		version, Verbosity,
		btfObj,
		load.Observer__program,
		attach,
		load.observer__label,
		k.bpfDir+load.observer__prog,
		k.mapDir,
		load.retProbe,
		argFilters)
}

func (k *ObserverKprobe) handleGenericTracepoint(r *bytes.Reader) {
	m := api.MsgGenericTracepoint{}
	err := binary.Read(r, binary.LittleEndian, &m)
	if err != nil {
		k.log.WithError(err).Warnf("Failed to read tracepoint")
		return
	}

	unix := &api.MsgGenericTracepointUnix{
		Common:     m.Common,
		ProcessKey: m.ProcessKey,
		Id:         m.Id,
		Subsys:     "UNKNOWN",
		Event:      "UNKNOWN",
	}

	tp, err := genericTracepointTable.getTracepoint(int(m.Id))
	if err != nil {
		k.log.WithField("id", m.Id).WithError(err).Warnf("genericTracepoint info not found")
		k.observerListenersGenericTracepoint(unix)
		return
	}

	unix.Subsys = tp.Info.Subsys
	unix.Event = tp.Info.Event

	for _, out := range tp.args {

		if out.nopTy {
			continue
		}

		switch out.genericTypeId {
		case GenericKprobeU64Type:
			var val uint64
			err := binary.Read(r, binary.LittleEndian, &val)
			if err != nil {
				k.log.WithError(err).Warnf("Size type error sizeof %d", m.Common.Size)
			}
			unix.Args = append(unix.Args, val)

		case GenericKprobeSizeType:
			var val uint64

			err := binary.Read(r, binary.LittleEndian, &val)
			if err != nil {
				k.log.WithError(err).Warnf("Size type error sizeof %d", m.Common.Size)
			}
			unix.Args = append(unix.Args, val)

		case GenericKprobeCharBuffer, GenericKprobeCharIovec:
			var b int32

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
				arg := string(outputStr[:])
				unix.Args = append(unix.Args, arg)
			} else if b == 0 {
				arg := "return value expected"
				unix.Args = append(unix.Args, arg)
			} else {
				arg := kprobeCharBufErrorToString(b)
				unix.Args = append(unix.Args, arg)
			}
		default:
			k.log.Warnf("handleGenericTracepoint: ignoring:  %+v", out)
		}
	}
	k.observerListenersGenericTracepoint(unix)
}

func (k *ObserverKprobe) observerListenersGenericTracepoint(msg *api.MsgGenericTracepointUnix) {
	for listener, _ := range k.listeners {
		if err := listener.Notify(msg); err != nil {
			k.log.Debug("Write failure removing Listener")
			k.RemoveListener(listener)
		}
	}
}

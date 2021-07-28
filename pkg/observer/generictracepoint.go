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
	"path"

	"github.com/isovalent/hubble-fgs/pkg/api"
	"github.com/isovalent/hubble-fgs/pkg/bpf"
	"github.com/isovalent/hubble-fgs/pkg/btf"
	"github.com/isovalent/hubble-fgs/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/isovalent/hubble-fgs/pkg/logger"
	"github.com/isovalent/hubble-fgs/pkg/selectors"
	"github.com/isovalent/hubble-fgs/pkg/tracepoint"
	"github.com/sirupsen/logrus"

	. "github.com/isovalent/hubble-fgs/pkg/generictypes"
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

	tracepointLog logrus.FieldLogger
)

type observerTracepointSensor struct {
	name string
}

func init() {
	tp := &observerTracepointSensor{
		name: "tracepoint sensor",
	}
	registerTracingSensorsAtIinit(tp.name, tp)
	RegisterEventHandlerAtInit(api.MSG_OP_GENERIC_TRACEPOINT, handleGenericTracepoint)
}

// genericTracepoint is the internal representation of a tracepoint
type genericTracepoint struct {
	Info *tracepoint.Tracepoint
	args []genericTracepointArg

	Selectors *v1alpha1.TracepointSpec

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
type GenericTracepointConfArg v1alpha1.KProbeArg

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
		genericTypeId: GenericInvalidType,
	})
	return nil
}

func (o *genericTracepointArg) String() string {
	return fmt.Sprintf("genericTracepointArg{CtxOffset: %d format: %+v}", o.CtxOffset, o.format)
}

func (out *genericTracepointArg) setGenericTypeId() (int, error) {
	ret, err := out.getGenericTypeId()
	out.genericTypeId = ret
	return ret, err
}

// getGenericTypeId: returns the generic type Id of a tracepoint argument
// if such an id cannot be termined, it returns an GenericInvalidType and an error
func (out *genericTracepointArg) getGenericTypeId() (int, error) {

	if out.format == nil {
		return GenericInvalidType, errors.New("format is nil")
	}

	if out.format.Field == nil {
		err := out.format.ParseField()
		if err != nil {
			return GenericInvalidType, fmt.Errorf("failed to parse field: %w", err)
		}
	}

	switch ty := out.format.Field.Type.(type) {
	case tracepoint.IntTy:
		if out.format.Size == 4 && out.format.IsSigned {
			return GenericS32Type, nil
		} else if out.format.Size == 4 && !out.format.IsSigned {
			return GenericU32Type, nil
		} else if out.format.Size == 8 && out.format.IsSigned {
			return GenericS64Type, nil
		} else if out.format.Size == 8 && !out.format.IsSigned {
			return GenericU64Type, nil
		}
	case tracepoint.PointerTy:
		// char *
		intTy, ok := ty.Ty.(tracepoint.IntTy)
		if !ok {
			return GenericInvalidType, fmt.Errorf("cannot handle pointer type to %T", ty)
		}
		if intTy.Base == tracepoint.IntTyChar {
			// NB: there is no way to determine if this is a string
			// or a buffer without user information or something we
			// build manually ourselves. For now, we only deal with
			// buffers and expect a metadata argument.
			if out.MetaTp == 0 {
				return GenericInvalidType, errors.New("no metadata field for buffer")
			}
			return GenericCharBuffer, nil
		}

	case tracepoint.SizeTy:
		return GenericSizeType, nil
	}

	return GenericInvalidType, fmt.Errorf("Unknown type: %T", out.format.Field.Type)
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
		Info:      &tp,
		Selectors: conf,
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
			genericTypeId: GenericInvalidType,
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
func createGenericTracepointSensor(confs []GenericTracepointConf) (*observerSensor, error) {

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

func LoadGenericTracepointSensor(bpfDir, mapDir string, load *bpfLoad, version, verbose int, x64 bool) (error, int) {
	tracepointLog = logger.GetLogger()

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

	btfObj, err := btf.NewBTF()
	if err != nil {
		return err, 0
	}
	defer btfObj.Close()
	btfAddEnumValue := func(s string, val int) error {
		if ret := btfObj.AddEnumValue(s, val); ret < 0 {
			return fmt.Errorf("failed to add %s=%d BTF value (error=%d)", s, val, ret)
		}
		return nil
	}

	ret := btfObj.AddEnum(genericFuncArgsEnum, 4)
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

		_, err := tpArg.setGenericTypeId()
		if err != nil {
			return fmt.Errorf("output argument %v unsupported: %w\n", &tpArg, err), 0
		}

		if err := btfAddEnumValue(kprobeArgToString(i), tpArg.genericTypeId); err != nil {
			return err, 0
		}

		if err := btfAddEnumValue(kprobeArgMToString(i), tpArg.MetaArg); err != nil {
			return err, 0
		}

		tracepointLog.Infof("configured argument #%d: %+v (type:%d)", i, tpArg, tpArg.genericTypeId)
	}

	// nop args
	for i := len(tp.args); i < genericTP_MaxArgs; i++ {
		if err := btfAddEnumValue(btfCtxOffsetFn(i), 0); err != nil {
			return err, 0
		}

		if err := btfAddEnumValue(kprobeArgToString(i), GenericNopType); err != nil {
			return err, 0
		}

		if err := btfAddEnumValue(kprobeArgMToString(i), 0); err != nil {
			return err, 0
		}
	}

	// actions nop
	if err := btfAddEnumValue("sigkill", 0); err != nil {
		return err, 0
	}

	// rewrite arg index
	for i := range tp.args {
		tpArg := &tp.args[i]

		ty, err := tpArg.setGenericTypeId()
		if err != nil {
			return fmt.Errorf("output argument %v unsupported: %w\n", &tpArg, err), 0
		}

		if len(tp.Selectors.Args) > i && tp.Selectors.Args[i].Type == "" {
			tp.Selectors.Args[i].Type = selectors.ArgTypeToString(uint32(ty))
		}

		// could we rewrite and then catch it again :/
		fmt.Printf("tpArg: TpIdx %d, ArgIdx %d\n", tpArg.TpIdx, tpArg.ArgIdx)
		for j, arg := range tp.Selectors.Args {
			if arg.Index == uint32(tpArg.TpIdx) {
				tp.Selectors.Args[j].Index = tpArg.ArgIdx
			}
		}
		for j, s := range tp.Selectors.Selectors {
			for k, match := range s.MatchArgs {
				if match.Index == uint32(tpArg.TpIdx) {
					tp.Selectors.Selectors[j].MatchArgs[k].Index = uint32(tpArg.ArgIdx)
				}
			}
		}
	}

	kernelSelectors, err := selectors.InitTracepointSelectors(tp.Selectors)
	if err != nil {
		return err, 0
	}

	var attach string
	if x64 {
		attach = load.observer__x64_attach
	} else {
		attach = load.observer__attach
	}

	return bpf.LoadTracepointArgsProgram(
		version, Verbosity,
		uintptr(btfObj),
		load.Observer__program,
		attach,
		load.observer__label,
		bpfDir+load.observer__prog,
		mapDir,
		load.retProbe,
		kernelSelectors)
}

func handleGenericTracepoint(r *bytes.Reader) (interface{}, error) {
	m := api.MsgGenericTracepoint{}
	err := binary.Read(r, binary.LittleEndian, &m)
	if err != nil {
		return nil, fmt.Errorf("Failed to read tracepoint: %w", err)
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
		logger.GetLogger().WithField("id", m.Id).WithError(err).Warnf("genericTracepoint info not found")
		return unix, nil
	}

	unix.Subsys = tp.Info.Subsys
	unix.Event = tp.Info.Event

	for idx, out := range tp.args {

		if out.nopTy {
			continue
		}

		switch out.genericTypeId {
		case GenericU64Type:
			var val uint64
			err := binary.Read(r, binary.LittleEndian, &val)
			if err != nil {
				logger.GetLogger().WithError(err).Warnf("Size type error sizeof %d", m.Common.Size)
			}
			unix.Args = append(unix.Args, val)

		case GenericSizeType:
			var val uint64

			err := binary.Read(r, binary.LittleEndian, &val)
			if err != nil {
				logger.GetLogger().WithError(err).Warnf("Size type error sizeof %d", m.Common.Size)
			}
			unix.Args = append(unix.Args, val)

		case GenericCharBuffer, GenericCharIovec:
			if arg, err := ReadArgBytes(r, idx); err == nil {
				unix.Args = append(unix.Args, arg.Value)
			} else {
				logger.GetLogger().WithError(err).Warnf("failed to read bytes argument")
			}

		default:
			logger.GetLogger().Warnf("handleGenericTracepoint: ignoring:  %+v", out)
		}
	}
	return unix, nil
}

func (t *observerTracepointSensor) specHandler(spec *v1alpha1.TracingPolicySpec) (*observerSensor, error) {
	if len(spec.KProbes) > 0 && len(spec.Tracepoints) > 0 {
		return nil, errors.New("tracing policies with both kprobes and tracepoints are not currently supported")
	}
	if len(spec.Tracepoints) > 0 {
		return createGenericTracepointSensor(spec.Tracepoints)
	}
	return nil, nil
}

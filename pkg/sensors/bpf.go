//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package sensors

import (
	"fmt"

	"github.com/cilium/ebpf"
)

func ProgramBuilder(
	objFile, attach, label, pinFile string,
	ty string,
) *Program {
	return &Program{
		objFile, attach, label, pinFile, false, true, ty,
		Idle(), -1, struct{}{},
	}
}

func GetProgramInfo(l *Program) (program, label, prog string) {
	return l.Name, l.Label, l.PinPath
}

// Program reprents a BPF program.
type Program struct {
	// Name is the name of the BPF object file.
	Name string
	// Attach is the attachment point, e.g. the kernel function.
	Attach string
	// Label is the program section name to load from program.
	Label string
	// PinPath is the pinned path to this program. Note this is a relative path
	// based on the BPF directory FGS is running under.
	PinPath string

	// RetProbe indicates whether a kprobe is a kretprobe.
	RetProbe bool
	// ErrorFatal indicates whether a program must load and fatal otherwise.
	// Most program will set this to true. For example, kernel functions hooks
	// may change across verions so different names are attempted, hence
	// avoiding fataling when the first attempt fails.
	ErrorFatal bool

	// Type is the type of BPF program. For example, tc, skb, tracepoint,
	// etc.
	Type      string
	LoadState State

	// TraceFD is needed because tracepoints are added different than kprobes
	// for example. The FD is to keep a reference to the tracepoint program in
	// order to delete it. TODO: This can be moved into loaderData for
	// tracepoints.
	traceFD int

	// LoaderData represents per-type specific fields.
	LoaderData interface{}
}

func (p *Program) SetRetProbe(ret bool) *Program {
	p.RetProbe = ret
	return p
}

func (p *Program) SetLoaderData(d interface{}) *Program {
	p.LoaderData = d
	return p
}

// State represents the state of a BPF program or map.
//
// NB: Currently there is no case where we attempt to load a program that is
// already loaded. If this changes, we can use the count as a reference count
// to track users of a bpf program.
type State struct {
	//   0: idle (not loaded)
	//   1: loaded
	//  -1: disabled
	count int
}

func Idle() State {
	return State{0}
}

func (s *State) IsLoaded() bool {
	return s.count > 0
}

func (s State) IsDisabled() bool {
	return s.count == -1
}

func (s *State) SetDisabled() {
	if s.IsLoaded() {
		panic(fmt.Errorf("called SetDisabled() while program is loaded (cnt: %d)", s.count))
	}
	s.count = -1
}

func (s *State) SetLoaded() {
	if s.IsDisabled() {
		panic(fmt.Errorf("called SetLoaded() while program is disabled (cnt: %d)", s.count))
	}
	s.count = 1
}

// Map represents BPF maps.
type Map struct {
	Name      string
	Prog      *Program
	PinState  State
	mapHandle *ebpf.Map
}

func MapBuilder(name string, ld *Program) *Map {
	return &Map{name, ld, Idle(), nil}
}

func (m *Map) Close() error {
	if m.mapHandle != nil {
		err := m.mapHandle.Close()
		m.mapHandle = nil
		return err
	}
	m.PinState = Idle()
	return nil
}

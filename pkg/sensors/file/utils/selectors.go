//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package file

import (
	"fmt"
	"path/filepath"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/selectors"
	"github.com/cilium/tetragon/pkg/sensors/tracing"
	"github.com/isovalent/hubble-fgs/pkg/sensors/base"
)

const (
	FileOperationTypePost  = uint32(tetragon.FileOperation_FILE_OP_POST)
	FileOperationTypeBlock = uint32(tetragon.FileOperation_FILE_OP_BLOCK)
)

var fileActionTypeTable = map[string]uint32{
	"post":  FileOperationTypePost,
	"block": FileOperationTypeBlock,
}

type KernelSelectorState struct {
	selectors.KernelSelectorState

	// matchBinaries mappings
	selOpsOp  uint32
	selOpsMap sync.Map

	// matchActions value
	action uint32
}

func NewKernelSelectorState() *KernelSelectorState {
	return &KernelSelectorState{
		KernelSelectorState: *selectors.NewKernelSelectorState(),
	}
}

func (k *KernelSelectorState) SetOperationOp(op uint32) {
	k.selOpsOp = op
}

func (k *KernelSelectorState) GetOperationOp() uint32 {
	return k.selOpsOp
}

func (k *KernelSelectorState) GetOpsSelMap() map[uint32]uint32 {
	retMap := make(map[uint32]uint32)
	k.selOpsMap.Range(func(key, val any) bool {
		retMap[key.(uint32)] = val.(uint32)
		return true
	})
	return retMap
}

func (k *KernelSelectorState) AddOpsVal(op, val uint32) {
	k.selOpsMap.LoadOrStore(op, val)
}

func writeBinaryMap(m *ebpf.Map, id uint32, path string) error {
	p := [256]byte{0}
	copy(p[:], path)
	k := &tracing.BinaryMapKey{PathName: p}
	v := &tracing.BinaryMapValue{Id: uint32(id)}
	return m.Update(k, v, ebpf.UpdateAny)
}

func UpdateNamesMap(mapDir string, sel *KernelSelectorState) error {
	m, err := ebpf.LoadPinnedMap(filepath.Join(mapDir, base.NamesMap.Name), nil)
	if err != nil {
		return err
	}
	defer m.Close()

	for i, path := range sel.GetNewBinaryMappings() {
		if err := writeBinaryMap(m, i, path); err != nil {
			return err
		}
	}
	return nil
}

func GenerateFileNamesMap(m *ebpf.Map, sel *KernelSelectorState) error {
	allEntries := sel.GetBinSelNamesMap()
	if len(allEntries) == 0 {
		return nil
	}

	binEntries, ok := allEntries[0] // we support only a single selector in FIM for now
	if !ok {
		return nil
	}

	entries := binEntries.GetBinSelNamesMap()
	if len(entries) == 0 { // no matchBinaries selectors
		return nil
	}

	// add a special entry (key == UINT32_MAX) that has as a value the number of matchBinaries entry
	// if this is zero we don't have any matchBinaries selectors
	if err := m.Update(uint32(0xffffffff), sel.GetBinaryOp(0), ebpf.UpdateAny); err != nil {
		return err
	}

	for idx, val := range entries {
		if err := m.Update(idx, val, ebpf.UpdateAny); err != nil {
			return err
		}
	}

	return nil
}

func GenerateFileOpsMap(m *ebpf.Map, sel *KernelSelectorState) error {
	entries := sel.GetOpsSelMap()
	if len(entries) == 0 { // no matchOperations selectors
		return nil
	}

	// add a special entry (key == UINT32_MAX) that has as a value the number of matchOperations entry
	// if this is zero we don't have any matchOperations selectors
	if err := m.Update(uint32(0xffffffff), sel.GetOperationOp(), ebpf.UpdateAny); err != nil {
		return err
	}

	for op, val := range entries {
		if err := m.Update(op, val, ebpf.UpdateAny); err != nil {
			return err
		}
	}

	return nil
}

func GenerateFileActionsMap(m *ebpf.Map, sel *KernelSelectorState) error {
	return m.Update(uint32(0), sel.action, ebpf.UpdateAny)
}

func ParseMatchOperation(k *KernelSelectorState, b *v1alpha1.OperationSelector) error {
	op, err := selectors.SelectorOp(b.Operator)
	if err != nil {
		return fmt.Errorf("matchOperation error: %w", err)
	}
	if op != selectors.SelectorOpIn && op != selectors.SelectorOpNotIn {
		return fmt.Errorf("matchOperation error: Only In and NotIn operators are supported")
	}
	k.SetOperationOp(op)
	for _, s := range b.Values {
		val, ok := tetragon.FileAction_value[strings.ToUpper(s)]
		if !ok {
			return fmt.Errorf("unknown value in matchOperation: %s", s)
		}
		k.AddOpsVal(uint32(val), 1)
	}
	return nil
}

func ParseMatchOperations(k *KernelSelectorState, ops []v1alpha1.OperationSelector) error {
	if len(ops) > 1 {
		return fmt.Errorf("only support single operations selector")
	}
	for _, s := range ops {
		if err := ParseMatchOperation(k, &s); err != nil {
			return err
		}
	}
	return nil
}

func ParseMatchActions(k *KernelSelectorState, actions []v1alpha1.FileActionSelector) error {
	if len(actions) > 1 {
		return fmt.Errorf("only support single actions selector")
	}
	for _, a := range actions {
		act, ok := fileActionTypeTable[strings.ToLower(a.Action)]
		if !ok {
			return fmt.Errorf("parseMatchAction: ActionType %s unknown", a.Action)
		}
		k.action |= act
	}
	return nil
}

func parseSelector(k *KernelSelectorState, fileSel *v1alpha1.FileSelector) error {
	if err := selectors.ParseMatchBinaries(&k.KernelSelectorState, fileSel.MatchBinaries, 0); err != nil {
		return fmt.Errorf("parseMatchBinaries error: %w", err)
	}
	if err := ParseMatchOperations(k, fileSel.MatchOperations); err != nil {
		return fmt.Errorf("parseMatchOperations error: %w", err)
	}
	if err := ParseMatchActions(k, fileSel.MatchActions); err != nil {
		return fmt.Errorf("parseMatchActions error: %w", err)
	}
	return nil
}

func (k *KernelSelectorState) NeedEnforcement() bool {
	return (k.action & FileOperationTypeBlock) != 0
}

func InitKernelSelectorState(fileSel []v1alpha1.FileSelector) (*KernelSelectorState, error) {
	if len(fileSel) > 1 {
		return nil, fmt.Errorf("file monitoring supports up to 1 selector")
	}

	kernelSelectors := NewKernelSelectorState()
	for _, s := range fileSel {
		if err := parseSelector(kernelSelectors, &s); err != nil {
			return nil, err
		}
	}
	return kernelSelectors, nil
}

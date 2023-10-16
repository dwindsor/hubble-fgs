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
	"strconv"
	"strings"
	"sync"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/selectors"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/tracing"
	"github.com/isovalent/hubble-fgs/pkg/api/fileapi"
	"github.com/isovalent/hubble-fgs/pkg/sensors/base"
)

const (
	FileOperationTypePost  = uint32(tetragon.FileOperation_FILE_OP_POST)
	FileOperationTypeBlock = uint32(tetragon.FileOperation_FILE_OP_BLOCK)

	MaxFimSelectors = 6 // should match MAX_FIM_SELECTORS in bpf/file/bpf_file.h
)

var fileActionTypeTable = map[string]uint32{
	"post":  FileOperationTypePost,
	"block": FileOperationTypeBlock,
}

type SelOps struct {
	opVal  uint32
	opsMap sync.Map
}

type KernelSelectorState struct {
	selectors.KernelSelectorState

	// matchOperations mappings
	operations map[uint32]*SelOps

	// matchDigests mappings
	digests map[uint32]*SelDigests

	// matchActions value
	action map[uint32]uint32

	// number of selectors
	num uint32
}

func NewKernelSelectorState() *KernelSelectorState {
	return &KernelSelectorState{
		KernelSelectorState: *selectors.NewKernelSelectorState(nil, nil),
		operations:          map[uint32]*SelOps{},
		digests:             map[uint32]*SelDigests{},
		action:              map[uint32]uint32{},
	}
}

func (k *KernelSelectorState) GetNumSelectors() uint32 {
	return k.num
}

func (k *SelOps) SetOperationOp(op uint32) {
	k.opVal = op
}

func (k *SelOps) GetOperationOp() uint32 {
	return k.opVal
}

func (k *SelOps) GetOpsSelMap() map[uint32]uint32 {
	retMap := make(map[uint32]uint32)
	k.opsMap.Range(func(key, val any) bool {
		retMap[key.(uint32)] = val.(uint32)
		return true
	})
	return retMap
}

func (k *SelOps) GetOpsSelMapSize() uint32 {
	numItems := uint32(0)
	k.opsMap.Range(func(key, val any) bool {
		numItems++
		return true
	})
	return numItems
}

func (k *SelOps) AddOpsVal(op, val uint32) {
	k.opsMap.LoadOrStore(op, val)
}

func (k *KernelSelectorState) InitOrGetOperations(selIdx uint32) *SelOps {
	val, ok := k.operations[selIdx]
	if ok {
		return val
	}
	inner := &SelOps{}
	k.operations[selIdx] = inner
	return inner
}

func (k *KernelSelectorState) GetOpsEntries() map[uint32]*SelOps {
	return k.operations
}

type SelDigests struct {
	digVal uint32
	digMap sync.Map
}

func (k *SelDigests) SetDigestOp(op uint32) {
	k.digVal = op
}

func (k *SelDigests) GetDigestOp() uint32 {
	return k.digVal
}

func (k *SelDigests) GetDigestsSelMap() map[fileapi.DigestKey]uint32 {
	retMap := make(map[fileapi.DigestKey]uint32)
	k.digMap.Range(func(key, val any) bool {
		retMap[key.(fileapi.DigestKey)] = val.(uint32)
		return true
	})
	return retMap
}

func (k *SelDigests) GetDigestsSelMapSize() uint32 {
	numItems := uint32(0)
	k.digMap.Range(func(key, val any) bool {
		numItems++
		return true
	})
	return numItems
}

func (k *SelDigests) AddDigestsVal(op fileapi.DigestKey, val uint32) {
	k.digMap.LoadOrStore(op, val)
}

func (k *KernelSelectorState) InitOrGetDigests(selIdx uint32) *SelDigests {
	val, ok := k.digests[selIdx]
	if ok {
		return val
	}
	inner := &SelDigests{}
	k.digests[selIdx] = inner
	return inner
}

func (k *KernelSelectorState) GetDigestEntries() map[uint32]*SelDigests {
	return k.digests
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

func GetMaxInnerEntriesNamesMap(sel *KernelSelectorState) uint32 {
	maxEntries := 0
	for _, entry := range sel.GetBinSelNamesMap() {
		num := len(entry.GetBinSelNamesMap())
		if num > maxEntries {
			maxEntries = num
		}
	}
	return uint32(maxEntries) + 1 // for the special entry UINT32_MAX
}

func GenerateFileNamesMap(outerMap *ebpf.Map, sel *KernelSelectorState, pinPathPrefix string) error {
	maxEntries := GetMaxInnerEntriesNamesMap(sel)
	for innerID, entry := range sel.GetBinSelNamesMap() {
		entries := entry.GetBinSelNamesMap()
		// in order kernels we should provide the maximum number of inner map entries
		maxInnerEntries := uint32(len(entries)) + 1 // for the special entry UINT32_MAX
		if !kernels.MinKernelVersion("5.9") {
			// Versions before 5.9 do not allow inner maps to have different sizes.
			// See: https://lore.kernel.org/bpf/20200828011800.1970018-1-kafai@fb.com/
			maxInnerEntries = maxEntries
		}

		innerName := fmt.Sprintf("file_names_map_%d", innerID)
		innerSpec := &ebpf.MapSpec{
			Name:       innerName,
			Type:       ebpf.Hash,
			KeySize:    4, // uint32
			ValueSize:  4, // uint32
			MaxEntries: maxInnerEntries,
		}
		innerMap, err := ebpf.NewMapWithOptions(innerSpec, ebpf.MapOptions{
			PinPath: sensors.PathJoin(pinPathPrefix, innerName),
		})
		if err != nil {
			return fmt.Errorf("creating innerMap %s failed: %w", innerName, err)
		}
		defer innerMap.Close()

		// add a special entry (key == UINT32_MAX) that has as a value the number of matchBinaries entry
		// if this is zero we don't have any matchBinaries selectors
		if err := innerMap.Update(uint32(0xffffffff), sel.GetBinaryOp(innerID), ebpf.UpdateAny); err != nil {
			return fmt.Errorf("ops: %w", err)
		}

		for idx, val := range entries {
			if err := innerMap.Update(idx, val, ebpf.UpdateAny); err != nil {
				return fmt.Errorf("entries: %w", err)
			}
		}

		if err := outerMap.Update(uint32(innerID), uint32(innerMap.FD()), 0); err != nil {
			return fmt.Errorf("failed to insert %s: %w", innerName, err)
		}
	}

	return nil
}

func GetMaxInnerEntriesOpsMap(sel *KernelSelectorState) uint32 {
	maxEntries := uint32(0)
	for _, entry := range sel.GetOpsEntries() {
		num := entry.GetOpsSelMapSize()
		if num > maxEntries {
			maxEntries = num
		}
	}
	return maxEntries + 1 // for the special entry UINT32_MAX
}

func GenerateFileOpsMap(outerMap *ebpf.Map, sel *KernelSelectorState, pinPathPrefix string) error {
	maxEntries := GetMaxInnerEntriesOpsMap(sel)
	for innerID, entry := range sel.GetOpsEntries() {
		entries := entry.GetOpsSelMap()

		// in order kernels we should provide the maximum number of inner map entries
		maxInnerEntries := uint32(len(entries)) + 1 // for the special entry UINT32_MAX
		if !kernels.MinKernelVersion("5.9") {
			// Versions before 5.9 do not allow inner maps to have different sizes.
			// See: https://lore.kernel.org/bpf/20200828011800.1970018-1-kafai@fb.com/
			maxInnerEntries = maxEntries
		}

		innerName := fmt.Sprintf("file_ops_map_%d", innerID)
		innerSpec := &ebpf.MapSpec{
			Name:       innerName,
			Type:       ebpf.Hash,
			KeySize:    4, // uint32
			ValueSize:  4, // uint32
			MaxEntries: maxInnerEntries,
		}
		innerMap, err := ebpf.NewMapWithOptions(innerSpec, ebpf.MapOptions{
			PinPath: sensors.PathJoin(pinPathPrefix, innerName),
		})
		if err != nil {
			return fmt.Errorf("creating innerMap %s failed: %w", innerName, err)
		}
		defer innerMap.Close()

		// add a special entry (key == UINT32_MAX) that has as a value the number of matchOperations entry
		// if this is zero we don't have any matchOperations selectors
		if err := innerMap.Update(uint32(0xffffffff), entry.GetOperationOp(), ebpf.UpdateAny); err != nil {
			return fmt.Errorf("ops: %w", err)
		}

		for op, val := range entries {
			if err := innerMap.Update(op, val, ebpf.UpdateAny); err != nil {
				return fmt.Errorf("entries: %w", err)
			}
		}

		if err := outerMap.Update(uint32(innerID), uint32(innerMap.FD()), 0); err != nil {
			return fmt.Errorf("failed to insert %s: %w", innerName, err)
		}
	}

	return nil
}

func GetMaxInnerEntriesDigestsMap(sel *KernelSelectorState) uint32 {
	maxEntries := uint32(0)
	for _, entry := range sel.GetDigestEntries() {
		num := entry.GetDigestsSelMapSize()
		if num > maxEntries {
			maxEntries = num
		}
	}
	return maxEntries + 1 // for the special entry UINT32_MAX
}

func GenerateFileDigestsMap(outerMap *ebpf.Map, sel *KernelSelectorState, pinPathPrefix string) error {
	maxEntries := GetMaxInnerEntriesDigestsMap(sel)
	for innerID, entry := range sel.GetDigestEntries() {
		entries := entry.GetDigestsSelMap()

		// in order kernels we should provide the maximum number of inner map entries
		maxInnerEntries := uint32(len(entries)) + 1 // for the special entry UINT32_MAX
		if !kernels.MinKernelVersion("5.9") {
			// Versions before 5.9 do not allow inner maps to have different sizes.
			// See: https://lore.kernel.org/bpf/20200828011800.1970018-1-kafai@fb.com/
			maxInnerEntries = maxEntries
		}

		innerName := fmt.Sprintf("file_digests_map_%d", innerID)
		innerSpec := &ebpf.MapSpec{
			Name:       innerName,
			Type:       ebpf.Hash,
			KeySize:    uint32(unsafe.Sizeof(fileapi.DigestKey{})),
			ValueSize:  4, // uint32
			MaxEntries: maxInnerEntries,
		}
		innerMap, err := ebpf.NewMapWithOptions(innerSpec, ebpf.MapOptions{
			PinPath: sensors.PathJoin(pinPathPrefix, innerName),
		})
		if err != nil {
			return fmt.Errorf("creating innerMap %s failed: %w", innerName, err)
		}
		defer innerMap.Close()

		innerMap.Pin(sensors.PathJoin(pinPathPrefix, innerName))

		// add a special entry (key.algo == INT32_MAX) that has as a value the number of matchDigests entry
		// if this is zero we don't have any matchDigests selectors
		if err := innerMap.Update(fileapi.DigestKey{Algo: int32(0x7fffffff)}, entry.GetDigestOp(), ebpf.UpdateAny); err != nil {
			return fmt.Errorf("ops: %w", err)
		}

		for op, val := range entries {
			if err := innerMap.Update(op, val, ebpf.UpdateAny); err != nil {
				return fmt.Errorf("entries: %w", err)
			}
		}

		if err := outerMap.Update(uint32(innerID), uint32(innerMap.FD()), 0); err != nil {
			return fmt.Errorf("failed to insert %s: %w", innerName, err)
		}

	}
	return nil
}

func GenerateFileActionsMap(m *ebpf.Map, sel *KernelSelectorState) error {
	for idx, action := range sel.action {
		if err := m.Update(idx, action, ebpf.UpdateAny); err != nil {
			return err
		}
	}
	return nil
}

func ParseMatchOperation(k *KernelSelectorState, b *v1alpha1.OperationSelector, selIdx int) error {
	op, err := selectors.SelectorOp(b.Operator)
	if err != nil {
		return fmt.Errorf("matchOperation error: %w", err)
	}
	if op != selectors.SelectorOpIn && op != selectors.SelectorOpNotIn {
		return fmt.Errorf("matchOperation error: Only In and NotIn operators are supported")
	}
	v := k.InitOrGetOperations(uint32(selIdx))
	v.SetOperationOp(op)
	for _, s := range b.Values {
		val, ok := tetragon.FileAction_value[strings.ToUpper(s)]
		if !ok {
			return fmt.Errorf("unknown value in matchOperation: %s", s)
		}
		v.AddOpsVal(uint32(val), 1)
	}
	return nil
}

func ParseMatchOperations(k *KernelSelectorState, ops []v1alpha1.OperationSelector, selIdx int) error {
	if len(ops) > 1 {
		return fmt.Errorf("only support single operations selector")
	}
	for _, s := range ops {
		if err := ParseMatchOperation(k, &s, selIdx); err != nil {
			return err
		}
	}
	return nil
}

func ParseMatchDigest(k *KernelSelectorState, d *v1alpha1.DigestSelector, selIdx int) error {
	op, err := selectors.SelectorOp(d.Operator)
	if err != nil {
		return fmt.Errorf("matchDigest error: %w", err)
	}
	if op != selectors.SelectorOpIn && op != selectors.SelectorOpNotIn {
		return fmt.Errorf("matchDigest error: Only In and NotIn operators are supported")
	}
	v := k.InitOrGetDigests(uint32(selIdx))
	v.SetDigestOp(op)
	for _, s := range d.Values {
		ss := strings.Split(s, ":")
		if len(ss) != 2 {
			return fmt.Errorf("matchDigest value:[%s] has wrong format", s)
		}

		algo := ss[0]
		digest := ss[1]
		val, ok := HashNameAlgo[strings.ToLower(algo)]
		if !ok {
			return fmt.Errorf("unknown hash algo in matchDigests: %s", algo)
		}
		k := fileapi.DigestKey{Algo: int32(val), Digest: [64]uint8{}, Ok: 1}

		for i := 0; i < len(digest)/2; i++ {
			d := digest[(i * 2) : (i*2)+2]
			num, _ := strconv.ParseInt(d, 16, 64)
			k.Digest[i] = uint8(num)
		}
		v.AddDigestsVal(k, 1)
	}
	return nil
}

func ParseMatchDigests(k *KernelSelectorState, digests []v1alpha1.DigestSelector, selIdx int) error {
	if len(digests) > 1 {
		return fmt.Errorf("only support single digests selector")
	}
	for _, d := range digests {
		if err := ParseMatchDigest(k, &d, selIdx); err != nil {
			return err
		}
	}
	return nil
}

func ParseMatchActions(k *KernelSelectorState, actions []v1alpha1.FileActionSelector, selIdx int) error {
	if len(actions) > 1 {
		return fmt.Errorf("only support single actions selector")
	}
	action := uint32(0)
	for _, a := range actions {
		act, ok := fileActionTypeTable[strings.ToLower(a.Action)]
		if !ok {
			return fmt.Errorf("parseMatchAction: ActionType %s unknown", a.Action)
		}
		action |= act
	}
	k.action[uint32(selIdx)] = action
	return nil
}

func (k *KernelSelectorState) NeedEnforcement() bool {
	for _, v := range k.action {
		if v&FileOperationTypeBlock != 0 {
			return true
		}
	}
	return false
}

func InitKernelSelectorState(fileSel []v1alpha1.FileSelector) (*KernelSelectorState, error) {
	if len(fileSel) > MaxFimSelectors {
		return nil, fmt.Errorf("file monitoring supports up to %d selectors", MaxFimSelectors)
	}
	kernelSelectors := NewKernelSelectorState()
	for i, s := range fileSel {
		if err := selectors.ParseMatchBinaries(&kernelSelectors.KernelSelectorState, s.MatchBinaries, i); err != nil {
			return nil, fmt.Errorf("parseMatchBinaries error: %w", err)
		}
		if err := ParseMatchOperations(kernelSelectors, s.MatchOperations, i); err != nil {
			return nil, fmt.Errorf("parseMatchOperations error: %w", err)
		}
		if err := ParseMatchDigests(kernelSelectors, s.MatchDigests, i); err != nil {
			return nil, fmt.Errorf("parseMatchDigests error: %w", err)
		}
		if err := ParseMatchActions(kernelSelectors, s.MatchActions, i); err != nil {
			return nil, fmt.Errorf("parseMatchActions error: %w", err)
		}
	}
	kernelSelectors.num = uint32(len(fileSel))
	return kernelSelectors, nil
}

func InitKernelExecSelectorState(fileSel []v1alpha1.FileExecSelector) (*KernelSelectorState, error) {
	if len(fileSel) > MaxFimSelectors {
		return nil, fmt.Errorf("file monitoring supports up to %d selectors", MaxFimSelectors)
	}
	kernelSelectors := NewKernelSelectorState()
	for i, s := range fileSel {
		if err := selectors.ParseMatchBinaries(&kernelSelectors.KernelSelectorState, s.MatchBinaries, i); err != nil {
			return nil, fmt.Errorf("parseMatchBinaries error: %w", err)
		}
		if err := ParseMatchDigests(kernelSelectors, s.MatchDigests, i); err != nil {
			return nil, fmt.Errorf("parseMatchDigests error: %w", err)
		}
		if err := ParseMatchActions(kernelSelectors, s.MatchActions, i); err != nil {
			return nil, fmt.Errorf("parseMatchActions error: %w", err)
		}
	}
	kernelSelectors.num = uint32(len(fileSel))
	return kernelSelectors, nil
}

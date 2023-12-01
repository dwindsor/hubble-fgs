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
	"strconv"
	"strings"
	"sync"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/reader/namespace"
	"github.com/cilium/tetragon/pkg/selectors"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/isovalent/hubble-fgs/pkg/api/fileapi"
)

const (
	FileOperationTypePost  = uint32(tetragon.FileOperation_FILE_OP_POST)
	FileOperationTypeBlock = uint32(tetragon.FileOperation_FILE_OP_BLOCK)

	MaxFimSelectors = 6 // should match MAX_FIM_SELECTORS in bpf/file/bpf_file.h
)

const (
	capsPermitted   = 0
	capsEffective   = 1
	capsInheritable = 2
)

var capabilitiesTypeTable = map[string]uint32{
	"effective":   capsEffective,
	"inheritable": capsInheritable,
	"permitted":   capsPermitted,
}

const (
	namespaceTypeUts             = 0
	namespaceTypeIpc             = 1
	namespaceTypeMnt             = 2
	namespaceTypePid             = 3
	namespaceTypePidForChildren  = 4
	namespaceTypeNet             = 5
	namespaceTypeTime            = 6
	namespaceTypeTimeForChildren = 7
	namespaceTypeCgroup          = 8
	namespaceTypeUser            = 9
)

var namespaceTypeTable = map[string]uint32{
	"uts":             namespaceTypeUts,
	"ipc":             namespaceTypeIpc,
	"mnt":             namespaceTypeMnt,
	"pid":             namespaceTypePid,
	"pidforchildren":  namespaceTypePidForChildren,
	"net":             namespaceTypeNet,
	"time":            namespaceTypeTime,
	"timeforchildren": namespaceTypeTimeForChildren,
	"cgroup":          namespaceTypeCgroup,
	"user":            namespaceTypeUser,
}

const (
	namespaceFilterAll    = 0
	namespaceFilterHost   = 1
	namespaceFilterNoHost = 2
)

var namespaceFilterTable = map[string]uint32{
	"all":    namespaceFilterAll,
	"host":   namespaceFilterHost,
	"nohost": namespaceFilterNoHost,
}

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

	// matchLinuxCapabilities
	capabilities map[uint32]*fileapi.SelCaps

	// matchLinuxNamespaces
	namespaces map[uint32]*fileapi.SelNs

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
		capabilities:        map[uint32]*fileapi.SelCaps{},
		namespaces:          map[uint32]*fileapi.SelNs{},
		action:              map[uint32]uint32{},
	}
}

func (k *KernelSelectorState) GetNumSelectors() uint32 {
	return k.num
}

func (k *KernelSelectorState) InitOrGetCapabilities(selIdx uint32) *fileapi.SelCaps {
	val, ok := k.capabilities[selIdx]
	if ok {
		return val
	}
	inner := &fileapi.SelCaps{}
	k.capabilities[selIdx] = inner
	return inner
}

func (k *KernelSelectorState) InitOrGetNamespaces(selIdx uint32) *fileapi.SelNs {
	val, ok := k.namespaces[selIdx]
	if ok {
		return val
	}
	inner := &fileapi.SelNs{}
	k.namespaces[selIdx] = inner
	return inner
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

func PopulateMatchBinariesMaps(ks *KernelSelectorState, bpfMap *ebpf.Map) error {
	for selID, sel := range ks.MatchBinaries() {
		if err := bpfMap.Update(uint32(selID), sel, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("failed to insert %v: %w", sel, err)
		}
	}
	return nil
}

func PopulateMatchBinariesPathsMaps(k *KernelSelectorState, pinPathPrefix string, outerMap *ebpf.Map) error {
	maxEntriesFromAllSelector := k.MatchBinariesPathsMaxEntries()
	for selectorID, paths := range k.MatchBinariesPaths() {
		maxEntries := len(paths)
		// Versions before 5.9 do not allow inner maps to have different sizes.
		// See: https://lore.kernel.org/bpf/20200828011800.1970018-1-kafai@fb.com/
		if !kernels.MinKernelVersion("5.9") {
			maxEntries = maxEntriesFromAllSelector
		}

		innerName := fmt.Sprintf("tg_mb_path_%d", selectorID)
		innerSpec := &ebpf.MapSpec{
			Name:       innerName,
			Type:       ebpf.Hash,
			KeySize:    uint32(processapi.BINARY_PATH_MAX_LEN),
			ValueSize:  uint32(1),
			MaxEntries: uint32(maxEntries),
		}
		innerMap, err := ebpf.NewMapWithOptions(innerSpec, ebpf.MapOptions{
			PinPath: sensors.PathJoin(pinPathPrefix, innerName),
		})
		if err != nil {
			return fmt.Errorf("creating innerMap %s failed: %w", innerName, err)
		}
		defer innerMap.Close()

		for _, path := range paths {
			err := innerMap.Update(path, uint8(1), 0)
			if err != nil {
				return fmt.Errorf("failed to insert value into %s: %w", innerName, err)
			}
		}

		if err := outerMap.Update(uint32(selectorID), uint32(innerMap.FD()), 0); err != nil {
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

func GenerateFileCapabilitiesMap(m *ebpf.Map, sel *KernelSelectorState) error {
	for idx, caps := range sel.capabilities {
		if err := m.Update(idx, caps, ebpf.UpdateAny); err != nil {
			return err
		}
	}
	return nil
}

func GenerateFileNamespacesMap(m *ebpf.Map, sel *KernelSelectorState) error {
	for idx, ns := range sel.namespaces {
		if err := m.Update(idx, ns, ebpf.UpdateAny); err != nil {
			return err
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

func GetActions(actions []v1alpha1.FileActionSelector) (uint32, error) {
	if len(actions) > 1 {
		return 0, fmt.Errorf("only support single actions selector")
	}
	action := uint32(0)
	for _, a := range actions {
		act, ok := fileActionTypeTable[strings.ToLower(a.Action)]
		if !ok {
			return 0, fmt.Errorf("parseMatchAction: ActionType %s unknown", a.Action)
		}
		action |= act
	}
	return action, nil
}

func ParseMatchActions(k *KernelSelectorState, actions []v1alpha1.FileActionSelector, selIdx int) error {
	action, err := GetActions(actions)
	if err != nil {
		return err
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

func ParseLinuxMatchCapability(k *KernelSelectorState, cap *v1alpha1.FileCapabilitiesSelector, selIdx int) error {
	val := k.InitOrGetCapabilities(uint32(selIdx))
	var err error
	var ok bool

	// operator
	val.Op, err = selectors.SelectorOp(cap.Operator)
	if err != nil {
		return fmt.Errorf("matchLinuxCapabilities error: %w", err)
	}
	if (val.Op != selectors.SelectorOpIn) && (val.Op != selectors.SelectorOpNotIn) {
		return fmt.Errorf("matchLinuxCapabilities supports only In and NotIn operators")
	}

	// type
	tystr := strings.ToLower(cap.Type)
	val.Type, ok = capabilitiesTypeTable[tystr]
	if !ok {
		return fmt.Errorf("parseMatchLinuxCapability: actionType %s unknown", cap.Type)
	}

	// values
	val.Filter = uint64(0)
	for _, v := range cap.Values {
		valstr := strings.ToUpper(v)
		c, ok := tetragon.CapabilitiesType_value[valstr]
		if !ok {
			return fmt.Errorf("parseMatchLinuxCapability: value %s unknown", valstr)
		}
		val.Filter |= (1 << c)
	}

	return nil
}

func ParseLinuxMatchCapabilities(k *KernelSelectorState, caps []v1alpha1.FileCapabilitiesSelector, selIdx int) error {
	if !kernels.MinKernelVersion("5.4") && len(caps) > 0 {
		return fmt.Errorf("only support matchLinuxCapabilities for kernels >= 5.4")
	}
	if len(caps) > 1 {
		return fmt.Errorf("only support one capabilities filter inside a single selector")
	}
	for _, c := range caps {
		if err := ParseLinuxMatchCapability(k, &c, selIdx); err != nil {
			return err
		}
	}
	return nil
}

func ParseLinuxMatchNamespace(k *KernelSelectorState, ns *v1alpha1.FileNamespaceSelector, selIdx int) error {
	val := k.InitOrGetNamespaces(uint32(selIdx))

	nsStr := strings.ToLower(ns.Namespace)
	nsId, ok := namespaceTypeTable[nsStr]
	if !ok {
		return fmt.Errorf("parseMatchLinuxNamespace: namespaceType %s unknown", ns.Namespace)
	}

	filterSr := strings.ToLower(ns.Filter)
	filterId, ok := namespaceFilterTable[filterSr]
	if !ok {
		return fmt.Errorf("parseMatchLinuxNamespace: filterType %s unknown", ns.Filter)
	}

	var err error
	switch nsId {
	case namespaceTypeUts:
		val.Filter.UtsFilter = filterId
		val.Ns.UtsInum, err = namespace.GetPidNsInode(1, nsStr)
	case namespaceTypeIpc:
		val.Filter.IpcFilter = filterId
		val.Ns.IpcInum, err = namespace.GetPidNsInode(1, nsStr)
	case namespaceTypeMnt:
		val.Filter.MntFilter = filterId
		val.Ns.MntInum, err = namespace.GetPidNsInode(1, nsStr)
	case namespaceTypePid:
		val.Filter.PidFilter = filterId
		val.Ns.PidInum, err = namespace.GetPidNsInode(1, nsStr)
	case namespaceTypePidForChildren:
		val.Filter.PidChildFilter = filterId
		val.Ns.PidChildInum, err = namespace.GetPidNsInode(1, nsStr)
	case namespaceTypeNet:
		val.Filter.NetFilter = filterId
		val.Ns.NetInum, err = namespace.GetPidNsInode(1, nsStr)
	case namespaceTypeTime:
		val.Filter.TimeFilter = filterId
		val.Ns.TimeInum, err = namespace.GetPidNsInode(1, nsStr)
	case namespaceTypeTimeForChildren:
		val.Filter.TimeChildFilter = filterId
		val.Ns.TimeChildInum, err = namespace.GetPidNsInode(1, nsStr)
	case namespaceTypeCgroup:
		val.Filter.CgroupFilter = filterId
		val.Ns.CgroupInum, err = namespace.GetPidNsInode(1, nsStr)
	case namespaceTypeUser:
		val.Filter.UserFilter = filterId
		val.Ns.UserInum, err = namespace.GetPidNsInode(1, nsStr)
	}
	if err != nil {
		return fmt.Errorf("parseMatchLinuxNamespace: Failed to get root namespace for %s: %w", nsStr, err)
	}
	return nil
}

func ParseLinuxMatchNamespaces(k *KernelSelectorState, nses []v1alpha1.FileNamespaceSelector, selIdx int) error {
	if !kernels.MinKernelVersion("5.4") && len(nses) > 0 {
		return fmt.Errorf("only support matchLinuxNamespaces for kernels >= 5.4")
	}
	// we only support one filter per namespace
	nsFilter := make(map[string]int)
	for _, ns := range nses {
		nsStr := strings.ToLower(ns.Namespace)
		_, ok := nsFilter[nsStr]
		if ok {
			return fmt.Errorf("only support one namespace filter per type inside a single selector: %s appears twice", ns.Namespace)
		}
		nsFilter[nsStr] = 0
	}
	for _, c := range nses {
		if err := ParseLinuxMatchNamespace(k, &c, selIdx); err != nil {
			return err
		}
	}
	return nil
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
		if err := ParseLinuxMatchCapabilities(kernelSelectors, s.MatchCapabilities, i); err != nil {
			return nil, fmt.Errorf("parseMatchLinuxCapabilities error: %w", err)
		}
		if err := ParseLinuxMatchNamespaces(kernelSelectors, s.MatchNamespaces, i); err != nil {
			return nil, fmt.Errorf("parseMatchLinuxNamespaces error: %w", err)
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
		if err := ParseLinuxMatchCapabilities(kernelSelectors, s.MatchCapabilities, i); err != nil {
			return nil, fmt.Errorf("parseMatchLinuxCapabilities error: %w", err)
		}
		if err := ParseLinuxMatchNamespaces(kernelSelectors, s.MatchNamespaces, i); err != nil {
			return nil, fmt.Errorf("parseMatchLinuxNamespaces error: %w", err)
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

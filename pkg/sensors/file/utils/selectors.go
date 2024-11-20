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
	"github.com/cilium/tetragon/pkg/mbset"
	"github.com/cilium/tetragon/pkg/reader/namespace"
	"github.com/cilium/tetragon/pkg/selectors"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/isovalent/hubble-fgs/pkg/api/fileapi"
	"golang.org/x/sys/unix"
)

const (
	FileOperationTypePost   = uint32(tetragon.FileOperation_FILE_OP_POST)
	FileOperationTypeBlock  = uint32(tetragon.FileOperation_FILE_OP_BLOCK)
	FileOperationTypeNoPost = uint32(tetragon.FileOperation_FILE_OP_NOPOST)

	MaxFimSelectors     = 6 // should match MAX_FIM_SELECTORS in bpf/file/bpf_file.h
	MaxFimGlobSelectors = 128

	MatchFilenameInPattern        = 0
	MatchFilenameInFileWithDigest = 1
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

const maxOpenFlagMaskPerOp = 8

var openFlagsString = map[string]uint32{
	"O_APPEND":    unix.O_APPEND,
	"O_ASYNC":     unix.O_ASYNC,
	"O_CLOEXEC":   unix.O_CLOEXEC,
	"O_CREAT":     unix.O_CREAT,
	"O_DIRECT":    unix.O_DIRECT,
	"O_DIRECTORY": unix.O_DIRECTORY,
	"O_DSYNC":     unix.O_DSYNC,
	"O_EXCL":      unix.O_EXCL,
	"O_NOATIME":   unix.O_NOATIME,
	"O_NOCTTY":    unix.O_NOCTTY,
	"O_NOFOLLOW":  unix.O_NOFOLLOW,
	"O_NONBLOCK":  unix.O_NONBLOCK,
	"O_NDELAY":    unix.O_NONBLOCK,
	"O_PATH":      unix.O_PATH,
	"O_SYNC":      unix.O_SYNC,
	"O_FSYNC":     unix.O_SYNC,
	"O_TMPFILE":   unix.O_TMPFILE,
	"O_TRUNC":     unix.O_TRUNC,
	"O_RDONLY":    unix.O_RDONLY,
	"O_RDWR":      unix.O_RDWR,
	"O_WRONLY":    unix.O_WRONLY,
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
	"post":   FileOperationTypePost,
	"block":  FileOperationTypeBlock,
	"nopost": FileOperationTypeNoPost,
}

type SelOps struct {
	opVal  uint32
	opsMap sync.Map
}

type RenameOps struct {
	opVal        uint32
	opsMatchMask uint32
}

type OpenFlagsPair struct {
	Op   uint32
	Mask uint32
}

type OpenFlagsOps struct {
	flags [maxOpenFlagMaskPerOp]OpenFlagsPair
}

type MatchFilenameOps struct {
	op    uint32
	fsm   []*GlobFSM        // when op == MatchFilenameInPattern
	paths map[string]uint32 // when op == MatchFilenameInFileWithDigest
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

	// matchRenameSrcType
	rename map[uint32]*RenameOps

	// matchOpenFlags
	oflags map[uint32]*OpenFlagsOps

	// matchFilename
	patterns map[uint32]*MatchFilenameOps

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
		rename:              map[uint32]*RenameOps{},
		oflags:              map[uint32]*OpenFlagsOps{},
		patterns:            map[uint32]*MatchFilenameOps{},
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

func (k *KernelSelectorState) InitOrGetOpenFlags(selIdx uint32) *OpenFlagsOps {
	val, ok := k.oflags[selIdx]
	if ok {
		return val
	}
	inner := &OpenFlagsOps{}
	for i := 0; i < maxOpenFlagMaskPerOp; i++ {
		inner.flags[i].Op = 0
		inner.flags[i].Mask = 0
	}
	k.oflags[selIdx] = inner
	return inner
}

func (k *KernelSelectorState) InitOrGetRename(selIdx uint32) *RenameOps {
	val, ok := k.rename[selIdx]
	if ok {
		return val
	}
	inner := &RenameOps{}
	k.rename[selIdx] = inner
	return inner
}

func (k *KernelSelectorState) InitOrGetPatterns(selIdx uint32) *MatchFilenameOps {
	val, ok := k.patterns[selIdx]
	if ok {
		return val
	}
	inner := &MatchFilenameOps{
		paths: make(map[string]uint32),
	}
	k.patterns[selIdx] = inner
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
	k.opsMap.Range(func(_, _ any) bool {
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
	k.digMap.Range(func(_, _ any) bool {
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
	matchBinaries := k.MatchBinaries()
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

		mbSelector := matchBinaries[selectorID]
		if mbSelector.MBSetID != mbset.InvalidID {
			if err := mbset.UpdateMap(mbSelector.MBSetID, paths); err != nil {
				return fmt.Errorf("updating mbset map failed: %w", err)
			}
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

func GenerateFileRenameMap(m *ebpf.Map, sel *KernelSelectorState) error {
	for idx, rename := range sel.rename {
		if err := m.Update(idx, rename, ebpf.UpdateAny); err != nil {
			return err
		}
	}
	return nil
}

func GenerateFileOpenFlagsMap(outerMap *ebpf.Map, sel *KernelSelectorState, pinPathPrefix string) error {
	for innerID, entries := range sel.oflags {
		innerName := fmt.Sprintf("file_open_flags_map_%d", innerID)
		innerSpec := &ebpf.MapSpec{
			Name:       innerName,
			Type:       ebpf.Array,
			KeySize:    4, // uint32
			ValueSize:  uint32(unsafe.Sizeof(OpenFlagsPair{})),
			MaxEntries: maxOpenFlagMaskPerOp,
		}
		innerMap, err := ebpf.NewMapWithOptions(innerSpec, ebpf.MapOptions{
			PinPath: sensors.PathJoin(pinPathPrefix, innerName),
		})
		if err != nil {
			return fmt.Errorf("creating innerMap %s failed: %w", innerName, err)
		}
		defer innerMap.Close()

		innerMap.Pin(sensors.PathJoin(pinPathPrefix, innerName))

		for i, f := range entries.flags {
			if err := innerMap.Update(uint32(i), OpenFlagsPair{
				Op:   f.Op,
				Mask: f.Mask,
			}, ebpf.UpdateAny); err != nil {
				return fmt.Errorf("entries: %w", err)
			}
		}

		if err := outerMap.Update(uint32(innerID), uint32(innerMap.FD()), 0); err != nil {
			return fmt.Errorf("failed to insert %s: %w", innerName, err)
		}
	}

	return nil
}

type patternKey struct {
	selIdx     uint32
	patternIdx uint32
}

func GenerateFilenameOpsMap(m *ebpf.Map, sel *KernelSelectorState) error {
	for idx, entry := range sel.patterns {
		if err := m.Update(idx, entry.op, ebpf.UpdateAny); err != nil {
			return err
		}
	}
	return nil
}

func GetNumFilenameSelectors(sel *KernelSelectorState) int {
	sz := len(sel.patterns)
	if sz == 0 {
		sz++
	}
	return sz
}

func GetMaxInnerEntriesPathMap(sel *KernelSelectorState) int {
	maxEntries := 0
	for _, entry := range sel.patterns {
		num := len(entry.paths)
		if num > maxEntries {
			maxEntries = num
		}
	}
	if maxEntries == 0 {
		maxEntries++
	}
	return maxEntries
}

func GeneratePathsMap(outerMap *ebpf.Map, sel *KernelSelectorState, pinPathPrefix string) error {
	for selID, entries := range sel.patterns {
		innerName := fmt.Sprintf("filename_path_map_%d", selID)
		innerSpec := &ebpf.MapSpec{
			Name:       innerName,
			Type:       ebpf.Hash,
			KeySize:    256, // path length
			ValueSize:  4,   // uint32
			MaxEntries: uint32(GetMaxInnerEntriesPathMap(sel)),
		}
		innerMap, err := ebpf.NewMapWithOptions(innerSpec, ebpf.MapOptions{
			PinPath: sensors.PathJoin(pinPathPrefix, innerName),
		})
		if err != nil {
			return fmt.Errorf("creating innerMap %s failed: %w", innerName, err)
		}
		defer innerMap.Close()

		innerMap.Pin(sensors.PathJoin(pinPathPrefix, innerName))

		for path, pathIdx := range entries.paths {
			var key [256]byte
			copy(key[:], path)

			if err := innerMap.Put(key, pathIdx); err != nil {
				return fmt.Errorf("put failed: %w", err)
			}
		}

		if err := outerMap.Update(selID, uint32(innerMap.FD()), 0); err != nil {
			return fmt.Errorf("failed to insert %s: %w", innerName, err)
		}
	}
	return nil
}

func CreateDigestKey(digest string, algoNum int32) fileapi.DigestKey {
	key := fileapi.DigestKey{
		Algo:   algoNum,
		Digest: [64]uint8{},
		Ok:     1,
	}

	// parse digest string
	for i := 0; i < len(digest)/2; i++ {
		d := digest[(i * 2) : (i*2)+2]
		num, _ := strconv.ParseInt(d, 16, 64)
		key.Digest[i] = uint8(num)
	}

	return key
}

func GenerateDigestsMap(outerMap *ebpf.Map, sel *KernelSelectorState, pinPathPrefix string, digestMap map[string][]string, algoNum int32) error {
	for selID, entries := range sel.patterns {
		innerName := fmt.Sprintf("filename_digest_map_%d", selID)
		innerSpec := &ebpf.MapSpec{
			Name:       innerName,
			Type:       ebpf.Hash,
			KeySize:    uint32(unsafe.Sizeof(fileapi.DigestKey{})),
			ValueSize:  4, // uint32
			MaxEntries: 32 * uint32(GetMaxInnerEntriesPathMap(sel)),
		}
		innerMap, err := ebpf.NewMapWithOptions(innerSpec, ebpf.MapOptions{
			PinPath: sensors.PathJoin(pinPathPrefix, innerName),
		})
		if err != nil {
			return fmt.Errorf("creating innerMap %s failed: %w", innerName, err)
		}
		defer innerMap.Close()

		innerMap.Pin(sensors.PathJoin(pinPathPrefix, innerName))

		for path, pathIdx := range entries.paths {
			digests, ok := digestMap[path]
			if !ok {
				continue // no digest for this path
			}

			for _, digest := range digests {
				if err := innerMap.Put(CreateDigestKey(digest, algoNum), pathIdx); err != nil {
					return fmt.Errorf("put failed: %w", err)
				}
			}
		}

		if err := outerMap.Update(selID, uint32(innerMap.FD()), 0); err != nil {
			return fmt.Errorf("failed to insert %s: %w", innerName, err)
		}
	}
	return nil
}

func (k *KernelSelectorState) GetDigestPaths() []string {
	uniquePaths := map[string]struct{}{}
	for _, entry := range k.patterns {
		for key := range entry.paths {
			uniquePaths[key] = struct{}{}
		}
	}
	paths := make([]string, 0)
	for key := range uniquePaths {
		paths = append(paths, key)
	}
	return paths
}

func (k *KernelSelectorState) GetPathMetadata() map[string][]DigestPathMetadata {
	pathMetadata := make(map[string][]DigestPathMetadata)
	for selIdx, entry := range k.patterns {
		for path, pathIdx := range entry.paths {
			m := DigestPathMetadata{
				PathIdx: pathIdx,
				SelIdx:  selIdx,
			}
			if _, ok := pathMetadata[path]; !ok {
				pathMetadata[path] = []DigestPathMetadata{m}
			} else {
				pathMetadata[path] = append(pathMetadata[path], m)
			}
		}
	}
	return pathMetadata

}

func GeneratePatternsMap(outerMap *ebpf.Map, sel *KernelSelectorState, pinPathPrefix string) error {
	for selID, entries := range sel.patterns {
		for patternID, fsm := range entries.fsm {
			innerName := fmt.Sprintf("glob_patterns_map_%d", selID)
			innerSpec := &ebpf.MapSpec{
				Name:       innerName,
				Type:       ebpf.Array,
				KeySize:    4, // uint32
				ValueSize:  uint32(unsafe.Sizeof(GlobState{})),
				MaxEntries: uint32(GetMaxInnerEntriesPatternsMap(sel)),
			}
			innerMap, err := ebpf.NewMapWithOptions(innerSpec, ebpf.MapOptions{
				PinPath: sensors.PathJoin(pinPathPrefix, innerName),
			})
			if err != nil {
				return fmt.Errorf("creating innerMap %s failed: %w", innerName, err)
			}
			defer innerMap.Close()

			innerMap.Pin(sensors.PathJoin(pinPathPrefix, innerName))

			for i, s := range fsm.stateArr {
				idx := uint32(i)
				if err := innerMap.Put(idx, s); err != nil {
					return fmt.Errorf("put failed: %w", err)
				}
			}

			if err := outerMap.Update(patternKey{
				selIdx:     selID,
				patternIdx: uint32(patternID),
			}, uint32(innerMap.FD()), 0); err != nil {
				return fmt.Errorf("failed to insert %s: %w", innerName, err)
			}
		}
	}

	return nil
}

func GetMaxInnerEntriesPatternsMap(sel *KernelSelectorState) int {
	maxEntries := 0
	for _, entry := range sel.patterns {
		for _, p := range entry.fsm {
			num := len(p.stateArr)
			if num > maxEntries {
				maxEntries = num
			}
		}
	}
	if maxEntries == 0 {
		maxEntries = 1
	}
	return maxEntries
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

	// no specific actions for this selector, use Post by default
	if len(actions) == 0 {
		return FileOperationTypePost, nil
	}

	// parse all actions
	action := uint32(0)
	for _, a := range actions {
		act, ok := fileActionTypeTable[strings.ToLower(a.Action)]
		if !ok {
			return 0, fmt.Errorf("parseMatchAction: ActionType %s unknown", a.Action)
		}
		action |= act
	}

	// having both post and nopost is not allowed
	if action&FileOperationTypePost != 0 && action&FileOperationTypeNoPost != 0 {
		return 0, fmt.Errorf("parseMatchAction: Post and NoPost actions are not allowed: %s", actions)
	}

	// if we have only block (and not NoPost), let's add Post as well
	if action&FileOperationTypeBlock != 0 && action&FileOperationTypeNoPost == 0 {
		action |= FileOperationTypePost
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

func ParseRenameSrcType(k *KernelSelectorState, m v1alpha1.FileRenameTypeSelector, selIdx int) error {
	val := k.InitOrGetRename(uint32(selIdx))
	var err error

	// operator
	val.opVal, err = selectors.SelectorOp(m.Operator)
	if err != nil {
		return fmt.Errorf("matchRenameSrcType error: %w", err)
	}
	if val.opVal != selectors.SelectorOpIn {
		return fmt.Errorf("matchRenameSrcType supports only In operator")
	}

	// values
	val.opsMatchMask = 0
	for _, v := range m.Values {
		valstr := strings.ToUpper(v)
		if valstr == "FILE" {
			val.opsMatchMask |= SRC_REG_FILE
		} else if valstr == "DIRECTORY" {
			val.opsMatchMask |= SRC_DIRECTORY
		} else {
			return fmt.Errorf("parseRenameSrcType: value %s unknown", valstr)
		}
	}

	return nil
}

func ParseRenameSrcTypes(k *KernelSelectorState, mv []v1alpha1.FileRenameTypeSelector, selIdx int) error {
	if len(mv) > 1 {
		return fmt.Errorf("only support one rename type filter inside a single selector")
	}
	for _, m := range mv {
		if err := ParseRenameSrcType(k, m, selIdx); err != nil {
			return err
		}
	}
	return nil
}

func ParseOpenFlag(k *KernelSelectorState, op v1alpha1.FileOpenFlagsTypeSelector, opIdx int, selIdx int) error {
	val := k.InitOrGetOpenFlags(uint32(selIdx))
	var err error

	// operator
	val.flags[opIdx].Op, err = selectors.SelectorOp(op.Operator)
	if err != nil {
		return fmt.Errorf("matchOpenFlags error: %w", err)
	}
	if val.flags[opIdx].Op != selectors.SelectorOpIn && val.flags[opIdx].Op != selectors.SelectorOpNotIn {
		return fmt.Errorf("matchOpenFlags supports only In and NotIn operator")
	}

	// values
	val.flags[opIdx].Mask = 0
	for _, v := range op.Values {
		valStr := strings.ToUpper(v)
		valNum, ok := openFlagsString[valStr]
		if !ok {
			return fmt.Errorf("matchOpenFlags: value %s unknown", valStr)
		}
		val.flags[opIdx].Mask |= valNum
	}

	return nil
}

func ParseOpenFlags(k *KernelSelectorState, op []v1alpha1.FileOpenFlagsTypeSelector, selIdx int) error {
	if len(op) > maxOpenFlagMaskPerOp {
		return fmt.Errorf("only support up to %d open flags masks inside a single selector", maxOpenFlagMaskPerOp)
	}
	for opIdx, m := range op {
		if err := ParseOpenFlag(k, m, opIdx, selIdx); err != nil {
			return err
		}
	}
	return nil
}

func ParseMatchFilename(k *KernelSelectorState, op []v1alpha1.FilePathGlobSelector, selIdx int) error {
	if len(op) > 1 {
		return fmt.Errorf("only support a single operation inside a single selector")
	}

	for _, o := range op {
		if o.Operator != "InPattern" && o.Operator != "InFileWithDigest" {
			return fmt.Errorf("only support op 'InPattern' and 'InFileWithDigest'")
		}

		val := k.InitOrGetPatterns(uint32(selIdx))
		if o.Operator == "InFileWithDigest" {
			val.op = MatchFilenameInFileWithDigest

			for idx, p := range o.Values {
				val.paths[p] = uint32(idx)
			}
		} else if o.Operator == "InPattern" {
			if len(o.Values) > 256 {
				return fmt.Errorf("only support up to 256 patterns")
			}

			val.op = MatchFilenameInPattern

			for _, p := range o.Values {
				fsm, err := CompileGlob(p)
				if err != nil {
					return fmt.Errorf("failed to compile glob, pattern: %s error: %w", p, err)
				}
				val.fsm = append(val.fsm, fsm)
			}
		}
	}

	return nil
}

func InitKernelSelectorState(fileSel []v1alpha1.FileSelector, maxFimSelectors int) (*KernelSelectorState, error) {
	if len(fileSel) > maxFimSelectors {
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
		if err := ParseRenameSrcTypes(kernelSelectors, s.MatchRenameSrcType, i); err != nil {
			return nil, fmt.Errorf("parseRenameSrcType error: %w", err)
		}
		if err := ParseOpenFlags(kernelSelectors, s.MatchOpenFlags, i); err != nil {
			return nil, fmt.Errorf("parseOpenFlags error: %w", err)
		}
		if err := ParseMatchFilename(kernelSelectors, s.MatchFilename, i); err != nil {
			return nil, fmt.Errorf("parseMatchFilename error: %w", err)
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

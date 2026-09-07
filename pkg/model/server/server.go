// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

//go:build !nok8s

package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	appModelV1 "github.com/isovalent/ipa/application_model/v1alpha"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	ossoption "github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/process"

	"github.com/cilium/tetragon/api/v1/tetragon"

	lru "github.com/hashicorp/golang-lru/v2"

	"github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	"github.com/isovalent/hubble-fgs/pkg/api/ops"
	"github.com/isovalent/hubble-fgs/pkg/common"
	"github.com/isovalent/hubble-fgs/pkg/dnsparser"
	"github.com/isovalent/hubble-fgs/pkg/endpoint"
	"github.com/isovalent/hubble-fgs/pkg/metrics/appmodelmetrics"
	"github.com/isovalent/hubble-fgs/pkg/model"
	"github.com/isovalent/hubble-fgs/pkg/model/diff"
	"github.com/isovalent/hubble-fgs/pkg/model/types"
	"github.com/isovalent/hubble-fgs/pkg/netpol/library"
	"github.com/isovalent/hubble-fgs/pkg/node/local"
	"github.com/isovalent/hubble-fgs/pkg/option"
	"github.com/isovalent/hubble-fgs/pkg/protoutils"
	"github.com/isovalent/hubble-fgs/pkg/util/set"
	"github.com/isovalent/hubble-fgs/pkg/workloadid"
)

const (
	processTreeMapName         = "process_tree_map"
	processTreeExecIDsMapName  = "tg_pstree_eids"
	destinationEndpointMapName = "destination_endpoint_map"
	listenEndpointMapName      = "listen_endpoint_map"
	endpointIdMapName          = "tg_endpoint_id_map"
	syscallMapName             = "tg_syscall_map"
	cgTrackerIdMapName         = "tg_cgtracker_map"
	defaultNodeLabelsInterval  = time.Minute
)

func decodeArgs(s string) string {
	var args strings.Builder

	for a := range strings.SplitSeq(strings.TrimRight(s, "\x00"), "\x00") {
		if strings.Contains(a, " ") {
			args.WriteByte(' ')
			args.WriteByte('"')
			args.WriteString(a)
			args.WriteByte('"')
		} else if args.Len() == 0 {
			args.WriteString(a)
		} else {
			args.WriteByte(' ')
			args.WriteString(a)
		}
	}

	return args.String()
}

// decodeBinaryArgs extracts the null-terminated binary path and
// double-null-terminated args string from a ProcessTreeValue.
func decodeBinaryArgs(val *types.ProcessTreeValue) (bin, args string) {
	n := bytes.IndexByte(val.Binary[:], 0)
	if n < 0 {
		n = len(val.Binary)
	}
	bin = protoutils.SanitizeString(string(val.Binary[:n]))
	ma := bytes.Index(val.Args[:], []byte{0x00, 0x00})
	if ma < 0 {
		ma = len(val.Args)
	}
	args = string(val.Args[:ma])
	args = decodeArgs(args)
	args = protoutils.SanitizeString(args)
	return bin, args
}

// ktimeConverter converts BPF ktime values to wall-clock times using a single
// CLOCK_BOOTTIME syscall captured at construction. All per-entry conversions
// are pure arithmetic, eliminating one syscall per timestamp field.
type ktimeConverter struct {
	// base is wallclock - boottime, i.e. the offset to add to a ktime_get_boot_ns value.
	base time.Time
}

// convert returns the wall-clock time for kt, or nil for zero values.
func (c ktimeConverter) convert(kt uint64) *time.Time {
	if kt == 0 || c.base.IsZero() {
		return nil
	}
	// There is some nanosecond precision loss in the ktime conversion,
	// so truncate to microsecond precision to preserve consistency in diffs.
	// Otherwise, you end up with consistently differing timestamps which leads to
	// a stream of new telemetry events on every export tick.
	t := c.base.Add(time.Duration(kt)).Truncate(time.Microsecond)
	return &t
}

// cachedBinaryInfo holds the decoded binary path and args for a process UID.
type cachedBinaryInfo struct {
	binary string
	args   string
}

type Server struct {
	tetragon.UnimplementedProcessModelServiceServer
	appModelV1.UnimplementedApplicationModelServiceServer

	// This holds mappings from cgroup id to cgroup tracker id outside of the
	// ebpf map tg_cgtracker_map. We need to hold a separate mapping because the
	// application model includes information for exited processes, while
	// tg_cgtracker_map deletes entries when the cgroup is removed.
	cgTrackerIdCache *lru.Cache[uint64, uint64]

	// Similarly, this holds mappings from cgroup id to container information.
	// We need to hold a separate mapping because the application model includes
	// information for deleted pods and containers. Deleted pod information is
	// actually available via the pod accessor and the deleted pod cache, but
	// it's possible that containers restart within a pod, and the pod accessor
	// does not keep track of deleted containers.
	cgroupIdToContainerInfoCache *lru.Cache[uint64, *types.ContainerInfo]

	// The function used to get the current time. Can be overridden in tests.
	TimeNow func() time.Time

	// binaryArgsCache caches decodeBinaryArgs results by process UID. The
	// binary/args bytes embedded in ProcessTreeValue are set at insertion time
	// and never change, so the decoded strings are stable for the lifetime of
	// the UID in the BPF map.
	binaryArgsCache *lru.Cache[uint64, cachedBinaryInfo]

	metadataService local.MetadataService

	nodeLabelsMutex          sync.Mutex
	nodeLabels               map[string]string
	nodeLabelsLastUpdated    time.Time
	nodeLabelsUpdateInterval time.Duration
}

func addExecIDs(key types.ProcessTreeKey, treeExecIDsMap *ebpf.Map) []string {
	if treeExecIDsMap == nil {
		return nil
	}

	value := types.ProcessTreeExecIds{}
	if err := treeExecIDsMap.Lookup(&key.Self, &value); err != nil {
		return nil
	}

	curLen := min(int(value.CurLen), types.ProcessTreeMaxExecIds)

	hashes := make([]string, 0, curLen)
	for i := range curLen {
		idx := (int(value.CurHead) - curLen + i + types.ProcessTreeMaxExecIds) % types.ProcessTreeMaxExecIds
		hashes = append(hashes, process.GetProcessID(value.ExecIds[idx].Pid, value.ExecIds[idx].Ktime))
	}

	return hashes
}

func (s *Server) GetDestinationMap(_ context.Context, _ *tetragon.GetDestinationMapRequest) (*tetragon.GetDestinationMapResponse, error) {
	dests := make([]*tetragon.DestinationEndpointDebug, 0)
	destMap := filepath.Join(bpf.MapPrefixPath(), destinationEndpointMapName)
	m, err := ebpf.LoadPinnedMap(destMap, nil)
	if err != nil {
		logger.GetLogger().Warn("Could not open destinationEndpointMap for GetDestinationMapRequest", logfields.Error, err, "file", destinationEndpointMapName)
		return nil, err
	}
	defer m.Close()

	var (
		k types.DestinationEndpointKey
		v types.DestinationEndpointValue
	)

	iter := m.Iterate()
	for iter.Next(&k, &v) {
		title, _ := library.GetRepository().GetName(v.Policy)
		d := &tetragon.DestinationEndpointDebug{
			LocalId:               k.LocalId,
			LocalNsId:             k.LocalWLID,
			DestinationId:         k.DestinationId,
			DestinationSource:     k.DestinationSource,
			DestinationPort:       uint64(k.DestinationPort),
			TxDrops:               v.TxDropBytes, //nolint:staticcheck // deprecated, populated for backwards compatibility with TxDropBytes
			TxDropBytes:           v.TxDropBytes,
			TxDropPackets:         v.TxDropPackets,
			DefaultAllowBytes:     v.TxDefaultAllowBytes,
			DefaultDenyBytes:      v.TxDefaultDropBytes,
			DefaultAllowPackets:   v.TxDefaultAllowPackets,
			DefaultDenyPackets:    v.TxDefaultDropPackets,
			RxDropBytes:           v.RxDropBytes,
			RxDropPackets:         v.RxDropPackets,
			RxDefaultDropBytes:    v.RxDefaultDropBytes,
			RxDefaultDropPackets:  v.RxDefaultDropPackets,
			RxDefaultAllowBytes:   v.RxDefaultAllowBytes,
			RxDefaultAllowPackets: v.RxDefaultAllowPackets,
			Policy:                title,
		}
		dests = append(dests, d)
	}

	resp := &tetragon.GetDestinationMapResponse{
		Destinations: dests,
	}

	return resp, nil
}

func (s *Server) GetProcessMap(_ context.Context, _ *tetragon.GetProcessMapRequest) (*tetragon.GetProcessMapResponse, error) {
	tetragonUUID := make([]*tetragon.ProcessUUID, 0)
	indexedUUID := make(map[uint64]*tetragon.ProcessUUID)

	treeMap := filepath.Join(bpf.MapPrefixPath(), processTreeMapName)

	m, err := ebpf.LoadPinnedMap(treeMap, nil)
	if err != nil {
		logger.GetLogger().Warn("Could not open process tree map", logfields.Error, err, "file", treeMap)
		return nil, err
	}
	defer m.Close()

	var (
		keyTk types.ProcessTreeKey
		valTk types.ProcessTreeValue
	)

	type treeEntry struct {
		key    types.ProcessTreeKey
		binary string
		args   string
	}

	// Pass 1: iterate the BPF map, decode binary/args, and populate the
	// UUID index so that every entry is available for child resolution.
	var entries []treeEntry
	iter := m.Iterate()
	for iter.Next(&keyTk, &valTk) {
		selfBin, selfArgs := decodeBinaryArgs(&valTk)
		indexedUUID[keyTk.Self] = &tetragon.ProcessUUID{
			Binary: selfBin,
			Args:   selfArgs,
			Id:     keyTk.Self,
		}
		entries = append(entries, treeEntry{key: keyTk, binary: selfBin, args: selfArgs})
	}

	// Build a parent-to-children map. Path[0..Depth-1] is the ancestry
	// chain (root to immediate parent), so Path[Depth-1] is the parent UID.
	childrenOf := make(map[uint64][]uint64)
	for _, e := range entries {
		if e.key.Depth > 0 && e.key.Depth <= uint64(len(e.key.Path)) {
			parentUID := e.key.Path[e.key.Depth-1]
			childrenOf[parentUID] = append(childrenOf[parentUID], e.key.Self)
		}
	}

	// Pass 2: build Children from the parent-to-children map.
	for _, e := range entries {
		children := make([]*tetragon.ProcessUUID, 0)
		for _, childUID := range childrenOf[e.key.Self] {
			if child := indexedUUID[childUID]; child != nil {
				children = append(children, child)
			}
		}
		value := tetragon.ProcessUUID{
			Binary:   e.binary,
			Args:     e.args,
			Id:       e.key.Self,
			Depth:    uint32(e.key.Depth),
			Children: children,
		}
		tetragonUUID = append(tetragonUUID, &value)
	}

	processMap := &tetragon.ProcessMap{
		Process: tetragonUUID,
	}

	resp := &tetragon.GetProcessMapResponse{
		Map: processMap,
	}

	return resp, nil
}

func GetBPFDnsEndpoints() (map[dnsparser.DNSID]string, error) {
	idToDomainMapFile := bpf.MapPath(dnsparser.IDToDomainMapName)
	idToDomainMap, err := ebpf.LoadPinnedMap(idToDomainMapFile, nil)
	if err != nil {
		return make(map[dnsparser.DNSID]string, 0), fmt.Errorf("fail to load pinned map %s: %w", idToDomainMapFile, err)
	}
	defer idToDomainMap.Close()

	idToDomain := dnsparser.NewIDToDomainMap(idToDomainMap)
	return idToDomain.Values()
}

func (s *Server) GetEndpointMap(_ context.Context, _ *tetragon.GetEndpointMapRequest) (*tetragon.GetEndpointMapResponse, error) {
	c := endpoint.MustGet()
	keys, endpoints := c.DebugEndpointMap()
	tetragonEndpoints := make([]*tetragon.Endpoint, 0)
	endptToId := make(map[uint64]*tetragon.Endpoint)

	bpfDNSEndpoints, err := GetBPFDnsEndpoints()
	if err != nil {
		logger.GetLogger().Warn("failed to collect bpf DNS endpoints", logfields.Error, err)
		// continue and at least collect other endpoints
	}

	endptIdMap := filepath.Join(bpf.MapPrefixPath(), endpointIdMapName)
	endpt, err := ebpf.LoadPinnedMap(endptIdMap, nil)
	if err != nil {
		logger.GetLogger().Warn("Could not open destination endpoint map for EndpointDebugReq", logfields.Error, err, "file", endptIdMap)
		return nil, err
	}
	defer endpt.Close()

	var (
		endptIdKey   types.EndpointIdKey
		endptIdValue types.EndpointIdValue
	)

	for key, e := range bpfDNSEndpoints {
		if key.Source != types.DestinationSourceDNS {
			continue
		}
		id := key.ID
		v := &tetragon.Endpoint{
			Key:  id,
			Type: tetragon.EndpointType_ENDPOINT_TYPE_BPF_DNS,
			Dns:  e,
		}

		endptToId[id] = v
		tetragonEndpoints = append(tetragonEndpoints, v)
	}

	for i, e := range endpoints {
		id := keys[i]
		v := &tetragon.Endpoint{
			Key:       id,
			Type:      tetragon.EndpointType(e.Type),
			Dns:       e.Dns,
			Kind:      e.Kind,
			Namespace: e.Namespace,
			Name:      e.Name,
			Ip:        e.CIDR.String(),
		}

		endptToId[id] = v
		tetragonEndpoints = append(tetragonEndpoints, v)
	}

	iter := endpt.Iterate()
	for iter.Next(&endptIdKey, &endptIdValue) {
		v, ok := endptToId[endptIdValue.Id]
		if !ok {
			continue
		}

		// tbd ipv6 support
		ip := networkapi.GetIP(endptIdKey.Addr, 0, false)
		v.SrcIP = ip.String()
	}

	listenMap := filepath.Join(bpf.MapPrefixPath(), listenEndpointMapName)
	listen, err := ebpf.LoadPinnedMap(listenMap, nil)
	if err != nil {
		return nil, err
	}

	var (
		listenKey   types.ListenKey
		listenValue types.ListenValue
	)

	liter := listen.Iterate()
	for liter.Next(&listenKey, &listenValue) {
		ip6 := listenKey.Addr[1] != 0
		ip := networkapi.GetIP(listenKey.Addr, 0, ip6)
		port := fmt.Sprintf("%d", listenKey.Port)
		v := &tetragon.Endpoint{
			Key:  0,
			Type: tetragon.EndpointType_ENDPOINT_TYPE_LISTEN,
			Ip:   ip.String(),
			Port: port,
		}
		tetragonEndpoints = append(tetragonEndpoints, v)
	}

	endpointMap := &tetragon.EndpointMap{
		Endpoints: tetragonEndpoints,
	}

	resp := &tetragon.GetEndpointMapResponse{
		Map: endpointMap,
	}

	return resp, nil
}

// Remove the provided Process Tree Key from anything used by the Application Model, including:
// - the process tree map
// - the destination endpoint map
// - the syscall map (if syscall tracking is enabled)
// - the process tree exec IDs map (if exec ID tracking is enabled)
func removeProcessTreeKeyFromModel(key *types.ProcessTreeKey, tree *ebpf.Map, endpt *ebpf.Map, sm *ebpf.Map, treeExecIDs *ebpf.Map) {
	// Shouldn't really ever happen, but give up if any of the maps/key are nil
	if key == nil || tree == nil || endpt == nil || (sm == nil && option.Config.EnableSyscallTracking) {
		logger.GetLogger().Warn("nil argument provided to removeProcessTreeKeyFromModel", "key", key, "tree", tree, "endpt", endpt, "sm", sm)
		return
	}

	logger.GetLogger().Debug("Removing ProcessTreeKey from app model state", "uid", key.Self, "wlid", key.WLID)

	// Remove the process tree entry itself.
	if err := tree.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		logger.GetLogger().Warn("Failed to delete stale process tree key", logfields.Error, err, "uid", key.Self, "wlid", key.WLID)
	}

	// Remove per-process destination entries bound to this process tree key.
	var (
		dstKey types.DestinationEndpointKey
		dstVal types.DestinationEndpointValue
	)
	keysToDelete := make([]types.DestinationEndpointKey, 0)
	iter := endpt.Iterate()
	for iter.Next(&dstKey, &dstVal) {
		if dstKey.LocalId == key.Self && dstKey.LocalWLID == key.WLID {
			keysToDelete = append(keysToDelete, dstKey)
		}
	}
	if err := iter.Err(); err != nil {
		logger.GetLogger().Warn("Failed iterating destination endpoint map for stale process key cleanup", logfields.Error, err)
	}
	for _, k := range keysToDelete {
		if err := endpt.Delete(&k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			logger.GetLogger().Warn("Failed to delete stale destination endpoint key", logfields.Error, err, "uid", key.Self, "wlid", key.WLID, "destinationID", k.DestinationId)
		}
	}

	if option.Config.EnableSyscallTracking {
		// Remove syscall tracking entry for this process tree key.
		if err := sm.Delete(key.Self); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			logger.GetLogger().Warn("Failed to delete stale syscall key for process tree key", logfields.Error, err, "uid", key.Self, "wlid", key.WLID)
		}
	}

	if treeExecIDs != nil {
		if err := treeExecIDs.Delete(&key.Self); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			logger.GetLogger().Warn("Failed to delete stale exec IDs key for process tree key", logfields.Error, err, "uid", key.Self, "wlid", key.WLID)
		}
	}
}

// Remove the provided cgroup from anything used by the Application Model, including:
// - the cgroup id to workload id map
// - the cgtracker id cache
// - the container id cache
func removeCgroupFromModel(cgroupid uint64, cgTrackerIdCache *lru.Cache[uint64, uint64], cgroupIdToContainerInfoCache *lru.Cache[uint64, *types.ContainerInfo]) {
	if cgroupid == 0 {
		return
	}

	logger.GetLogger().Debug("Removing cgroup from app model state", "cgroupid", cgroupid)

	if err := workloadid.GetState().DeleteCgroup(workloadid.CgroupID(cgroupid)); err != nil {
		logger.GetLogger().Debug("Failed to delete cgroup from workload ID map", logfields.Error, err, "cgroupid", cgroupid)
	}

	// Remove cached cgroup -> tracker id entries. This cache has the cgroups
	// used in the application model as values, so we need to iterate to find
	// the keys for those values.
	if ossoption.Config.EnableCgTrackerID {
		if cgTrackerIdCache != nil {
			for _, keycgroupid := range cgTrackerIdCache.Keys() {
				valcgroupid, ok := cgTrackerIdCache.Get(keycgroupid)
				if !ok {
					logger.GetLogger().Warn("Failed to get value for cgTrackerIdCache key?", "keycgroupid", keycgroupid)
				} else {
					if valcgroupid == cgroupid {
						cgTrackerIdCache.Remove(keycgroupid)
					}
				}
			}
		} else {
			logger.GetLogger().Warn("cgTrackerIdCache is nil during cgroup cleanup", "cgroupid", cgroupid)
		}
	}

	if cgroupIdToContainerInfoCache != nil {
		cgroupIdToContainerInfoCache.Remove(cgroupid)
	} else {
		logger.GetLogger().Warn("cgroupIdToContainerInfoCache is nil during cgroup cleanup", "cgroupid", cgroupid)
	}
}

func getProcessModel(namespaces []string,
	debug bool,
	cgTrackerIdCache *lru.Cache[uint64, uint64],
	cgroupIdToContainerInfoCache *lru.Cache[uint64, *types.ContainerInfo],
	binaryArgsCache *lru.Cache[uint64, cachedBinaryInfo],
	timeNow func() time.Time) ([]*types.ProcessModel, error) {
	start := timeNow()
	defer func() {
		appmodelmetrics.RecordDuration(appmodelmetrics.PhaseGetProcessModel, float64(timeNow().Sub(start).Microseconds()))
	}()

	processModel := make([]*types.ProcessModel, 0)
	treeMap := filepath.Join(bpf.MapPrefixPath(), processTreeMapName)
	treeExecIDsMap := filepath.Join(bpf.MapPrefixPath(), processTreeExecIDsMapName)
	endptMap := filepath.Join(bpf.MapPrefixPath(), destinationEndpointMapName)
	syscallMap := filepath.Join(bpf.MapPrefixPath(), syscallMapName)
	workloadIDMapPath := filepath.Join(bpf.MapPrefixPath(), workloadid.CgroupIDWorkloadIDMapName)
	cgTrackerIdMapPath := filepath.Join(bpf.MapPrefixPath(), cgTrackerIdMapName)

	var treeExecIDs *ebpf.Map
	var err error
	if option.Config.AppModelTrackExecIds {
		treeExecIDs, err = ebpf.LoadPinnedMap(treeExecIDsMap, nil)
		if err != nil {
			logger.GetLogger().Warn("Could not open process tree exec ids map", logfields.Error, err, "file", treeExecIDsMap)
			return nil, err
		}
		defer treeExecIDs.Close()
	}

	endpt, err := ebpf.LoadPinnedMap(endptMap, nil)
	if err != nil {
		logger.GetLogger().Warn("Could not open destination endpoint map", logfields.Error, err, "file", endptMap)
		return nil, err
	}
	defer endpt.Close()

	nsIDMap, err := ebpf.LoadPinnedMap(workloadIDMapPath, nil)
	if err != nil {
		logger.GetLogger().Warn("Could not open workload ID map", logfields.Error, err, "file", workloadIDMapPath)
		return nil, err
	}
	defer nsIDMap.Close()

	var cgTrackerMap *ebpf.Map
	if ossoption.Config.EnableCgTrackerID {
		cgTrackerMap, err = ebpf.LoadPinnedMap(cgTrackerIdMapPath, nil)
		if err != nil {
			logger.GetLogger().Warn("Could not open cgroup tracker ID map", logfields.Error, err, "file", cgTrackerIdMapPath)
			return nil, err
		}
		defer cgTrackerMap.Close()
	}

	var dnsDomainMap dnsparser.DomainMap
	defer dnsDomainMap.CloseMaps()

	var (
		dstKey types.DestinationEndpointKey
		dstVal types.DestinationEndpointValue
	)

	type dstListKey struct {
		localID    uint64
		workloadID uint64
	}

	dstMaxEntries := int(endpt.MaxEntries())
	dstList := make(map[dstListKey][]*types.Destination, dstMaxEntries)
	nsList := make(map[uint64][]*types.Destination, dstMaxEntries)

	c := endpoint.MustGet()

	var destinationCount int
	iter := endpt.Iterate()
	for iter.Next(&dstKey, &dstVal) {
		var d *types.Destination
		var ep endpoint.Endpoint

		// Skip policy template entries that have not observed real traffic yet.
		// These are created when policies are programmed but the connection
		// hasn't actually been used. BPF clears this flag on first traffic.
		if dstVal.Flags&types.DestFlagPolicyTemplateOnly != 0 {
			continue
		}

		// The zero destination rule is a default_action policy rule
		// skip posting to the user as drops have been pushed down
		// to more specific rules and showing 0.0.0.0 -> 0.0.0.0 drops
		// counter seems not so helpful.
		if dstKey.DestinationId == 0 {
			continue
		}

		switch dstKey.DestinationSource {
		case types.DestinationSourceBPF:
			if dstVal.IPv6 == 0 {
				addr := uint32(dstVal.AddrCreate[0])
				if id, err := c.LookupIPv4Raw(addr); err == nil {
					var ok bool
					ep, ok = c.LookupID(id)
					if !ok {
						continue
					}
					if ep.Type == tetragon.EndpointType_ENDPOINT_TYPE_DNS && debug {
						ep.Dns = ep.Dns + "<promoted>"
					}
				} else {
					b := [4]byte{byte(addr), byte(addr >> 8), byte(addr >> 16), byte(addr >> 24)}
					ep = endpoint.Endpoint{
						Type: tetragon.EndpointType_ENDPOINT_TYPE_IP,
						CIDR: netip.PrefixFrom(netip.AddrFrom4(b), 32),
					}
				}
			} else {
				ip := networkapi.GetIP(dstVal.AddrCreate, ops.MSG_OP_UNDEF, true)
				if id, err := c.LookupIP(ip); err == nil {
					var ok bool
					ep, ok = c.LookupID(id)
					if !ok {
						continue
					}
					if ep.Type == tetragon.EndpointType_ENDPOINT_TYPE_DNS && debug {
						ep.Dns = ep.Dns + "<promoted>"
					}
				} else {
					addr, ok := netip.AddrFromSlice(ip)
					if !ok {
						return nil, fmt.Errorf("failed to convert net.IP to netip.Addr, this shouldn't happen")
					}
					ep = endpoint.Endpoint{
						Type: tetragon.EndpointType_ENDPOINT_TYPE_IP,
						CIDR: netip.PrefixFrom(addr, 128),
					}
				}
			}
		case types.DestinationSourceUser:
			var ok bool

			// If we have service or pod for this destination ID then
			// use that. If none exists check the domain map for a
			// DNS string and use that. Finally, give up at that point.
			ep, ok = c.LookupID(dstKey.DestinationId)
			if ok {
				break
			}

			domain, err := dnsDomainMap.Domain(dstKey.DestinationId)
			if err != nil {
				logger.GetLogger().Warn("Could not retrieve BPF DNS parser domain info for Source User", logfields.Error, err, "id", dstKey.DestinationId)
				appmodelmetrics.RecordLookupError(appmodelmetrics.LookupDNS)
				continue
			}
			ep = endpoint.Endpoint{
				Type: tetragon.EndpointType_ENDPOINT_TYPE_DNS,
				Dns:  domain,
			}
		case types.DestinationSourceDNS:
			domain, err := dnsDomainMap.Domain(dstKey.DestinationId)
			if err != nil {
				logger.GetLogger().Warn("Could not retrieve BPF DNS parser domain info", logfields.Error, err)
				appmodelmetrics.RecordLookupError(appmodelmetrics.LookupDNS)
				continue
			}
			ep = endpoint.Endpoint{
				Type: tetragon.EndpointType_ENDPOINT_TYPE_DNS,
				Dns:  domain,
			}
		default:
			logger.GetLogger().Warn("unknown dstKey.DestinationSrc", "dstKey", dstKey, "dstVal", dstVal)
			continue
		}

		observedAtDestination := dstVal.Flags&types.DestFlagObservedAtDestination != 0

		stats := &types.DestinationStats{
			TxBytes:               dstVal.TxBytes,
			RxBytes:               dstVal.RxBytes,
			TxDropBytes:           dstVal.TxDropBytes,
			DefaultAllowBytes:     dstVal.TxDefaultAllowBytes,
			DefaultDenyBytes:      dstVal.TxDefaultDropBytes,
			Sessions:              dstVal.Sessions,
			TxDropPackets:         dstVal.TxDropPackets,
			DefaultAllowPackets:   dstVal.TxDefaultAllowPackets,
			DefaultDenyPackets:    dstVal.TxDefaultDropPackets,
			RxDropBytes:           dstVal.RxDropBytes,
			RxDropPackets:         dstVal.RxDropPackets,
			RxDefaultDropBytes:    dstVal.RxDefaultDropBytes,
			RxDefaultDropPackets:  dstVal.RxDefaultDropPackets,
			RxDefaultAllowBytes:   dstVal.RxDefaultAllowBytes,
			RxDefaultAllowPackets: dstVal.RxDefaultAllowPackets,
		}
		if dstVal.Policy != 0 {
			policy, ok := library.GetRepository().GetName(dstVal.Policy)
			if !ok {
				logger.GetLogger().Warn("unknown policy id in process model", "policyID", dstVal.Policy)
			} else {
				stats.Policy = policy
			}

			denyDefault := dstVal.TxDefaultDropBytes > 0
			allowDefault := dstVal.TxDefaultAllowBytes > 0
			rule, ok := library.GetRepository().GetRule(policy, dstVal.RuleID, denyDefault, allowDefault)
			if !ok {
				logger.GetLogger().Warn("unknown rule id in process model", "Policy", policy, "ruleID", dstVal.RuleID)

			} else {
				stats.RuleName = rule
			}
		}

		switch ep.Type {
		case tetragon.EndpointType_ENDPOINT_TYPE_UNKNOWN:
			d = &types.Destination{
				DestinationNames:      []string{},
				Port:                  0,
				Stats:                 stats,
				Protocol:              dstVal.Protocol,
				ObservedAtDestination: observedAtDestination,
			}
		case tetragon.EndpointType_ENDPOINT_TYPE_DNS:
			d = &types.Destination{
				DestinationNames:      strings.Split(ep.Dns, ","),
				Port:                  dstVal.Port,
				Stats:                 stats,
				Protocol:              dstVal.Protocol,
				ObservedAtDestination: observedAtDestination,
			}
		case tetragon.EndpointType_ENDPOINT_TYPE_POD:
			workloadUID := ep.UID
			if workloadID, ok := workloadid.GetState().LookupID(workloadid.WorkloadKey{
				Namespace: ep.Namespace,
				Workload:  ep.Name,
				Kind:      ep.Kind,
			}); ok {
				if workload, ok := workloadid.GetState().LookupMeta(workloadID); ok {
					workloadUID = workload.UID
				}
			}
			d = &types.Destination{
				DestinationPod: &types.Pod{
					Namespace:    ep.Namespace,
					Workload:     ep.Name,
					WorkloadKind: ep.Kind,
					WorkloadUID:  workloadUID,
				},
				Port:                  dstVal.Port,
				Stats:                 stats,
				Protocol:              dstVal.Protocol,
				ObservedAtDestination: observedAtDestination,
			}
		case tetragon.EndpointType_ENDPOINT_TYPE_IP:
			// Report the address via DestinationIP so it classifies as a plain
			// IP downstream. Do not put it in DestinationNames, which would
			// misfile it as a DNS name and emit it in world_entity.dns_name.
			d = &types.Destination{
				DestinationIP:         ep.CIDR.Addr().String(),
				Port:                  dstVal.Port,
				Stats:                 stats,
				Protocol:              dstVal.Protocol,
				ObservedAtDestination: observedAtDestination,
			}
		case tetragon.EndpointType_ENDPOINT_TYPE_SERVICE:
			d = &types.Destination{
				DestinationService: &types.Service{
					Namespace: ep.Namespace,
					Name:      ep.Name,
					UID:       ep.UID,
				},
				Port:                  dstVal.Port,
				Stats:                 stats,
				Protocol:              dstVal.Protocol,
				ObservedAtDestination: observedAtDestination,
			}
		case tetragon.EndpointType_ENDPOINT_TYPE_LISTEN:
			d = &types.Destination{
				Port:                  dstVal.Port,
				Stats:                 stats,
				Protocol:              dstVal.Protocol,
				ObservedAtDestination: observedAtDestination,
			}
		case tetragon.EndpointType_ENDPOINT_TYPE_BPF_DNS:
			d = &types.Destination{
				DestinationNames:      []string{ep.Name},
				Port:                  dstVal.Port,
				Stats:                 stats,
				Protocol:              dstVal.Protocol,
				ObservedAtDestination: observedAtDestination,
			}
		case tetragon.EndpointType_ENDPOINT_TYPE_NODE:
			d = &types.Destination{
				DestinationNames:      []string{ep.Name},
				Port:                  dstVal.Port,
				Stats:                 stats,
				Protocol:              dstVal.Protocol,
				ObservedAtDestination: observedAtDestination,
			}
		case tetragon.EndpointType_ENDPOINT_TYPE_CIDR:
			// Report the address via DestinationIP so it classifies as a plain
			// IP downstream, matching ENDPOINT_TYPE_IP.
			d = &types.Destination{
				DestinationIP:         ep.CIDR.Addr().String(),
				Port:                  dstVal.Port,
				Stats:                 stats,
				Protocol:              dstVal.Protocol,
				ObservedAtDestination: observedAtDestination,
			}
		}

		destinationCount++

		// If this is the Zero ProcessID and it has a WLID then its an
		// aggregated CgroupId destination.
		if dstKey.LocalId == 0 && dstKey.LocalWLID != 0 {
			cgid := dstKey.LocalWLID
			l, ok := nsList[cgid]
			if !ok {
				nsList[cgid] = []*types.Destination{d}
			} else {
				l := append(l, d)
				nsList[cgid] = l
			}
		} else {
			idKey := dstListKey{
				localID:    dstKey.LocalId,
				workloadID: dstKey.LocalWLID,
			}

			l, ok := dstList[idKey]
			if !ok {
				dstList[idKey] = []*types.Destination{d}
			} else {
				l = append(l, d)
				dstList[idKey] = l
			}
		}
	}

	m, err := ebpf.LoadPinnedMap(treeMap, nil)
	if err != nil {
		logger.GetLogger().Warn("Could not open process tree map", logfields.Error, err, "file", treeMap)
		return nil, err
	}

	defer m.Close()

	var sm *ebpf.Map
	var abi string
	if option.Config.EnableSyscallTracking {
		abi, err = common.DefaultABI()
		if err != nil {
			return nil, fmt.Errorf("unsupported ABI %q for syscall sensor: %w", abi, err)
		}

		sm, err = ebpf.LoadPinnedMap(syscallMap, nil)
		if err != nil {
			logger.GetLogger().Info("Could not open syscall map", logfields.Error, err, "file", syscallMap)
			return nil, err
		}

		defer sm.Close()
	}

	var (
		key        types.ProcessTreeKey
		val        types.ProcessTreeValue
		syscallVal types.ProcessSyscallValue
	)

	err = initContainerIDMap()
	if err != nil {
		logger.GetLogger().Error("Could not open cgroupID to containerID map", logfields.Error, err)
		return nil, err
	}

	/* Build out Branches for workloads */
	for ns, d := range nsList {
		var nsPath, wlPath, kind string

		wlid, ok := workloadid.GetState().LookupMeta(workloadid.WorkloadID(ns))
		if ok {
			nsPath = wlid.Namespace
			wlPath = wlid.Workload
			kind = wlid.Kind
		} else {
			nsPath = model.HostNamespace
			wlPath = model.HostWorkload
			kind = model.HostKind
		}
		if len(namespaces) > 0 && !slices.Contains(namespaces, nsPath) {
			continue
		}

		processModel = append(processModel, &types.ProcessModel{
			Binary:    "",
			Parent:    "",
			Namespace: nsPath,
			Workload: &types.Workload{
				Name: wlPath,
				Kind: kind,
				UID:  wlid.UID,
			},
			Dest: d,
		})
	}

	idKey := dstListKey{
		localID:    0,
		workloadID: 0,
	}

	// Build process independent destination totals for host; these use
	// the defined id 0. If the model is qualified by namespace ignore
	// these host destinations.
	if len(dstList[idKey]) != 0 && len(namespaces) == 0 {
		processModel = append(processModel, &types.ProcessModel{
			Binary:    "",
			Parent:    "",
			Namespace: "",
			Dest:      dstList[idKey],
			Workload:  &types.Workload{},
		})
	}

	type WLIDUpdate struct {
		oldValue      types.ProcessTreeValue
		newWorkloadID uint64
		newCgroupID   uint64
	}
	pendingNSIDUpdates := make(map[types.ProcessTreeKey]WLIDUpdate)
	var skippedEntries int
	treeMaxEntries := int(m.MaxEntries())
	binaryByUID := make(map[uint64]cachedBinaryInfo, treeMaxEntries)

	type processEntry struct {
		key             types.ProcessTreeKey
		ns, wl          string
		kind            string
		uid             string
		selfBin         string
		selfArgs        string
		execIDs         []string
		dest            []*types.Destination
		inInitTree      bool
		syscalls        set.Set[uint32]
		container       *types.ContainerInfo
		cgroupid        uint64
		ktimeFirstExec  uint64
		ktimeLastExec   uint64
		ktimeLatestExit uint64
		execCount       uint64
		exitCount       uint64
	}

	ktConv := newKtimeConverter()

	// Pass 1: iterate the BPF map, collect per-entry state, and populate
	// binaryByUID so that parent resolution in pass 2 never misses.
	procEntries := make([]processEntry, 0, treeMaxEntries)

	// Keep track of "stale" process tree keys, where the ExecCount == ExitCount
	// and KTimeLatestExec is older than now - the retention duration.
	staleProcessTreeKeys := make(map[types.ProcessTreeKey]types.ProcessTreeValue)

	// This tracks the set of process tree keys for each cgroup. When every
	// process tree for a cgroup is present in staleProcessTreeKeys, we can also
	// remove the cgroup.
	cgroupCountsMap := make(map[uint64][]types.ProcessTreeKey)

	retentionCutoff := start.Add(-option.Config.ApplicationModelRetentionDuration)
	logger.GetLogger().Debug("Using threshold for stale process retention", "retentionCutoff", retentionCutoff, "duration", option.Config.ApplicationModelRetentionDuration)

	iter = m.Iterate()
	for iter.Next(&key, &val) {
		var ns, wl, kind, uid string
		var syscalls set.Set[uint32]
		if option.Config.EnableSyscallTracking {
			syscalls = set.NewSet[uint32]()
		}

		// If EnableCgTrackerID is enabled, we need to find the cgroup tracker id for this cgroup id
		var cgroupid uint64

		// Read binary path and args from the LRU cache, falling back to decode.
		// Binary is embedded at insertion time and never changes for a given UID.
		var binInfo cachedBinaryInfo
		if cached, ok := binaryArgsCache.Get(key.Self); ok {
			binInfo = cached
		} else {
			selfBin, selfArgs := decodeBinaryArgs(&val)
			binInfo = cachedBinaryInfo{binary: selfBin, args: selfArgs}
			binaryArgsCache.Add(key.Self, binInfo)
		}
		selfBin, selfArgs := binInfo.binary, binInfo.args
		// Binary is embedded at insertion time, so this is not expected
		// to be empty in practice. Guard defensively just in case.
		if selfBin == "" {
			logger.GetLogger().Debug("Empty binary in process tree entry", "uuid", key.Self)
			skippedEntries++
			continue
		}

		// Only look up cgroup tracker ids for non host (or possibly non-host) processes.
		if ossoption.Config.EnableCgTrackerID &&
			(key.WLID != 0 || (key.WLID == 0 && val.MaybeMissingWLID)) {
			var ok bool

			cgroupid, ok = cgTrackerIdCache.Get(val.CgroupID)
			if !ok {
				err = cgTrackerMap.Lookup(&val.CgroupID, &cgroupid)
				if err != nil {
					logger.GetLogger().Debug("Failed to look up cgroup tracker id for process", logfields.Error, err, "binary", selfBin, "args", selfArgs, "wlid", key.WLID, "missing", val.MaybeMissingWLID, "val.CgroupID", val.CgroupID)
					appmodelmetrics.RecordLookupError(appmodelmetrics.LookupCgroup)
					// Use the cgroupid from val
					cgroupid = val.CgroupID
				} else {
					cgTrackerIdCache.Add(val.CgroupID, cgroupid)
				}
			}
		} else {
			cgroupid = val.CgroupID
		}

		// Track all process tree keys per cgroup and mark stale entries for GC.
		if cgroupid != 0 {
			cgroupCountsMap[cgroupid] = append(cgroupCountsMap[cgroupid], key)
		}
		if val.ExecCount > 0 && val.ExecCount == val.ExitCount && val.KtimeLatestExit > 0 {
			if exitTime := ktConv.convert(val.KtimeLatestExit); exitTime != nil && exitTime.Before(retentionCutoff) {
				logger.GetLogger().Debug("Marking process tree entry as stale", "binary", selfBin, "args", selfArgs, "wlid", key.WLID, "cgroupid", cgroupid, "ExecCount", val.ExecCount, "ExitCount", val.ExitCount, "exitTime", exitTime)
				staleProcessTreeKeys[key] = val

				// No need to do any of the other lookups, this process won't be
				// added to procEntries anyway.
				continue
			}
		}

		if val.MaybeMissingWLID {
			var updatedNSID uint64
			if err := nsIDMap.Lookup(cgroupid, &updatedNSID); err != nil {
				logger.GetLogger().Debug("failed to look up workload id", logfields.Error, err, "cgid", cgroupid)
				appmodelmetrics.RecordLookupError(appmodelmetrics.LookupNSID)
			} else {
				// Queue up a map update and fixup WLID value
				pendingNSIDUpdates[key] = WLIDUpdate{
					oldValue:      val,
					newWorkloadID: updatedNSID,
					newCgroupID:   cgroupid,
				}
				key.WLID = updatedNSID
			}
		}

		policyFilterNSInfo, ok := workloadid.GetState().LookupMeta(workloadid.WorkloadID(key.WLID))
		if ok {
			ns = policyFilterNSInfo.Namespace
			wl = policyFilterNSInfo.Workload
			kind = policyFilterNSInfo.Kind
			uid = policyFilterNSInfo.UID
		} else {
			ns = model.HostNamespace
			wl = model.HostWorkload
			kind = model.HostKind
		}
		if len(namespaces) > 0 && !slices.Contains(namespaces, ns) {
			continue
		}

		binaryByUID[key.Self] = binInfo

		idKey := dstListKey{
			localID:    key.Self,
			workloadID: key.WLID,
		}
		dest := dstList[idKey]
		inInitTree := val.InInitTree

		if option.Config.EnableSyscallTracking {
			err = sm.Lookup(&key.Self, &syscallVal)
			if err == nil {
				for i, mask := range syscallVal.Syscalls {
					for j := range 64 {
						if mask&(uint64(1)<<j) != uint64(0) {
							id := i*64 + j
							syscalls.Insert(uint32(id))
						}
					}
				}
			} else {
				logger.GetLogger().Debug("Failed to look up system calls for process", logfields.Error, err, "key", key.Self)
				appmodelmetrics.RecordLookupError(appmodelmetrics.LookupSyscall)
			}
		}

		// Look up container information from cgroup id
		var containerInfo *types.ContainerInfo

		if cgroupid != 0 {
			logger.GetLogger().Debug("Looking up container info", "binary", selfBin, "args", selfArgs, "cgroupid", cgroupid)
			containerInfo = getContainerInfo(cgroupid, cgroupIdToContainerInfoCache)
		}

		procEntries = append(procEntries, processEntry{
			key: key,
			ns:  ns, wl: wl, kind: kind,
			uid:     uid,
			selfBin: selfBin, selfArgs: selfArgs,
			execIDs: addExecIDs(key, treeExecIDs),
			dest:    dest, inInitTree: inInitTree,
			syscalls:        syscalls,
			container:       containerInfo,
			cgroupid:        cgroupid,
			ktimeFirstExec:  val.KtimeFirstExec,
			ktimeLastExec:   val.KtimeLastExec,
			ktimeLatestExit: val.KtimeLatestExit,
			execCount:       val.ExecCount,
			exitCount:       val.ExitCount,
		})
	}

	// Pass 2: resolve parent binary/args from the now-complete binaryByUID
	// index and build the final process model entries.
	for _, e := range procEntries {
		parentPath := ""
		parentArgs := ""
		if e.key.Depth > 0 && e.key.Depth <= uint64(len(e.key.Path)) {
			parentUID := e.key.Path[e.key.Depth-1]
			if info, ok := binaryByUID[parentUID]; ok {
				parentPath = info.binary
				parentArgs = info.args
			}
		}

		// Initialize parents slice with immediate parent if it exists
		var parents []string
		if parentPath != "" {
			parents = []string{parentPath}
		}

		processModel = append(processModel, &types.ProcessModel{
			Binary:     e.selfBin,
			BinaryArgs: e.selfArgs,
			Parent:     parentPath,
			ParentArgs: parentArgs,
			Parents:    parents,
			ExecIDs:    e.execIDs,
			Namespace:  e.ns,
			Syscalls:   e.syscalls.AsSlice(),
			Abi:        abi,
			Workload: &types.Workload{
				Name: e.wl,
				Kind: e.kind,
				UID:  e.uid,
			},
			Container:       e.container,
			Dest:            e.dest,
			InInitTree:      e.inInitTree,
			FirstStartTime:  ktConv.convert(e.ktimeFirstExec),
			LatestStartTime: ktConv.convert(e.ktimeLastExec),
			LatestExitTime:  ktConv.convert(e.ktimeLatestExit),
			ExecCount:       e.execCount,
			ExitCount:       e.exitCount,
		})

		logger.GetLogger().Debug("Added process model", "process", *processModel[len(processModel)-1])
	}

	if skippedEntries > 0 {
		logger.GetLogger().Warn("Skipped process tree entries with missing binary info (LRU eviction)",
			"count", skippedEntries)
	}

	// Garbage collect stale process tree keys.

	for staleKey := range staleProcessTreeKeys {
		removeProcessTreeKeyFromModel(&staleKey, m, endpt, sm, treeExecIDs)
	}

	// Garbage collect cgroups where all process tree entries are stale.
	for cgroupid, keys := range cgroupCountsMap {
		allStale := len(keys) > 0
		for _, key := range keys {
			if _, ok := staleProcessTreeKeys[key]; !ok {
				allStale = false
				break
			}
		}
		if allStale {
			removeCgroupFromModel(cgroupid, cgTrackerIdCache, cgroupIdToContainerInfoCache)
		}
	}

	// Do queued WorkloadID updates
	// TODO use batch operations here if supported
	for k, v := range pendingNSIDUpdates {
		// Delete the old entry
		m.Delete(&k)
		// Fix up new WorkloadID and remove the flag
		k.WLID = v.newWorkloadID
		k.CGID = v.newCgroupID
		v.oldValue.MaybeMissingWLID = false
		// Update process tree map with the new value
		if err := m.Update(&k, &v.oldValue, ebpf.UpdateAny); err != nil {
			logger.GetLogger().Debug("failed to update process tree map with corrected WLID", logfields.Error, err, "wlid", k.WLID, "uid", k.Self)
		}
	}
	clear(pendingNSIDUpdates)

	appmodelmetrics.SetEntities(appmodelmetrics.EntityDestination, destinationCount)

	return processModel, nil
}

var ErrApplicationModelNotEnabled = errors.New("application model must be enabled with the --enable-application-model flag or the tetragon.enableApplicationModel Helm value")

func (s *Server) GetProcessModel(_ context.Context, ns []string, debug bool) ([]*types.ProcessModel, error) {
	if !option.Config.EnableApplicationModel {
		return nil, ErrApplicationModelNotEnabled
	}
	return getProcessModel(ns, debug, s.cgTrackerIdCache, s.cgroupIdToContainerInfoCache, s.binaryArgsCache, s.TimeNow)
}

func (s *Server) GetApplicationModel(ctx context.Context, nsFilter map[string]bool) (*appModelV1.ApplicationModelEvent, error) {
	res, err := s.GetProcessModel(ctx, []string{}, false)
	if err != nil {
		logger.GetLogger().Error("Failed to get process model from Tetragon", logfields.Error, err)
		return nil, err
	}

	model := model.ProcessModelToApplicationModel(res, nsFilter, s.GetNodeLabels(ctx))

	return model, nil
}

func (s *Server) GetNodeLabels(ctx context.Context) map[string]string {
	now := s.TimeNow()
	s.nodeLabelsMutex.Lock()
	defer s.nodeLabelsMutex.Unlock()

	if s.nodeLabels != nil && now.Before(s.nodeLabelsLastUpdated.Add(s.nodeLabelsUpdateInterval)) {
		return s.nodeLabels
	}

	nodeLabels, err := s.metadataService.GetLabels(ctx)
	if err != nil {
		logger.GetLogger().Warn("Failed to get node labels. node_labels field will be empty", logfields.Error, err)
		nodeLabels = make(map[string]string)
	}
	s.nodeLabels = nodeLabels
	s.nodeLabelsLastUpdated = now
	return s.nodeLabels
}

func (s *Server) GetModel(ctx context.Context, req *appModelV1.GetModelRequest) (*appModelV1.GetModelResponse, error) {
	nsFilter := make(map[string]bool, 0)
	for _, f := range req.Namespaces {
		nsFilter[f] = true
	}

	model, err := s.GetApplicationModel(ctx, nsFilter)
	if err != nil {
		return nil, err
	}

	return &appModelV1.GetModelResponse{
		Model: model,
	}, nil
}

func (s *Server) StreamModelFragments(req *appModelV1.StreamModelFragmentsRequest, stream appModelV1.ApplicationModelService_StreamModelFragmentsServer) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	nsFilter := make(map[string]bool, 0)
	for _, f := range req.Namespaces {
		nsFilter[f] = true
	}

	appModel, err := s.GetApplicationModel(ctx, nsFilter)
	if err != nil {
		return err
	}

	fragments := model.SplitApplicationModelEvent(appModel)

	for _, m := range fragments {
		resp := &appModelV1.StreamModelFragmentsResponse{
			ModelFragment: m,
		}

		if err := stream.Send(resp); err != nil {
			logger.GetLogger().Error("Failed to send application model event", logfields.Error, err)
			return err
		}
	}
	return nil

}

func (s *Server) StreamTelemetry(req *appModelV1.StreamTelemetryRequest, stream appModelV1.ApplicationModelService_StreamTelemetryServer) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	interval := time.Duration(1) * time.Second
	ticker := time.NewTicker(interval)

	nsFilter := make(map[string]bool, 0)
	for _, f := range req.Namespaces {
		nsFilter[f] = true
	}

	res, err := s.GetProcessModel(ctx, []string{}, false)
	if err != nil {
		logger.GetLogger().Error("Failed to get process model from Tetragon", logfields.Error, err)
		return err
	}
	lastModel := model.ProcessModelToApplicationModel(res, nsFilter, s.GetNodeLabels(ctx))

	for {
		var networkDiffModel *appModelV1.ApplicationModel

		select {
		case <-ticker.C:
			res, err := s.GetProcessModel(ctx, []string{}, false)
			if err != nil {
				logger.GetLogger().Error("Failed to get process model from Tetragon", logfields.Error, err)
				return err
			}
			newModel := model.ProcessModelToApplicationModel(res, nsFilter, s.GetNodeLabels(ctx))
			networkDiffModel, _, err = diff.ApplicationModelDiff(newModel.ApplicationModel, lastModel.ApplicationModel)
			if err != nil {
				logger.GetLogger().Error("Failed to produce application model difference", logfields.Error, err)
				return err
			}

			// If nothing has changed do not update last model and skip writing empty record
			if networkDiffModel == nil {
				continue
			}
			lastModel = newModel

			netFlatPack, err := diff.ApplicationModelToNetworkFlat(ctx, networkDiffModel, s.metadataService)
			if err != nil {
				logger.GetLogger().Error("Failed to decode application model to network event model", logfields.Error, err)
				return err
			}
			for _, entry := range netFlatPack {
				network := &appModelV1.StreamTelemetryResponse_NetworkConnect{
					NetworkConnect: entry,
				}
				send := appModelV1.StreamTelemetryResponse{
					Event: network,
				}
				if err := stream.Send(&send); err != nil {
					logger.GetLogger().Error("Failed to send network event model", logfields.Error, err)
					return err
				}
			}
		case <-ctx.Done():
			return nil
		}
	}
}

func DefaultNewServer() (*Server, error) {
	dfltBpfId := true
	return NewServer(dfltBpfId)
}

func NewServer(enableBpfId bool) (*Server, error) {
	cfg := &CfgProcessModel{
		Enable:       option.Config.EnableApplicationModel,
		EnableBpfId:  enableBpfId,
		TrackExecIds: option.Config.AppModelTrackExecIds,
	}

	err := configureSettings(cfg)
	if err != nil {
		return nil, err
	}

	cgTrackerIdCacheInstance, err := lru.New[uint64, uint64](option.Config.ProcessTreeCacheSize)
	if err != nil {
		logger.GetLogger().Error("Failed to create LRU cache for cgroup tracker IDs", logfields.Error, err)
		return nil, err
	}

	cgroupIdToContainerInfoCacheInstance, err := lru.New[uint64, *types.ContainerInfo](option.Config.ProcessTreeCacheSize)
	if err != nil {
		logger.GetLogger().Error("Failed to create LRU cache for container IDs", logfields.Error, err)
		return nil, err
	}

	binaryArgsCacheInstance, err := lru.New[uint64, cachedBinaryInfo](option.Config.ProcessTreeCacheSize)
	if err != nil {
		logger.GetLogger().Error("Failed to create LRU cache for binary args", logfields.Error, err)
		return nil, err
	}

	mService, err := local.GetMetadataService()
	if err != nil {
		logger.GetLogger().Warn("Failed to get metadata service. Node labels will be incomplete", logfields.Error, err)
		mService = &local.NoopMetadataService{}
	}

	return &Server{
		cgTrackerIdCache:             cgTrackerIdCacheInstance,
		cgroupIdToContainerInfoCache: cgroupIdToContainerInfoCacheInstance,
		binaryArgsCache:              binaryArgsCacheInstance,
		TimeNow:                      time.Now,
		metadataService:              mService,
		nodeLabelsUpdateInterval:     defaultNodeLabelsInterval,
	}, nil
}

// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

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
	"time"

	"github.com/cilium/ebpf"
	appModelV1 "github.com/isovalent/ipa/application_model/v1alpha"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/cilium/tetragon/pkg/api"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/ktime"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	ossoption "github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/process"

	"github.com/cilium/cilium/pkg/container/set"

	"github.com/cilium/tetragon/api/v1/tetragon"

	"github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	"github.com/isovalent/hubble-fgs/pkg/api/ops"
	"github.com/isovalent/hubble-fgs/pkg/common"
	"github.com/isovalent/hubble-fgs/pkg/dnsparser"
	"github.com/isovalent/hubble-fgs/pkg/endpoint"
	"github.com/isovalent/hubble-fgs/pkg/model"
	"github.com/isovalent/hubble-fgs/pkg/model/diff"
	"github.com/isovalent/hubble-fgs/pkg/model/types"
	"github.com/isovalent/hubble-fgs/pkg/netpol/library"
	"github.com/isovalent/hubble-fgs/pkg/option"
	"github.com/isovalent/hubble-fgs/pkg/protoutils"
	"github.com/isovalent/hubble-fgs/pkg/workloadid"
)

const (
	processTreeMapName         = "process_tree_map"
	destinationEndpointMapName = "destination_endpoint_map"
	listenEndpointMapName      = "listen_endpoint_map"
	endpointIdMapName          = "tg_endpoint_id_map"
	syscallMapName             = "tg_syscall_map"
	cgTrackerIdMapName         = "tg_cgtracker_map"
)

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
	args, _ = process.ArgsDecoder(args, api.EventNoCWDSupport)
	args = protoutils.SanitizeString(args)
	return bin, args
}

// ktimeToTime converts a ktime value to *time.Time, returning nil for zero values
func ktimeToTime(kt uint64) *time.Time {
	if kt == 0 {
		return nil
	}
	// Use CLOCK_BOOTTIME (monotonic=false) since BPF uses ktime_get_boot_ns() when available.
	// This ensures correct timestamp conversion after system suspend/resume cycles.
	// The application model requires modern kernels (5.x+) where ktime_get_boot_ns is
	// always available, so CLOCK_BOOTTIME is the sensible default here.
	t, err := ktime.DecodeKtime(int64(kt), false)
	if err != nil {
		return nil
	}
	// There is some nanosecond precision loss in the ktime conversion,
	// so truncate to microsecond precision to preserve consistency in diffs.
	// Otherwise, you end up with consistently differing timestamps which leads to
	// a stream of new telemetry events on every export tick.
	t = t.Truncate(time.Microsecond)
	return &t
}

type Server struct {
	tetragon.UnimplementedProcessModelServiceServer
	appModelV1.UnimplementedApplicationModelServiceServer
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
			LocalId:           k.LocalId,
			LocalNsId:         k.LocalNSId,
			DestinationId:     k.DestinationId,
			DestinationSource: k.DestinationSource,
			DestinationPort:   k.DestinationPort,
			TxQuota:           v.TxQuota,
			TxLimit:           v.TxLimit,
			TxDrops:           v.TxDrops,
			DefaultAllowBytes: v.AllowDefaultBytes,
			DefaultDenyBytes:  v.DenyDefaultBytes,
			Policy:            title,
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

func GetProcessModel(namespaces []string, debug bool) ([]*types.ProcessModel, error) {
	processModel := make([]*types.ProcessModel, 0)
	treeMap := filepath.Join(bpf.MapPrefixPath(), processTreeMapName)
	endptMap := filepath.Join(bpf.MapPrefixPath(), destinationEndpointMapName)
	syscallMap := filepath.Join(bpf.MapPrefixPath(), syscallMapName)
	nsIDMapPath := filepath.Join(bpf.MapPrefixPath(), workloadid.CgroupIDWorkloadIDMapName)
	cgTrackerIdMapPath := filepath.Join(bpf.MapPrefixPath(), cgTrackerIdMapName)

	endpt, err := ebpf.LoadPinnedMap(endptMap, nil)
	if err != nil {
		logger.GetLogger().Warn("Could not open destination endpoint map", logfields.Error, err, "file", endptMap)
		return nil, err
	}
	defer endpt.Close()

	nsIDMap, err := ebpf.LoadPinnedMap(nsIDMapPath, nil)
	if err != nil {
		logger.GetLogger().Warn("Could not open nsid map", logfields.Error, err, "file", nsIDMapPath)
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
		localID uint64
		nsID    uint64
	}

	dstList := make(map[dstListKey][]*types.Destination)
	nsList := make(map[uint64][]*types.Destination)

	c := endpoint.MustGet()

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
			ip := networkapi.GetIP(dstVal.AddrCreate, ops.MSG_OP_UNDEF, dstVal.IPv6 != 0)
			// If the IP has resolved to a DNS or K8s object lets
			// omit the duplicate individual IP. This can happen
			// when the connect races with the watchers and/or DNS
			// handler.
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
				prefixLen := 32
				if addr.Is6() {
					prefixLen = 128
				}
				ep = endpoint.Endpoint{
					Type: tetragon.EndpointType_ENDPOINT_TYPE_IP,
					CIDR: netip.PrefixFrom(addr, prefixLen),
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

		stats := &types.DestinationStats{
			TxBytes:           dstVal.TxBytes,
			RxBytes:           dstVal.RxBytes,
			TxDrops:           dstVal.TxDrops,
			DefaultAllowBytes: dstVal.AllowDefaultBytes,
			DefaultDenyBytes:  dstVal.DenyDefaultBytes,
		}
		// Report quota-related stats if TxLimit is set.
		if dstVal.TxLimit != 0 {
			stats.TxLimit = dstVal.TxLimit
			stats.TxQuota = dstVal.TxQuota
			stats.KtimeLastReset = ktime.ToProto(dstVal.KtimeLastReset)
			lastReset := stats.KtimeLastReset.AsTime()
			stats.KtimeTxReset = timestamppb.New(lastReset.Add(time.Duration(dstVal.KtimeTxReset)))
		}

		if dstVal.Policy != 0 {
			policy, ok := library.GetRepository().GetName(dstVal.Policy)
			if !ok {
				logger.GetLogger().Warn("unknown policy id in process model", "policyID", dstVal.Policy)
			} else {
				stats.Policy = policy
			}

			denyDefault := dstVal.DenyDefaultBytes > 0
			allowDefault := dstVal.AllowDefaultBytes > 0
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
				DestinationNames: []string{},
				Port:             uint64(0),
				Stats:            stats,
			}
		case tetragon.EndpointType_ENDPOINT_TYPE_DNS:
			d = &types.Destination{
				DestinationNames: strings.Split(ep.Dns, ","),
				Port:             dstVal.Port,
				Stats:            stats,
			}
		case tetragon.EndpointType_ENDPOINT_TYPE_POD:
			d = &types.Destination{
				DestinationPod: &types.Pod{
					Namespace:    ep.Namespace,
					Workload:     ep.Name,
					WorkloadKind: ep.Kind,
				},
				Port:  dstVal.Port,
				Stats: stats,
			}
		case tetragon.EndpointType_ENDPOINT_TYPE_IP:
			d = &types.Destination{
				DestinationNames: []string{ep.CIDR.String()},
				Port:             dstVal.Port,
				Stats:            stats,
			}
		case tetragon.EndpointType_ENDPOINT_TYPE_SERVICE:
			d = &types.Destination{
				DestinationService: &types.Service{
					Namespace: ep.Namespace,
					Name:      ep.Name,
				},
				Port:  dstVal.Port,
				Stats: stats,
			}
		case tetragon.EndpointType_ENDPOINT_TYPE_LISTEN:
			d = &types.Destination{
				Port:  dstVal.Port,
				Stats: stats,
			}
		case tetragon.EndpointType_ENDPOINT_TYPE_BPF_DNS:
			d = &types.Destination{
				DestinationNames: []string{ep.Name},
				Port:             dstVal.Port,
				Stats:            stats,
			}
		case tetragon.EndpointType_ENDPOINT_TYPE_NODE:
			d = &types.Destination{
				DestinationNames: []string{ep.Name},
				Port:             dstVal.Port,
				Stats:            stats,
			}
		case tetragon.EndpointType_ENDPOINT_TYPE_CIDR:
			d = &types.Destination{
				DestinationNames: []string{ep.CIDR.String()},
				Port:             dstVal.Port,
				Stats:            stats,
			}
		}

		// If this is the Zero ProcessID and it has a NSId then its an
		// aggregated CgroupId destination.
		if dstKey.LocalId == 0 && dstKey.LocalNSId != 0 {
			cgid := dstKey.LocalNSId
			l, ok := nsList[cgid]
			if !ok {
				nsList[cgid] = []*types.Destination{d}
			} else {
				l := append(l, d)
				nsList[cgid] = l
			}
		} else {
			idKey := dstListKey{
				localID: dstKey.LocalId,
				nsID:    dstKey.LocalNSId,
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

		nsId, ok := workloadid.GetState().LookupMeta(workloadid.WorkloadID(ns))
		if ok {
			nsPath = nsId.Namespace
			wlPath = nsId.Workload
			kind = nsId.Kind
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
			},
			Dest: d,
		})
	}

	idKey := dstListKey{
		localID: 0,
		nsID:    0,
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

	type NSIDUpdate struct {
		oldValue types.ProcessTreeValue
		newNSID  uint64
	}
	pendingNSIDUpdates := make(map[types.ProcessTreeKey]NSIDUpdate)
	var skippedEntries int
	type binaryInfo struct {
		binary string
		args   string
	}
	binaryByUID := make(map[uint64]binaryInfo)

	type processEntry struct {
		key             types.ProcessTreeKey
		ns, wl          string
		kind            string
		selfBin         string
		selfArgs        string
		dest            []*types.Destination
		inInitTree      bool
		syscalls        set.Set[uint32]
		containerId     string
		cgroupid        uint64
		ktimeFirstExec  uint64
		ktimeLastExec   uint64
		ktimeLatestExit uint64
		execCount       uint64
	}

	// Pass 1: iterate the BPF map, collect per-entry state, and populate
	// binaryByUID so that parent resolution in pass 2 never misses.
	var procEntries []processEntry
	iter = m.Iterate()
	for iter.Next(&key, &val) {
		var ns, wl, kind string
		syscalls := set.NewSet[uint32]()

		// If EnableCgTrackerID is enabled, we need to find the cgroup tracker id for this cgroup id
		var cgroupid uint64

		if ossoption.Config.EnableCgTrackerID {
			err = cgTrackerMap.Lookup(&val.CgroupID, &cgroupid)
			if err != nil {
				// This can happen for host processes that are not in any cgroup
				logger.GetLogger().Debug("Failed to look up cgroup tracker id for process", logfields.Error, err, "cgroupid", val.CgroupID)
			}
		} else {
			cgroupid = val.CgroupID
		}

		if val.MaybeMissingNSID {
			var updatedNSID uint64
			if err := nsIDMap.Lookup(cgroupid, &updatedNSID); err != nil {
				logger.GetLogger().Debug("failed to look up nsid", logfields.Error, err, "cgid", cgroupid)
			} else {
				// Queue up a map update and fixup NSID value
				pendingNSIDUpdates[key] = NSIDUpdate{
					oldValue: val,
					newNSID:  updatedNSID,
				}
				key.NSID = updatedNSID
			}
		}

		policyFilterNSInfo, ok := workloadid.GetState().LookupMeta(workloadid.WorkloadID(key.NSID))
		if ok {
			ns = policyFilterNSInfo.Namespace
			wl = policyFilterNSInfo.Workload
			kind = policyFilterNSInfo.Kind
		} else {
			ns = model.HostNamespace
			wl = model.HostWorkload
			kind = model.HostKind
		}
		if len(namespaces) > 0 && !slices.Contains(namespaces, ns) {
			continue
		}

		// Read binary path and args directly from the embedded fields in process_tree_value.
		selfBin, selfArgs := decodeBinaryArgs(&val)
		// Binary is embedded at insertion time, so this is not expected
		// to be empty in practice. Guard defensively just in case.
		if selfBin == "" {
			logger.GetLogger().Debug("Empty binary in process tree entry", "uuid", key.Self)
			skippedEntries++
			continue
		}

		binaryByUID[key.Self] = binaryInfo{binary: selfBin, args: selfArgs}

		idKey := dstListKey{
			localID: key.Self,
			nsID:    key.NSID,
		}
		dest := dstList[idKey]
		inInitTree := val.InInitTree

		if option.Config.EnableSyscallTracking {
			err = sm.Lookup(&key.Self, &syscallVal)
			if err == nil {
				for i, mask := range syscallVal.Syscalls {
					for j := 0; j < 64; j++ {
						if mask&(uint64(1)<<j) != uint64(0) {
							id := i*64 + j
							syscalls.Insert(uint32(id))
						}
					}
				}
			} else {
				logger.GetLogger().Debug("Failed to look up system calls for process", logfields.Error, err, "key", key.Self)
			}
		}

		// Look up container information from cgroup id
		var containerId string

		if cgroupid != 0 {
			logger.GetLogger().Debug("Looking up container info", "binary", selfBin, "args", selfArgs, "cgroupid", cgroupid)
			cid, found := getContainerID(cgroupid)
			if found && cid != "" {
				logger.GetLogger().Debug("Found container info", "cgroupid", cgroupid, "containerID", cid)
				containerId = cid
			} else {
				// If the cgroup id is 0, it means the process is not in a container.
				logger.GetLogger().Debug("No container info found for process", "cgroupid", cgroupid)
			}
		}

		procEntries = append(procEntries, processEntry{
			key: key,
			ns:  ns, wl: wl, kind: kind,
			selfBin: selfBin, selfArgs: selfArgs,
			dest: dest, inInitTree: inInitTree,
			syscalls: syscalls, containerId: containerId,
			cgroupid:        cgroupid,
			ktimeFirstExec:  val.KtimeFirstExec,
			ktimeLastExec:   val.KtimeLastExec,
			ktimeLatestExit: val.KtimeLatestExit,
			execCount:       val.ExecCount,
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
			Namespace:  e.ns,
			Syscalls:   e.syscalls.AsSlice(),
			Abi:        abi,
			Workload: &types.Workload{
				Name: e.wl,
				Kind: e.kind,
			},
			ContainerId:     e.containerId,
			Dest:            e.dest,
			InInitTree:      e.inInitTree,
			FirstStartTime:  ktimeToTime(e.ktimeFirstExec),
			LatestStartTime: ktimeToTime(e.ktimeLastExec),
			LatestExitTime:  ktimeToTime(e.ktimeLatestExit),
			ExecCount:       e.execCount,
		})

		logger.GetLogger().Debug("Added process model", "process", *processModel[len(processModel)-1])
	}

	if skippedEntries > 0 {
		logger.GetLogger().Warn("Skipped process tree entries with missing binary info (LRU eviction)",
			"count", skippedEntries)
	}

	// Do queued NSID updates
	// TODO use batch operations here if supported
	for k, v := range pendingNSIDUpdates {
		// Delete the old entry
		m.Delete(&k)
		// Fix up new NSID and remove the flag
		k.NSID = v.newNSID
		v.oldValue.MaybeMissingNSID = false
		// Update process tree map with the new value
		if err := m.Update(&k, &v.oldValue, ebpf.UpdateAny); err != nil {
			logger.GetLogger().Debug("failed to update process tree map with corrected NSID", logfields.Error, err, "nsid", k.NSID, "uid", k.Self)
		}
	}
	clear(pendingNSIDUpdates)

	return processModel, nil
}

var ErrApplicationModelNotEnabled = errors.New("application model must be enabled with the --enable-application-model flag or the tetragon.enableApplicationModel Helm value")

func (s *Server) GetProcessModel(_ context.Context, ns []string, debug bool) ([]*types.ProcessModel, error) {
	if !option.Config.EnableApplicationModel {
		return nil, ErrApplicationModelNotEnabled
	}
	return GetProcessModel(ns, debug)
}

func (s *Server) GetApplicationModel(ctx context.Context, nsFilter map[string]bool) (*appModelV1.ApplicationModelEvent, error) {
	res, err := s.GetProcessModel(ctx, []string{}, false)
	if err != nil {
		logger.GetLogger().Error("Failed to get process model from Tetragon", logfields.Error, err)
		return nil, err
	}

	model := model.ProcessModelToApplicationModel(res, nsFilter)

	return model, nil
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
	lastModel := model.ProcessModelToApplicationModel(res, nsFilter)

	for {
		var networkDiffModel *appModelV1.ApplicationModel

		select {
		case <-ticker.C:
			res, err := s.GetProcessModel(ctx, []string{}, false)
			if err != nil {
				logger.GetLogger().Error("Failed to get process model from Tetragon", logfields.Error, err)
				return err
			}
			newModel := model.ProcessModelToApplicationModel(res, nsFilter)
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

			netFlatPack, err := diff.ApplicationModelToNetworkFlat(ctx, networkDiffModel)
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
		Enable:      option.Config.EnableApplicationModel,
		EnableBpfId: enableBpfId,
	}
	err := configureSettings(cfg)
	return &Server{}, err
}

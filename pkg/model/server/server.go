// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package server

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/cilium/cilium/pkg/container/set"
	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/api"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/ktime"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/process"
	"github.com/cilium/tetragon/pkg/syscallinfo"
	"github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	"github.com/isovalent/hubble-fgs/pkg/api/ops"
	"github.com/isovalent/hubble-fgs/pkg/dnsparser"
	"github.com/isovalent/hubble-fgs/pkg/endpoint"
	"github.com/isovalent/hubble-fgs/pkg/model"
	"github.com/isovalent/hubble-fgs/pkg/model/diff"
	"github.com/isovalent/hubble-fgs/pkg/model/types"
	"github.com/isovalent/hubble-fgs/pkg/netpol/library"
	"github.com/isovalent/hubble-fgs/pkg/option"
	appModelV1 "github.com/isovalent/ipa/application_model/v1alpha"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const (
	processTreeMap         = "process_tree_map"
	processTreeUUIDMap     = "process_tree_uid_binary_map"
	destinationEndpointMap = "destination_endpoint_map"
	listenEndpointMap      = "listen_endpoint_map"
	endpointIdMap          = "tg_endpoint_id_map"
	syscallMap             = "tg_syscall_map"
	nsIDMapName            = "tg_cgroup_namespace_map"
)

type Server struct {
	tetragon.UnimplementedProcessModelServiceServer
	appModelV1.UnimplementedApplicationModelServiceServer
}

func (s *Server) GetDestinationMap(_ context.Context, _ *tetragon.GetDestinationMapRequest) (*tetragon.GetDestinationMapResponse, error) {
	dests := make([]*tetragon.DestinationEndpointDebug, 0)
	destMap := filepath.Join(bpf.MapPrefixPath(), destinationEndpointMap)
	m, err := ebpf.LoadPinnedMap(destMap, nil)
	if err != nil {
		logger.GetLogger().WithError(err).WithField("file", destinationEndpointMap).Warn("Could not open destinationEndpointMap for GetDestinationMapRequest")
		return nil, err
	}
	defer m.Close()

	var (
		k types.DestinationEndpointKey
		v types.DestinationEndpointValue
	)

	iter := m.Iterate()
	for iter.Next(&k, &v) {
		title, _ := library.GetName(v.Policy)
		d := &tetragon.DestinationEndpointDebug{
			LocalId:           k.LocalId,
			LocalNsId:         k.LocalNSId,
			DestinationId:     k.DestinationId,
			DestinationSource: k.DestinationSource,
			DestinationPort:   k.DestinationPort,
			TxQuota:           v.TxQuota,
			TxLimit:           v.TxLimit,
			TxDrops:           v.TxDrops,
			DefaultAllowBytes: v.AllowDefault,
			DefaultDenyBytes:  v.DenyDefault,
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

	uuidMap := filepath.Join(bpf.MapPrefixPath(), processTreeUUIDMap)
	uuid, err := ebpf.LoadPinnedMap(uuidMap, nil)
	if err != nil {
		logger.GetLogger().WithError(err).WithField("file", uuid).Warn("Could not open processTreeUUID map for GetProcessMapRequest")
		return nil, err
	}
	defer uuid.Close()

	var (
		key   types.ProcessTreeBinaryUUIDKey
		value types.ProcessTreeBinaryUUIDValue
	)

	iter := uuid.Iterate()
	for iter.Next(&key, &value) {
		n := bytes.IndexByte(value.Binary[:], 0)
		selfStr := string(value.Binary[:n])
		m := bytes.Index(value.Args[:], []byte{0x00, 0x00})
		selfArgs := string(value.Args[:m])
		// Call ArgsDecoder to replace nulls with spaces. Specify api.EventNoCWDSupport
		// since args in process tree binary map does not contain CWD.
		selfArgs, _ = process.ArgsDecoder(selfArgs, api.EventNoCWDSupport)

		t := tetragon.ProcessUUID{
			Binary: selfStr,
			Args:   selfArgs,
			Id:     key.Id,
		}
		indexedUUID[uint64(key.Id)] = &t
	}

	treeMap := filepath.Join(bpf.MapPrefixPath(), processTreeMap)

	m, err := ebpf.LoadPinnedMap(treeMap, nil)
	if err != nil {
		logger.GetLogger().WithError(err).WithField("file", treeMap).Warn("Could not open process tree map")
		return nil, err
	}

	defer m.Close()

	var (
		keyTk types.ProcessTreeKey
		valTk types.ProcessTreeValue
	)

	iter = m.Iterate()
	for iter.Next(&keyTk, &valTk) {
		v := indexedUUID[keyTk.Self]
		value := tetragon.ProcessUUID{
			Binary:   v.Binary,
			Args:     v.Args,
			Id:       v.Id,
			Depth:    v.Depth,
			Children: v.Children,
		}
		children := make([]*tetragon.ProcessUUID, 0)

		for i := 0; i < 8; i++ {
			if keyTk.Path[i] == 0 {
				break
			}
			child := indexedUUID[keyTk.Path[i]]
			children = append(children, child)
		}
		value.Depth = uint32(keyTk.Depth)
		value.Children = children
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
		logger.GetLogger().WithError(err).Warn("failed to collect bpf DNS endpoints")
		// continue and at least collect other endpoints
	}

	endptIdMap := filepath.Join(bpf.MapPrefixPath(), endpointIdMap)
	endpt, err := ebpf.LoadPinnedMap(endptIdMap, nil)
	if err != nil {
		logger.GetLogger().WithError(err).WithField("file", endptIdMap).Warn("Could not open destination endpoint map for EndpointDebugReq")
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
			Ip:        e.Ip,
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

	listenMap := filepath.Join(bpf.MapPrefixPath(), listenEndpointMap)
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

func statsAdd(a, b *tetragon.DestinationStats) *tetragon.DestinationStats {
	quota := uint64(0)
	limit := uint64(0)
	var reset *timestamppb.Timestamp
	var txreset *timestamppb.Timestamp

	if a.TxLimit <= b.TxLimit {
		limit = a.TxLimit
		quota = a.TxQuota
		reset = a.KtimeLastReset
		txreset = a.KtimeTxReset
	} else if b.TxLimit < a.TxLimit {
		limit = b.TxLimit
		quota = b.TxQuota
		reset = b.KtimeLastReset
		txreset = b.KtimeTxReset
	}

	return &tetragon.DestinationStats{
		TxBytes:           a.TxBytes + b.TxBytes,
		RxBytes:           a.RxBytes + b.RxBytes,
		DefaultAllowBytes: a.DefaultAllowBytes + b.DefaultAllowBytes,
		DefaultDenyBytes:  a.DefaultDenyBytes + b.DefaultDenyBytes,
		TxDrops:           a.TxDrops + b.TxDrops,
		TxLimit:           limit,
		TxQuota:           quota,
		KtimeLastReset:    reset,
		KtimeTxReset:      txreset,
	}
}

func fqdnDestEqual(a, b *tetragon.Destination) bool {
	return a.DestinationPod == nil &&
		strings.Compare(strings.Join(a.DestinationNames, ","), strings.Join(b.DestinationNames, ",")) == 0 &&
		a.Port == b.Port
}

func podEqual(a, b *tetragon.Pod) bool {
	return strings.Compare(a.Name, b.Name) == 0 &&
		strings.Compare(a.Namespace, b.Namespace) == 0
}

func podDestEqual(a, b *tetragon.Destination) bool {
	return a.DestinationPod != nil && b.DestinationPod != nil && podEqual(a.DestinationPod, b.DestinationPod) && a.Port == b.Port
}

func destEqual(a, b *tetragon.Destination) bool {
	if fqdnDestEqual(a, b) {
		return true
	}
	if podDestEqual(a, b) {
		return true
	}
	return false
}

func GetProcessModel(namespaces []string, debug bool) (*tetragon.GetProcessModelResponse, error) {
	processModel := make([]*tetragon.ProcessModel, 0)
	treeMap := filepath.Join(bpf.MapPrefixPath(), processTreeMap)
	binaryFile := filepath.Join(bpf.MapPrefixPath(), processTreeUUIDMap)
	endptMap := filepath.Join(bpf.MapPrefixPath(), destinationEndpointMap)
	syscallMap := filepath.Join(bpf.MapPrefixPath(), syscallMap)
	nsIDMapPath := filepath.Join(bpf.MapPrefixPath(), nsIDMapName)

	endpt, err := ebpf.LoadPinnedMap(endptMap, nil)
	if err != nil {
		logger.GetLogger().WithError(err).WithField("file", endptMap).Warn("Could not open destination endpoint map")
		return nil, err
	}
	defer endpt.Close()

	nsIDMap, err := ebpf.LoadPinnedMap(nsIDMapPath, nil)
	if err != nil {
		logger.GetLogger().WithError(err).WithField("file", nsIDMapPath).Warn("Could not open nsid map")
		return nil, err
	}
	defer nsIDMap.Close()

	var dnsDomainMap dnsparser.DomainMap
	defer dnsDomainMap.CloseMaps()

	var (
		dstKey types.DestinationEndpointKey
		dstVal types.DestinationEndpointValue
	)

	dstList := make(map[uint64][]*tetragon.Destination)
	nsList := make(map[uint64][]*tetragon.Destination)

	c := endpoint.MustGet()

	iter := endpt.Iterate()
	for iter.Next(&dstKey, &dstVal) {
		var d *tetragon.Destination
		var ep endpoint.Endpoint

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
				ep = endpoint.Endpoint{
					Type: tetragon.EndpointType_ENDPOINT_TYPE_IP,
					Ip:   ip.String(),
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
				logger.GetLogger().WithField("id", dstKey.DestinationId).WithError(err).Warn("Could not retrieve BPF DNS parser domain info for Source User")
				continue
			}
			ep = endpoint.Endpoint{
				Type: tetragon.EndpointType_ENDPOINT_TYPE_DNS,
				Dns:  domain,
			}
		case types.DestinationSourceDNS:
			domain, err := dnsDomainMap.Domain(dstKey.DestinationId)
			if err != nil {
				logger.GetLogger().WithError(err).Warn("Could not retrieve BPF DNS parser domain info")
				continue
			}
			ep = endpoint.Endpoint{
				Type: tetragon.EndpointType_ENDPOINT_TYPE_DNS,
				Dns:  domain,
			}
		default:
			logger.GetLogger().WithError(err).Warn("unknown dstKey.DestinationSrc")
			continue
		}

		stats := &tetragon.DestinationStats{
			TxBytes:           dstVal.TxBytes,
			RxBytes:           dstVal.RxBytes,
			TxDrops:           dstVal.TxDrops,
			DefaultAllowBytes: dstVal.AllowDefault,
			DefaultDenyBytes:  dstVal.DenyDefault,
		}
		// Report quota-related stats if TxLimit is set.
		if dstVal.TxLimit != 0 {
			stats.TxLimit = dstVal.TxLimit
			stats.TxQuota = dstVal.TxQuota
			stats.KtimeLastReset = ktime.ToProto(dstVal.KtimeLastReset)
			lastReset := stats.KtimeLastReset.AsTime()
			stats.KtimeTxReset = timestamppb.New(lastReset.Add(time.Duration(dstVal.KtimeTxReset)))
		}

		switch ep.Type {
		case tetragon.EndpointType_ENDPOINT_TYPE_UNKNOWN:
			d = &tetragon.Destination{
				DestinationNames: []string{},
				Port:             uint64(0),
				Stats:            stats,
			}
		case tetragon.EndpointType_ENDPOINT_TYPE_DNS:
			d = &tetragon.Destination{
				DestinationNames: strings.Split(ep.Dns, ","),
				Port:             dstVal.Port,
				Stats:            stats,
			}
		case tetragon.EndpointType_ENDPOINT_TYPE_POD:
			d = &tetragon.Destination{
				DestinationPod: &tetragon.Pod{
					Namespace:    ep.Namespace,
					Workload:     ep.Name,
					WorkloadKind: ep.Kind,
				},
				Port:  dstVal.Port,
				Stats: stats,
			}
		case tetragon.EndpointType_ENDPOINT_TYPE_IP:
			d = &tetragon.Destination{
				DestinationNames: strings.Split(ep.Ip, ","),
				Port:             dstVal.Port,
				Stats:            stats,
			}
		case tetragon.EndpointType_ENDPOINT_TYPE_SERVICE:
			d = &tetragon.Destination{
				DestinationService: &tetragon.Service{
					Namespace: ep.Namespace,
					Name:      ep.Name,
				},
				Port:  dstVal.Port,
				Stats: stats,
			}
		case tetragon.EndpointType_ENDPOINT_TYPE_LISTEN:
			d = &tetragon.Destination{
				Port:  dstVal.Port,
				Stats: stats,
			}
		case tetragon.EndpointType_ENDPOINT_TYPE_BPF_DNS:
			d = &tetragon.Destination{
				DestinationNames: []string{ep.Name},
				Port:             dstVal.Port,
				Stats:            stats,
			}
		case tetragon.EndpointType_ENDPOINT_TYPE_NODE:
			d = &tetragon.Destination{
				DestinationNames: []string{ep.Name},
				Port:             dstVal.Port,
				Stats:            stats,
			}
		case tetragon.EndpointType_ENDPOINT_TYPE_CIDR:
			d = &tetragon.Destination{
				DestinationNames: []string{ep.Ip},
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
				nsList[cgid] = []*tetragon.Destination{d}
			} else {
				l := append(l, d)
				nsList[cgid] = l
			}
		} else {
			l, ok := dstList[dstKey.LocalId]
			if !ok {
				dstList[dstKey.LocalId] = []*tetragon.Destination{d}
			} else {
				skip := false

				for _, dedup := range l {
					if destEqual(dedup, d) {
						dedup.Stats = statsAdd(dedup.Stats, d.Stats)
						skip = true
						break
					}
				}
				if !skip {
					l = append(l, d)
				}
				dstList[dstKey.LocalId] = l
			}
		}
	}

	m, err := ebpf.LoadPinnedMap(treeMap, nil)
	if err != nil {
		logger.GetLogger().WithError(err).WithField("file", treeMap).Warn("Could not open process tree map")
		return nil, err
	}

	defer m.Close()

	var sm *ebpf.Map
	var abi string
	if option.Config.EnableSyscallTracking {
		abi, err = syscallinfo.DefaultABI()
		if err != nil {
			return nil, fmt.Errorf("unsupported ABI %q for syscall sensor: %w", abi, err)
		}

		sm, err = ebpf.LoadPinnedMap(syscallMap, nil)
		if err != nil {
			logger.GetLogger().WithError(err).WithField("file", syscallMap).Info("Could not open syscall map")
			return nil, err
		}

		defer sm.Close()
	}

	var (
		key        types.ProcessTreeKey
		val        types.ProcessTreeValue
		syscallVal types.ProcessSyscallValue
	)

	uidMap, err := ebpf.LoadPinnedMap(binaryFile, nil)
	if err != nil {
		logger.GetLogger().WithError(err).WithField("file", binaryFile).Warn("Could not open UUID to Binary tree map")
		return nil, err
	}
	defer uidMap.Close()

	state, err := policyfilter.GetState()
	if err != nil {
		logger.GetLogger().WithError(err).Warn("Could not get policyfilter state")
		return nil, err
	}

	/* Build out Branches for workloads */
	for ns, d := range nsList {
		var nsPath, wlPath, kind string

		nsId, ok := state.GetNsId(policyfilter.StateID(ns))
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

		processModel = append(processModel, &tetragon.ProcessModel{
			Binary:    "",
			Parent:    "",
			Namespace: nsPath,
			Workload: &tetragon.Workload{
				Name: wlPath,
				Kind: kind,
			},
			Dest: d,
		})
	}

	// Build process independent destination totals for host; these use
	// the defined id 0. If the model is qualified by namespace ignore
	// these host destinations.
	if len(dstList[0]) != 0 && len(namespaces) == 0 {
		processModel = append(processModel, &tetragon.ProcessModel{
			Binary:    "",
			Parent:    "",
			Namespace: "",
			Dest:      dstList[0],
			Workload:  &tetragon.Workload{},
		})
	}

	type NSIDUpdate struct {
		oldValue types.ProcessTreeValue
		newNSID  uint64
	}
	pendingNSIDUpdates := make(map[types.ProcessTreeKey]NSIDUpdate)
	iter = m.Iterate()
	for iter.Next(&key, &val) {
		var ns, wl, kind string
		syscalls := set.NewSet[uint32]()

		if val.MaybeMissingNSID {
			var updatedNSID uint64
			if err := nsIDMap.Lookup(&val.CgroupID, &updatedNSID); err != nil {
				logger.GetLogger().WithError(err).WithField("cgid", val.CgroupID).Debug("failed to look up nsid")
			} else {
				// Queue up a map update and fixup NSID value
				pendingNSIDUpdates[key] = NSIDUpdate{
					oldValue: val,
					newNSID:  updatedNSID,
				}
				key.NSID = updatedNSID
			}
		}

		policyFilterNSInfo, ok := state.GetNsId(policyfilter.StateID(key.NSID))
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

		var (
			processKey types.ProcessTreeBinaryUUIDKey
			uidValue   types.ProcessTreeBinaryUUIDValue
		)

		processKey.Id = key.Self
		err := uidMap.Lookup(&processKey, &uidValue)
		if err != nil {
			logger.GetLogger().WithFields(logrus.Fields{
				"uuid": processKey,
			}).WithError(err).Warn("Could not map self UUID to Path")
			continue
		}
		// uidValue.Binary is a fixed size byte array. Trim trailing null bytes.
		n := bytes.IndexByte(uidValue.Binary[:], 0)
		selfStr := string(uidValue.Binary[:n])
		m := bytes.Index(uidValue.Args[:], []byte{0x00, 0x00})
		selfArgs := string(uidValue.Args[:m])
		// Call ArgsDecoder to replace nulls with spaces. Specify api.EventNoCWDSupport
		// since args in process tree binary map does not contain CWD.
		selfArgs, _ = process.ArgsDecoder(selfArgs, api.EventNoCWDSupport)

		parentPath := ""
		parentArgs := ""
		if key.Depth > 0 {
			parent := uint32(key.Path[key.Depth-1])
			err = uidMap.Lookup(&parent, &uidValue)
			if err == nil {
				n = bytes.IndexByte(uidValue.Binary[:], 0)
				parentPath = string(uidValue.Binary[:n])
				m := bytes.Index(uidValue.Args[:], []byte{0x00, 0x00})
				parentArgs = string(uidValue.Args[:m])
				// Call ArgsDecoder to replace nulls with spaces. Specify api.EventNoCWDSupport
				// since args in process tree binary map does not contain CWD.
				parentArgs, _ = process.ArgsDecoder(parentArgs, api.EventNoCWDSupport)
			}
		}

		dest := dstList[key.Self]

		var inInitTree *wrapperspb.BoolValue
		if val.InContainer {
			inInitTree = &wrapperspb.BoolValue{Value: val.InInitTree}
		}

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
				logger.GetLogger().WithError(err).WithField("key", key.Self).Debugf("Failed to look up system calls for process")
			}
		}

		processModel = append(processModel, &tetragon.ProcessModel{
			Binary:     selfStr,
			BinaryArgs: selfArgs,
			Parent:     parentPath,
			ParentArgs: parentArgs,
			Namespace:  ns,
			Syscalls:   syscalls.AsSlice(),
			Abi:        abi,
			Workload: &tetragon.Workload{
				Name: wl,
				Kind: kind,
			},
			Dest:       dest,
			InInitTree: inInitTree,
		})
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
			logger.GetLogger().WithError(err).WithField("nsid", k.NSID).WithField("uid", k.Self).Debug("failed to update process tree map with corrected NSID")
		}
	}
	clear(pendingNSIDUpdates)

	return &tetragon.GetProcessModelResponse{
		Processes: processModel,
	}, nil
}

func (s *Server) GetProcessModel(_ context.Context, req *tetragon.GetProcessModelRequest) (*tetragon.GetProcessModelResponse, error) {
	if !option.Config.EnableApplicationModel {
		return nil, fmt.Errorf("application model must be enabled with the --enable-application-model flag or the tetragon.enableApplicationModel Helm value")
	}
	namespaces := req.GetNamespaces()
	return GetProcessModel(namespaces, req.GetDebug())
}

func (s *Server) GetProcesses(req *tetragon.GetProcessModelRequest, stream tetragon.ProcessModelService_GetProcessesServer) error {
	res, err := s.GetProcessModel(stream.Context(), req)
	if err != nil {
		return err
	}
	for _, proc := range res.GetProcesses() {
		if err := stream.Send(proc); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) GetModel(ctx context.Context, req *appModelV1.GetModelRequest) (*appModelV1.GetModelResponse, error) {
	res, err := s.GetProcessModel(ctx, &tetragon.GetProcessModelRequest{})
	if err != nil {
		logger.GetLogger().WithError(err).Error("Failed to get process model from Tetragon")
		return nil, err
	}
	nsFilter := make(map[string]bool, 0)
	for _, f := range req.Namespaces {
		nsFilter[f] = true
	}
	model := model.ProcessModelToApplicationModel(res, nsFilter)
	return &appModelV1.GetModelResponse{
		Model: model,
	}, nil
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

	res, err := s.GetProcessModel(ctx, &tetragon.GetProcessModelRequest{})
	if err != nil {
		logger.GetLogger().WithError(err).Error("Failed to get process model from Tetragon")
		return err
	}
	lastModel := model.ProcessModelToApplicationModel(res, nsFilter)

	for {
		var diffModel *appModelV1.ApplicationModel

		select {
		case <-ticker.C:
			res, err := s.GetProcessModel(ctx, &tetragon.GetProcessModelRequest{})
			if err != nil {
				logger.GetLogger().WithError(err).Error("Failed to get process model from Tetragon")
				return err
			}
			newModel := model.ProcessModelToApplicationModel(res, nsFilter)
			diffModel, err = diff.ApplicationModelDiff(newModel.ApplicationModel, lastModel.ApplicationModel)
			if err != nil {
				logger.GetLogger().WithError(err).Error("Failed to produce application model difference")
				return err
			}

			// If nothing has changed do not update last model and skip writing empty record
			if diffModel == nil {
				continue
			}
			lastModel = newModel

			netFlatPack, err := diff.ApplicationModelToNetworkFlat(diffModel)
			if err != nil {
				logger.GetLogger().WithError(err).Error("Failed to decode application model to network event model")
				return err
			}
			for _, entry := range netFlatPack {
				network := &appModelV1.StreamTelemetryResponse_Network{
					Network: entry,
				}
				send := appModelV1.StreamTelemetryResponse{
					Event: network,
				}
				if err := stream.Send(&send); err != nil {
					logger.GetLogger().WithError(err).Error("Failed to send network event model")
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

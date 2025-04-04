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
	"github.com/isovalent/hubble-fgs/pkg/model/types"
	"github.com/isovalent/hubble-fgs/pkg/option"
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
)

type Server struct {
	tetragon.UnimplementedProcessModelServiceServer
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
		d := &tetragon.DestinationEndpointDebug{
			LocalId:           k.LocalId,
			LocalNsId:         k.LocalNSId,
			DestinationId:     k.DestinationId,
			DestinationSource: k.DestinationSource,
			DestinationPort:   k.DestinationPort,
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
		id := key.ID
		v := &tetragon.Endpoint{
			Key:  id,
			Type: tetragon.EndpointType_BpfDnsType,
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
			Type: tetragon.EndpointType_ListenType,
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

func GetProcessModel(namespaces []string, debug bool) (*tetragon.GetProcessModelResponse, error) {
	processModel := make([]*tetragon.ProcessModel, 0)
	treeMap := filepath.Join(bpf.MapPrefixPath(), processTreeMap)
	binaryFile := filepath.Join(bpf.MapPrefixPath(), processTreeUUIDMap)
	endptMap := filepath.Join(bpf.MapPrefixPath(), destinationEndpointMap)
	syscallMap := filepath.Join(bpf.MapPrefixPath(), syscallMap)

	endpt, err := ebpf.LoadPinnedMap(endptMap, nil)
	if err != nil {
		logger.GetLogger().WithError(err).WithField("file", endptMap).Warn("Could not open destination endpoint map")
		return nil, err
	}
	defer endpt.Close()

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
				if ep.Type == endpoint.DnsType && debug {
					ep.Dns = ep.Dns + "<promoted>"
				}

			} else {
				ep = endpoint.Endpoint{
					Type: endpoint.IpType,
					Ip:   ip.String(),
				}
			}
		case types.DestinationSourceUser:
			var ok bool

			ep, ok = c.LookupID(dstKey.DestinationId)
			if !ok {
				continue
			}
		case types.DestinationSourceDNS:
			domain, err := dnsDomainMap.Domain(dstKey.DestinationId)
			if err != nil {
				logger.GetLogger().WithError(err).Warn("Could not retrieve BPF DNS parser domain info")
				continue
			}
			ep = endpoint.Endpoint{
				Type: endpoint.DnsType,
				Dns:  domain,
			}
		default:
			logger.GetLogger().WithError(err).Warn("unknown dstKey.DestinationSrc")
			continue
		}

		stats := &tetragon.DestinationStats{
			TxBytes: dstVal.TxBytes,
			RxBytes: dstVal.RxBytes,
			TxDrops: dstVal.TxDrops,
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
		case endpoint.DnsType:
			d = &tetragon.Destination{
				DestinationNames: strings.Split(ep.Dns, ","),
				Port:             dstVal.Port,
				Stats:            stats,
			}
		case endpoint.ServiceType:
			d = &tetragon.Destination{
				DestinationService: &tetragon.Service{
					Namespace: ep.Namespace,
					Name:      ep.Name,
				},
				Port:  dstVal.Port,
				Stats: stats,
			}
		case endpoint.PodType:
			d = &tetragon.Destination{
				DestinationPod: &tetragon.Pod{
					Namespace:    ep.Namespace,
					Workload:     ep.Name,
					WorkloadKind: ep.Kind,
				},
				Port:  dstVal.Port,
				Stats: stats,
			}
		case endpoint.IpType:
			d = &tetragon.Destination{
				DestinationNames: strings.Split(ep.Ip, ","),
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
					if dedup.DestinationPod == nil &&
						strings.Compare(strings.Join(dedup.DestinationNames, ","), strings.Join(d.DestinationNames, ",")) == 0 &&
						dedup.Port == d.Port {
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

	iter = m.Iterate()
	for iter.Next(&key, &val) {
		var ns, wl, kind string
		syscalls := set.NewSet[uint32]()

		nsId, ok := state.GetNsId(policyfilter.StateID(key.CgroupId))
		if ok {
			ns = nsId.Namespace
			wl = nsId.Workload
			kind = nsId.Kind
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
			logger.GetLogger().WithError(err).Warn("Could not map self UUID to Path")
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
	return &tetragon.GetProcessModelResponse{
		Processes: processModel,
	}, nil
}

func (s *Server) GetProcessModel(_ context.Context, req *tetragon.GetProcessModelRequest) (*tetragon.GetProcessModelResponse, error) {
	if !option.Config.EnableProcessTree {
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

func DefaultNewServer() (*Server, error) {
	dfltBpfId := true
	return NewServer(dfltBpfId)
}

func NewServer(enableBpfId bool) (*Server, error) {
	cfg := &CfgProcessModel{
		Enable:      option.Config.EnableProcessTree,
		EnableBpfId: enableBpfId,
	}
	err := configureSettings(cfg)
	return &Server{}, err
}

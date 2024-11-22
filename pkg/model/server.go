// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package model

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/ktime"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	"github.com/isovalent/hubble-fgs/pkg/api/ops"
	"github.com/isovalent/hubble-fgs/pkg/endpoint"
	"github.com/isovalent/hubble-fgs/pkg/option"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	processTreeMap         = "process_tree_map"
	processTreeUUIDMap     = "process_tree_uid_binary_map"
	destinationEndpointMap = "destination_endpoint_map"
	HostNamespace          = "<host-namespace>"
	HostWorkload           = "<host-workload>"
	WorkloadDestinations   = "<wl-destinations>"
	HostKind               = "<host-kind>"
)

type binary struct {
	Path [256]byte
}

type ProcessExecveKey struct {
	Pid   uint32
	Pad   uint32
	Ktime uint64
}

type ProcessTreeKey struct {
	CgroupId uint64
	Self     ProcessExecveKey
	Parent   ProcessExecveKey
}

type processTreeValue struct {
	KtimeFirstExec uint64
	KtimeLastExec  uint64
}

const (
	DestinationSourceUknown = 0
	DestinationSourceBpf    = 1
	DestinationSourceUser   = 2
)

type DestinationEndpointKey struct {
	ProcessId         ProcessTreeKey
	DestinationId     uint64
	DestinationSource uint64
	DestinationPort   uint64
}

type DestinationEndpointValue struct {
	TxQuota        uint64
	TxLimit        uint64
	TxDrops        uint64
	KtimeLastReset uint64
	KtimeTxReset   uint64
	TxBytes        uint64
	RxBytes        uint64
	Pad0           uint64
	IPv6           uint64
	KtimeCreate    uint64
	AddrCreate     [2]uint64
	Port           uint64
}

type Server struct {
}

func (s *Server) GetEndpointMap(_ context.Context, _ *tetragon.GetEndpointMapRequest) (*tetragon.GetEndpointMapResponse, error) {
	c := endpoint.Get()
	keys, endpoints := c.DebugEndpointMap()
	tetragonEndpoints := make([]*tetragon.Endpoint, 0)

	for i, e := range endpoints {
		v := &tetragon.Endpoint{
			Key:       keys[i],
			Type:      tetragon.EndpointType(e.Type),
			Dns:       e.Dns,
			Kind:      e.Kind,
			Namespace: e.Namespace,
			Name:      e.Name,
			Ip:        e.Ip,
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

func (s *Server) GetProcessModel(_ context.Context, req *tetragon.GetProcessModelRequest) (*tetragon.GetProcessModelResponse, error) {
	if !option.Config.EnableProcessTree {
		return nil, fmt.Errorf("process tree must be enabled with the --enable-process-tree flag or the tetragon.enableProcessTree Helm value")
	}
	model := make([]*tetragon.ProcessModel, 0)
	treeMap := filepath.Join(bpf.MapPrefixPath(), processTreeMap)
	binaryFile := filepath.Join(bpf.MapPrefixPath(), processTreeUUIDMap)
	endptMap := filepath.Join(bpf.MapPrefixPath(), destinationEndpointMap)
	namespaces := req.GetNamespaces()

	endpt, err := ebpf.LoadPinnedMap(endptMap, nil)
	if err != nil {
		logger.GetLogger().WithError(err).WithField("file", endptMap).Warn("Could not open destination endpoint map")
		return nil, err
	}
	defer endpt.Close()

	var (
		dstKey DestinationEndpointKey
		dstVal DestinationEndpointValue
	)

	dstList := make(map[ProcessTreeKey][]*tetragon.Destination)
	nsList := make(map[uint64][]*tetragon.Destination)

	c := endpoint.Get()

	iter := endpt.Iterate()
	for iter.Next(&dstKey, &dstVal) {
		var d *tetragon.Destination
		var ep endpoint.Endpoint

		if dstKey.DestinationSource == DestinationSourceBpf {
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
				if ep.Type == endpoint.DnsType && req.GetDebug() {
					ep.Dns = ep.Dns + "<promoted>"
				}

			} else {
				ep = endpoint.Endpoint{
					Type: endpoint.IpType,
					Ip:   ip.String(),
				}
			}
		} else if dstKey.DestinationSource == DestinationSourceUser {
			var ok bool

			ep, ok = c.LookupID(dstKey.DestinationId)
			if !ok {
				continue
			}
		} else {
			logger.GetLogger().WithError(err).Warn("unknown dstKey.DestinationSrc")
			continue
		}

		stats := &tetragon.DestinationStats{
			TxBytes: dstVal.TxBytes,
			RxBytes: dstVal.RxBytes,
		}
		// Report quota-related stats if TxLimit is set.
		if dstVal.TxLimit != 0 {
			stats.TxDrops = dstVal.TxDrops
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

		// If this is the Zero ProcessID then its an aggregated CgroupId
		// destination. Log separately so we can entry for these.
		if dstKey.ProcessId.Self.Pid == 0 {
			cgid := dstKey.ProcessId.CgroupId
			l, ok := nsList[cgid]
			if !ok {
				nsList[cgid] = []*tetragon.Destination{d}
			} else {
				l := append(l, d)
				nsList[cgid] = l
			}
		}

		l, ok := dstList[dstKey.ProcessId]
		if !ok {
			dstList[dstKey.ProcessId] = []*tetragon.Destination{d}
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
			dstList[dstKey.ProcessId] = l
		}
	}

	m, err := ebpf.LoadPinnedMap(treeMap, nil)
	if err != nil {
		logger.GetLogger().WithError(err).WithField("file", treeMap).Warn("Could not open process tree map")
		return nil, err
	}

	defer m.Close()

	var (
		key ProcessTreeKey
		val processTreeValue
	)

	uidMap, err := ebpf.LoadPinnedMap(binaryFile, nil)
	if err != nil {
		logger.GetLogger().WithError(err).WithField("file", binaryFile).Warn("Could not open UUID to Binary tree map")
		return nil, err
	}
	defer uidMap.Close()
	var (
		uidValue binary
	)

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
			nsPath = HostNamespace
			wlPath = HostWorkload
			kind = HostKind
		}
		if len(namespaces) > 0 && !slices.Contains(namespaces, nsPath) {
			continue
		}

		model = append(model, &tetragon.ProcessModel{
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

	iter = m.Iterate()
	for iter.Next(&key, &val) {
		var ns, wl, kind string

		nsId, ok := state.GetNsId(policyfilter.StateID(key.CgroupId))
		if ok {
			ns = nsId.Namespace
			wl = nsId.Workload
			kind = nsId.Kind
		} else {
			ns = HostNamespace
			wl = HostWorkload
			kind = HostKind
		}
		if len(namespaces) > 0 && !slices.Contains(namespaces, ns) {
			continue
		}

		err := uidMap.Lookup(&key.Self, &uidValue)
		if err != nil {
			logger.GetLogger().WithError(err).Warn("Could not map self UUID to Path")
			continue
		}
		// uidValue.Path is a fixed size byte array. Trim trailing null bytes.
		n := bytes.IndexByte(uidValue.Path[:], 0)
		selfStr := fmt.Sprintf("%s", uidValue.Path[:n])

		parentPath := ""
		err = uidMap.Lookup(&key.Parent, &uidValue)
		if err == nil {
			n = bytes.IndexByte(uidValue.Path[:], 0)
			parentPath = fmt.Sprintf("%s", uidValue.Path[:n])
		}

		var dest []*tetragon.Destination
		dest = dstList[key]

		model = append(model, &tetragon.ProcessModel{
			Binary:    selfStr,
			Parent:    parentPath,
			Namespace: ns,
			Workload: &tetragon.Workload{
				Name: wl,
				Kind: kind,
			},
			Dest: dest,
		})
	}
	return &tetragon.GetProcessModelResponse{
		Processes: model,
	}, nil
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

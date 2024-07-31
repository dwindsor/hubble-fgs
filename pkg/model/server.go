// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package model

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/isovalent/hubble-fgs/pkg/endpoint"
	"github.com/isovalent/hubble-fgs/pkg/option"

	"github.com/cilium/tetragon/api/v1/tetragon"
)

const (
	processTreeMap         = "process_tree_map"
	processTreeUUIDMap     = "process_tree_uid_binary_map"
	destinationEndpointMap = "destination_endpoint_map"
)

type binary struct {
	Length int64
	Path   [256]byte
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
	KtimeCreate    uint64
	AddrCreate     [16]byte
	Port           uint64
	TxQuota        uint64
	TxLimit        uint64
	KtimeLastReset uint64
	KtimeTxReset   uint64
	TxBytes        uint64
	RxBytes        uint64
}

type Server struct {
}

func (s *Server) GetProcessModel(_ context.Context, _ *tetragon.GetProcessModelRequest) (*tetragon.GetProcessModelResponse, error) {
	model := make([]*tetragon.ProcessModel, 0)
	treeMap := filepath.Join(bpf.MapPrefixPath(), processTreeMap)
	binaryFile := filepath.Join(bpf.MapPrefixPath(), processTreeUUIDMap)
	endptMap := filepath.Join(bpf.MapPrefixPath(), destinationEndpointMap)

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
			ip := make(net.IP, 4)
			ip[0] = dstVal.AddrCreate[0]
			ip[1] = dstVal.AddrCreate[1]
			ip[2] = dstVal.AddrCreate[2]
			ip[3] = dstVal.AddrCreate[3]

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

		switch ep.Type {
		case endpoint.DnsType:
			d = &tetragon.Destination{
				DestinationNames: strings.Split(ep.Dns, ","),
				Port:             dstVal.Port,
				Stats: &tetragon.DestinationStats{
					TxBytes: dstVal.TxBytes,
					RxBytes: dstVal.RxBytes,
				},
			}
		case endpoint.PodType:
			d = &tetragon.Destination{
				DestinationPod: &tetragon.Pod{
					Namespace:    ep.Namespace,
					Workload:     ep.Name,
					WorkloadKind: ep.Kind,
				},
				Port: dstVal.Port,
				Stats: &tetragon.DestinationStats{
					TxBytes: dstVal.TxBytes,
					RxBytes: dstVal.RxBytes,
				},
			}
		case endpoint.IpType:
			d = &tetragon.Destination{
				DestinationNames: strings.Split(ep.Ip, ","),
				Port:             dstVal.Port,
				Stats: &tetragon.DestinationStats{
					TxBytes: dstVal.TxBytes,
					RxBytes: dstVal.RxBytes,
				},
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
			nsPath = "<host-namespace>"
			wlPath = "<host-workload>"
			kind = "<host-kind>"
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
			ns = "<host-namespace>"
			wl = "<host-workload>"
			kind = "<host-kind>"
		}

		err := uidMap.Lookup(&key.Self, &uidValue)
		if err != nil {
			logger.GetLogger().WithError(err).Warn("Could not map self UUID to Path")
			continue
		}
		selfStr := fmt.Sprintf("%s", uidValue.Path)

		parentPath := ""
		err = uidMap.Lookup(&key.Parent, &uidValue)
		if err == nil {
			parentPath = fmt.Sprintf("%s", uidValue.Path)
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

func AddDnsQuota(namespace, wl, kind string, dns []string, quota string) error {
	ep := endpoint.Endpoint{
		Type: endpoint.DnsType,
		Dns:  strings.Join(dns, ","),
	}

	c := endpoint.Get()
	dstId, err := c.AddEndpoint(ep)
	if err != nil {
		logger.GetLogger().WithError(err).Warn("Failed to add endpoint for quota")
		return err
	}

	file := filepath.Join(bpf.MapPrefixPath(), destinationEndpointMap)
	dstMap, err := ebpf.LoadPinnedMap(file, nil)
	if err != nil {
		logger.GetLogger().WithError(err).WithField("file", file).Warn("Could not open map")
		return err
	}
	defer dstMap.Close()

	var nsId policyfilter.StateID
	if namespace != "" {
		var ok bool

		workload := policyfilter.NSID{
			Namespace: namespace,
			Workload:  wl,
			Kind:      kind,
		}

		state, err := policyfilter.GetState()
		if err != nil {
			logger.GetLogger().WithError(err).Warn("Unable to get policyfilter")
			return nil
		}
		nsId, ok = state.GetIdNs(workload)
		if !ok {
			logger.GetLogger().WithField("namespace", namespace).WithField("workload", wl).Info("workload does not exist.")
			return nil
		}
	} else {
		nsId = policyfilter.StateID(0)
	}

	processId := ProcessTreeKey{
		CgroupId: uint64(nsId),
		Self: ProcessExecveKey{
			Pid:   0,
			Pad:   0,
			Ktime: 0,
		},
		Parent: ProcessExecveKey{
			Pid:   0,
			Pad:   0,
			Ktime: 0,
		},
	}

	key := &DestinationEndpointKey{
		ProcessId:         processId,
		DestinationId:     dstId,
		DestinationSource: DestinationSourceUser,
		DestinationPort:   0,
	}

	var addr [16]byte
	quotaBytes, err := strconv.ParseUint(quota, 10, 64)
	if err != nil {
		return err
	}

	value := &DestinationEndpointValue{
		KtimeCreate: 0,
		AddrCreate:  addr,
		Port:        0,
		TxQuota:     0,
		TxLimit:     quotaBytes,
		TxBytes:     0,
		RxBytes:     0,
	}

	if err := dstMap.Update(key, value, 0); err != nil {
		return err
	}
	return nil
}

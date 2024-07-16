// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package model

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/isovalent/hubble-fgs/pkg/endpoint"

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

type processExecveKey struct {
	Pid   uint32
	Pad   uint32
	Ktime uint64
}

type processTreeKey struct {
	CgroupId uint64
	Self     processExecveKey
	Parent   processExecveKey
}

type processTreeValue struct {
	KtimeFirstExec uint64
	KtimeLastExec  uint64
}

type destinationEndpointKey struct {
	ProcessId     processTreeKey
	DestinationId uint64
}

type destinationEndpointValue struct {
	KtimeCreate uint64
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
		dstKey destinationEndpointKey
		dstVal destinationEndpointValue
	)

	dstList := make(map[processTreeKey][]*tetragon.Destination)
	c := endpoint.Get()

	iter := endpt.Iterate()
	for iter.Next(&dstKey, &dstVal) {
		var d *tetragon.Destination

		ep, ok := c.LookupID(dstKey.DestinationId)
		if !ok {
			continue
		}

		switch ep.Type {
		case endpoint.DnsType:
			d = &tetragon.Destination{
				DestinationNames: strings.Split(ep.Dns, ","),
			}
		case endpoint.PodType:
			d = &tetragon.Destination{
				DestinationPod: &tetragon.Pod{
					Namespace:    ep.Namespace,
					Workload:     ep.Name,
					WorkloadKind: ep.Kind,
				},
			}
		}

		l, ok := dstList[dstKey.ProcessId]
		if !ok {
			dstList[dstKey.ProcessId] = []*tetragon.Destination{d}
		} else {
			l = append(l, d)
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
		key processTreeKey
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

func NewServer() *Server {
	return &Server{}
}

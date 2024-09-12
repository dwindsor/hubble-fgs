// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package model

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/isovalent/hubble-fgs/pkg/endpoint"
	"github.com/isovalent/hubble-fgs/pkg/option"
	"github.com/sirupsen/logrus"

	"github.com/cilium/tetragon/api/v1/tetragon"
)

const (
	processTreeMap         = "process_tree_map"
	processTreeUUIDMap     = "process_tree_uid_binary_map"
	destinationEndpointMap = "destination_endpoint_map"
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
	Pad1           uint64
	KtimeCreate    uint64
	AddrCreate     [16]byte
	Port           uint64
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
				if ep.Type == endpoint.DnsType {
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
			TxDrops: dstVal.TxDrops,
			TxLimit: dstVal.TxLimit,
		}

		switch ep.Type {
		case endpoint.DnsType:
			d = &tetragon.Destination{
				DestinationNames: strings.Split(ep.Dns, ","),
				Port:             dstVal.Port,
				Stats:            stats,
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

func quotaToNs(reset string) (uint64, error) {
	var mult uint64

	specifier := reset[len(reset)-1:]
	if specifier == "m" {
		mult = 60000000000
	} else if specifier == "h" {
		mult = 3600000000000
	} else if specifier == "s" {
		mult = 1000000000
	} else {
		return 0, fmt.Errorf("unknown reset specifier %s", specifier)
	}
	time := reset[0 : len(reset)-1]
	resetNS, err := strconv.ParseUint(time, 10, 64)
	if err != nil {
		return 0, err
	}
	resetNS *= mult
	return resetNS, nil
}

// This is a somewhat lossy operation the BPF side may lose some stats during
// the update. However, this is a heavy operation to remove a quotas so we
// accept it.
func ClearDnsQuota() error {
	var dstVal DestinationEndpointValue
	var dstKey DestinationEndpointKey

	file := filepath.Join(bpf.MapPrefixPath(), destinationEndpointMap)
	dstMap, err := ebpf.LoadPinnedMap(file, nil)
	if err != nil {
		logger.GetLogger().WithError(err).WithField("file", file).Warn("Could not open destination endpoint map")
		return err
	}
	defer dstMap.Close()

	iter := dstMap.Iterate()
	for iter.Next(&dstKey, &dstVal) {
		if dstVal.TxLimit == 0 {
			continue
		}

		dstVal.TxLimit = 0

		if err := dstMap.Update(dstKey, dstVal, 0); err != nil {
			return err
		}
	}
	return nil
}

type quotaPolicy struct {
	dns   []string
	quota string
	reset string
}

var (
	queueWl     = make(map[policyfilter.NSID]quotaPolicy)
	queueWlLock = sync.Mutex{}
)

func queueWorkloadQuotaPolicy(wl policyfilter.NSID, dns []string, reset, quota string) {
	qp := quotaPolicy{
		dns:   dns,
		quota: quota,
		reset: reset,
	}

	queueWlLock.Lock()
	queueWl[wl] = qp
	queueWlLock.Unlock()
}

func CheckWorkloadQuotaPolicy(epPod *v1alpha1.PodInfo) error {
	wl := policyfilter.NSID{
		Kind:      epPod.WorkloadType.Kind,
		Namespace: epPod.WorkloadObject.Namespace,
		Workload:  epPod.WorkloadObject.Name,
	}

	queueWlLock.Lock()
	qp, ok := queueWl[wl]
	if !ok {
		queueWlLock.Unlock()
		return nil
	}
	delete(queueWl, wl)
	queueWlLock.Unlock()
	return AddDnsQuota(wl.Namespace, wl.Workload, wl.Kind, qp.dns, qp.quota, qp.reset)
}

func addSingleDnsQuota(src *ProcessTreeKey, ep *endpoint.Endpoint, dstMap *ebpf.Map, quota, reset uint64) error {
	var addr [16]byte

	c := endpoint.Get()
	dst, err := c.AddEndpoint(*ep)
	if err != nil {
		logger.GetLogger().WithError(err).Warn("Failed to add endpoint for quota")
		return err
	}
	key := &DestinationEndpointKey{
		ProcessId:         *src,
		DestinationId:     dst,
		DestinationSource: DestinationSourceUser,
		DestinationPort:   0,
	}

	value := &DestinationEndpointValue{
		TxQuota:        0,
		TxLimit:        quota,
		TxDrops:        0,
		KtimeLastReset: 0,
		KtimeTxReset:   reset,
		TxBytes:        0,
		RxBytes:        0,
		Pad0:           0,
		Pad1:           0,
		KtimeCreate:    0,
		AddrCreate:     addr,
		Port:           0,
	}

	if err := dstMap.Update(key, value, 0); err != nil {
		return err
	}

	return nil
}

func createSrcKey(namespace, wl, kind string) (*ProcessTreeKey, error) {
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
			return nil, err
		}
		// If the ID does not yet exist we need to wait for it to be added. This is
		// an imperfect solution. Ideally we would just modify the policyfilter state
		// to preallocate an ID.But, its in OSS and not obvious how to extend it to
		// support this.
		nsId, ok = state.GetIdNs(workload)
		if !ok {
			logger.GetLogger().WithField("namespace", namespace).WithField("workload", wl).Info("workload info does not exist yet, queuing for workload updates.")
			return nil, nil
		}
	} else {
		nsId = policyfilter.StateID(0)
	}

	return &ProcessTreeKey{
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
	}, nil
}

func AddDnsQuota(namespace, wl, kind string, dns []string, quota, reset string) error {
	file := filepath.Join(bpf.MapPrefixPath(), destinationEndpointMap)
	dstMap, err := ebpf.LoadPinnedMap(file, nil)
	if err != nil {
		logger.GetLogger().WithError(err).WithField("file", file).Warn("Could not open map")
		return err
	}

	defer dstMap.Close()
	src, err := createSrcKey(namespace, wl, kind)
	if err != nil {
		return err
	}

	// If the src does not yet exist we watch for it and create the policy
	// once an ID has been generated.
	if src == nil {
		workload := policyfilter.NSID{
			Namespace: namespace,
			Workload:  wl,
			Kind:      kind,
		}
		queueWorkloadQuotaPolicy(workload, dns, reset, quota)
		return nil
	}

	resetNS, err := quotaToNs(reset)
	if err != nil {
		logger.GetLogger().WithError(err).Warn("failed to conver reset time")
		return err
	}

	quotaBytes, err := strconv.ParseUint(quota, 10, 64)
	if err != nil {
		return err
	}

	for _, entry := range dns {
		ep := &endpoint.Endpoint{
			Type: endpoint.DnsType,
			Dns:  entry,
		}

		if err := addSingleDnsQuota(src, ep, dstMap, quotaBytes, resetNS); err != nil {
			logger.GetLogger().WithFields(logrus.Fields{
				"namespace": namespace,
				"workload":  wl,
				"quota":     quotaBytes,
				"reset":     reset,
				"dest":      entry,
			}).Warn("TCP quota entry Failed")
		}
	}
	logger.GetLogger().WithFields(logrus.Fields{
		"namespace": namespace,
		"workload":  wl,
		"quota":     quotaBytes,
		"reset":     reset,
		"dest":      strings.Join(dns, " "),
	}).Info("TCP quota added")
	return nil
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon
package dns

import (
	"fmt"
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
	"github.com/sirupsen/logrus"

	model "github.com/isovalent/hubble-fgs/pkg/model/server"
)

type quotaPolicy struct {
	dns   []string
	quota string
	reset string
}

var (
	queueWl     = make(map[policyfilter.NSID]quotaPolicy)
	queueWlLock = sync.Mutex{}
)

const (
	destinationEndpointMap = "destination_endpoint_map"
)

func addSingleDnsQuota(src *model.ProcessTreeKey, ep *endpoint.Endpoint, dstMap *ebpf.Map, quota, reset uint64) error {
	var addr [2]uint64

	c := endpoint.Get()
	dst, err := c.AddEndpoint(*ep)
	if err != nil {
		logger.GetLogger().WithError(err).Warn("Failed to add endpoint for quota")
		return err
	}
	key := &model.DestinationEndpointKey{
		LocalId:           src.Self,
		DestinationId:     dst,
		DestinationSource: model.DestinationSourceUser,
		DestinationPort:   0,
	}

	value := &model.DestinationEndpointValue{
		TxQuota:        0,
		TxLimit:        quota,
		TxDrops:        0,
		KtimeLastReset: 0,
		KtimeTxReset:   reset,
		TxBytes:        0,
		RxBytes:        0,
		Pad0:           0,
		IPv6:           0,
		KtimeCreate:    0,
		AddrCreate:     addr,
		Port:           0,
	}

	if err := dstMap.Update(key, value, 0); err != nil {
		return err
	}

	return nil
}

func QueueWorkloadQuotaPolicy(wl policyfilter.NSID, dns []string, reset, quota string) {
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
		/* Check for Namespace policy */
		nswl := policyfilter.NSID{
			Namespace: wl.Namespace,
			Kind:      "",
			Workload:  "",
		}
		qp, ok = queueWl[nswl]
		if !ok {
			queueWlLock.Unlock()
			return nil
		}
	} else {
		delete(queueWl, wl)
	}
	queueWlLock.Unlock()
	return AddDnsQuota(wl.Namespace, wl.Workload, wl.Kind, qp.dns, qp.quota, qp.reset)
}

func createSrcKey(namespace, wl, kind string) (*model.ProcessTreeKey, error) {
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

	return &model.ProcessTreeKey{
		CgroupId: uint64(nsId),
		Depth:    0,
		Self:     0,
		Path:     [8]uint64{0, 0, 0, 0, 0, 0, 0, 0},
	}, nil
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

func AddDnsQuota(namespace, wl, kind string, dns []string, quota, reset string) error {
	file := filepath.Join(bpf.MapPrefixPath(), destinationEndpointMap)
	dstMap, err := ebpf.LoadPinnedMap(file, nil)
	if err != nil {
		logger.GetLogger().WithError(err).WithField("file", file).Warn("Could not open map")
		return err
	}

	defer dstMap.Close()
	// The wl="",kind="" case will fall throuh to queueWorkloadQuotaPolicy
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
		QueueWorkloadQuotaPolicy(workload, dns, reset, quota)
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

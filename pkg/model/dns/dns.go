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

	"github.com/isovalent/hubble-fgs/pkg/model/types"
)

var (
	queueWl     = make(map[types.TetragonNetworkSubject]*types.TetragonNetworkPolicy)
	queueWlLock = sync.Mutex{}

	// QuotasDNSDomainMappings stores the mappings between the domain and
	// their ID generated after parsing a quota policy.
	QuotasDNSDomainMappings = map[endpoint.Endpoint]uint64{}
)

const (
	destinationEndpointMap = "destination_endpoint_map"
)

func addSingleDnsPolicy(src *types.ProcessTreeKey, ep *endpoint.Endpoint, dstMap *ebpf.Map, quota, reset, deny uint64) error {
	var addr [2]uint64

	c := endpoint.Get()
	dst, err := c.AddEndpoint(*ep)
	if err != nil {
		logger.GetLogger().WithError(err).Warn("Failed to add endpoint for quota")
		return err
	}

	// This configuration for the DNS domain maps will be written at load time
	QuotasDNSDomainMappings[*ep] = dst

	key := &types.DestinationEndpointKey{
		LocalId:           src.Self,
		DestinationId:     dst,
		DestinationSource: types.DestinationSourceUser,
		DestinationPort:   0,
	}

	value := &types.DestinationEndpointValue{
		TxQuota:        0,
		TxLimit:        quota,
		TxDrops:        0,
		TxDeny:         deny,
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

func queueWorkloadNetworkPolicy(policy *types.TetragonNetworkPolicy) {
	queueWl[policy.Subject] = policy
}

func QueueWorkloadNetworkPolicy(policy *types.TetragonNetworkPolicy) {
	queueWlLock.Lock()
	queueWorkloadNetworkPolicy(policy)
	queueWlLock.Unlock()
}

func CheckWorkloadQuotaPolicy(epPod *v1alpha1.PodInfo) error {
	subject := types.TetragonNetworkSubject{
		Namespace: epPod.WorkloadObject.Namespace,
		Workload:  epPod.WorkloadObject.Name,
		Kind:      epPod.WorkloadType.Kind,
	}

	queueWlLock.Lock()
	policy, ok := queueWl[subject]
	if !ok {
		/* Check for Namespace policy */
		namespaceSubject := types.TetragonNetworkSubject{
			Namespace: subject.Namespace,
			Kind:      "",
			Workload:  "",
		}
		policy, ok = queueWl[namespaceSubject]
		if !ok {
			queueWlLock.Unlock()
			return nil
		}
	} else {
		delete(queueWl, subject)
	}
	queueWlLock.Unlock()
	return AddNetworkPolicy(policy)
}

func createSrcPolicy(policy *types.TetragonNetworkPolicy) (*types.ProcessTreeKey, error) {
	queueWlLock.Lock()
	defer queueWlLock.Unlock()

	s := &policy.Subject

	src, err := createSrcKey(s.Namespace, s.Workload, s.Kind)
	if err != nil {
		return nil, err
	}

	// If the src does not yet exist we watch for it and create the policy
	// once an ID has been generated.
	if src == nil {
		queueWorkloadNetworkPolicy(policy)
		return nil, nil
	}
	return src, nil
}

func createSrcKey(namespace, wl, kind string) (*types.ProcessTreeKey, error) {
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

	return &types.ProcessTreeKey{
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

func AddNetworkPolicy(policy *types.TetragonNetworkPolicy) error {
	file := filepath.Join(bpf.MapPrefixPath(), destinationEndpointMap)
	dstMap, err := ebpf.LoadPinnedMap(file, nil)
	if err != nil {
		logger.GetLogger().WithError(err).WithField("file", file).Warn("Could not open map")
		return err
	}

	defer dstMap.Close()

	s := &policy.Subject
	d := &policy.Destination
	a := &policy.Action

	// The wl="",kind="" case will fall throuh to queueWorkloadQuotaPolicy
	src, err := createSrcPolicy(policy)
	if err != nil {
		return err
	}
	if src == nil {
		return nil
	}

	resetNS := uint64(0)
	quotaBytes := uint64(0)

	if a.QuotaAction != nil {
		resetNS, err = quotaToNs(a.QuotaAction.Reset)
		if err != nil {
			logger.GetLogger().WithError(err).Warn("failed to conver reset time")
			return err
		}

		quotaBytes, err = strconv.ParseUint(a.QuotaAction.Quota, 10, 64)
		if err != nil {
			return err
		}
	}

	denyVal := uint64(0)
	if a.EnforceAction != nil && a.EnforceAction.Deny {
		denyVal = uint64(1)
	}

	for _, entry := range d.Names {
		ep := &endpoint.Endpoint{
			Type: endpoint.DnsType,
			Dns:  entry,
		}
		if err := addSingleDnsPolicy(src, ep, dstMap, quotaBytes, resetNS, denyVal); err != nil {
			logger.GetLogger().WithFields(logrus.Fields{
				"namespace": s.Namespace,
				"workload":  s.Workload,
				"quota":     quotaBytes,
				"reset":     a.QuotaAction,
				"deny":      denyVal,
				"dest":      entry,
			}).WithError(err).Error("TCP quota entry Failed")
		}
	}
	logger.GetLogger().WithFields(logrus.Fields{
		"namespace": s.Namespace,
		"workload":  s.Workload,
		"quota":     quotaBytes,
		"reset":     a.QuotaAction,
		"dest":      strings.Join(d.Names, " "),
	}).Info("TCP quota added")
	return nil
}

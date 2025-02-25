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
	"github.com/isovalent/hubble-fgs/pkg/dnsparser"
	"github.com/isovalent/hubble-fgs/pkg/endpoint"
	"github.com/sirupsen/logrus"

	"github.com/isovalent/hubble-fgs/pkg/model/matchLabels"
	"github.com/isovalent/hubble-fgs/pkg/model/types"
)

var (
	queueWl     = make(map[types.TetragonWorkloadNetworkSubject]*types.TetragonNetworkPolicy)
	queueWlLock = sync.Mutex{}

	// Global Match Label policy
	matchLabelPolicy     matchLabels.PolicyList = make(map[string]*matchLabels.LabelSet)
	queueMatchLabelsLock                        = sync.Mutex{}

	// QuotasDNSDomainMappings stores the mappings between the domain and
	// their ID generated after parsing a quota policy. So that we can
	// initialize them once the TCP, UDP, and DNS sensors are online.
	QuotasInitDNSDomainMappings = map[endpoint.Endpoint]uint64{}

	// dnsDomainMap is used to bring DNS/ID mappings up to date at runtime.
	dnsDomainMap = dnsparser.DomainMap{}
)

const (
	destinationEndpointMap = "destination_endpoint_map"
)

func addSingleDnsPolicy(src *types.ProcessTreeKey, ep *endpoint.Endpoint, dstMap *ebpf.Map, quota, reset, deny uint64, init bool) error {
	var addr [2]uint64

	c := endpoint.Get()
	dst, err := c.AddEndpoint(*ep)
	if err != nil {
		logger.GetLogger().WithError(err).Warn("Failed to add endpoint for quota")
		return err
	}

	// A rather annoying ordering problem occurs where we are consuming
	// quota DNS policy through TCP policy and that may or may not have
	// initialized the DNS/UDP sensors yet. If DNS is not yet initialized
	// we need to wait until it comes up. So we check init state. And
	// if this update is through a path already fully initialized we
	// add it directly to the map otherwise we do a bulk update in init
	// path.
	if init {
		if err := dnsDomainMap.Update(ep.Dns, dst); err != nil {
			return fmt.Errorf("failed to write BPF domain maps: %w", err)
		}
	} else {
		QuotasInitDNSDomainMappings[*ep] = dst
	}

	key := &types.DestinationEndpointKey{
		LocalId:           src.Self,
		LocalNSId:         src.CgroupId,
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

func delSingleDnsPolicy(src *types.ProcessTreeKey, ep *endpoint.Endpoint, dstMap *ebpf.Map) error {
	var addr [2]uint64

	c := endpoint.Get()
	dst, err := c.AddEndpoint(*ep)
	if err != nil {
		logger.GetLogger().WithError(err).Warn("Failed to add endpoint for quota")
		return err
	}

	// On delete leave dnsDomainMap!

	// Ideally we would keep all the values here and just update the TxDeny, TxQuota and
	// TxLimit fields. Unfortunately its hard to do a partial update without doing multiple
	// reads. So for now zero entry, but keep the key/value in the map its not obvious
	// to me that we need to move it given the connection is likely still around.
	key := &types.DestinationEndpointKey{
		LocalId:           src.Self,
		LocalNSId:         src.CgroupId,
		DestinationId:     dst,
		DestinationSource: types.DestinationSourceUser,
		DestinationPort:   0,
	}

	value := &types.DestinationEndpointValue{
		TxQuota:        0,
		TxLimit:        0,
		TxDrops:        0,
		TxDeny:         0,
		KtimeLastReset: 0,
		KtimeTxReset:   0,
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
	queueWl[policy.Subject.Workload] = policy
}

func QueueWorkloadNetworkPolicy(policy *types.TetragonNetworkPolicy) {
	queueWlLock.Lock()
	queueWorkloadNetworkPolicy(policy)
	queueWlLock.Unlock()
}

func checkWorkloadQuotaPolicy(epPod *v1alpha1.PodInfo) error {
	subject := types.TetragonWorkloadNetworkSubject{
		Namespace: epPod.WorkloadObject.Namespace,
		Name:      epPod.WorkloadObject.Name,
		Kind:      epPod.WorkloadType.Kind,
	}

	queueWlLock.Lock()
	policy, ok := queueWl[subject]
	if !ok {
		/* Check for Namespace policy */
		namespaceSubject := types.TetragonWorkloadNetworkSubject{
			Namespace: subject.Namespace,
			Kind:      "",
			Name:      "",
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
	return AddNetworkPolicy(policy, true)
}

func checkMatchLabelsPolicy(epPod *v1alpha1.PodInfo) error {
	ml := &matchLabels.LabelSet{
		Label: epPod.ObjectMeta.Labels,
	}

	s := matchLabelPolicy.MergedCollection(ml)
	if s == nil {
		return fmt.Errorf("no merged policy applies")
	}

	ns := epPod.WorkloadObject.Namespace
	name := epPod.WorkloadObject.Name
	kind := epPod.WorkloadType.Kind

	src, err := createSrcKey(ns, name, kind)
	if err != nil {
		return err
	}
	if err := addNetworkPolicy(src, &s.Policy.Action, &s.Policy.Destination, true); err != nil {
		return err
	}
	return nil
}

func CheckPodAdd(epPod *v1alpha1.PodInfo) error {
	if err := checkWorkloadQuotaPolicy(epPod); err != nil {
		return err
	}
	if err := checkMatchLabelsPolicy(epPod); err != nil {
		return err
	}
	return nil
}

func createMatchLabelsPolicy(uid string, policy *types.TetragonNetworkPolicy) error {
	queueMatchLabelsLock.Lock()
	defer queueMatchLabelsLock.Unlock()

	ls := &matchLabels.LabelSet{
		Label:  policy.Subject.MatchLabelsEqual,
		Policy: policy,
	}

	matchLabelPolicy.Add(uid, ls)
	return nil
}

func createSrcPolicy(policy *types.TetragonNetworkPolicy) (*types.ProcessTreeKey, error) {
	queueWlLock.Lock()
	defer queueWlLock.Unlock()

	s := &policy.Subject.Workload

	src, err := createSrcKey(s.Namespace, s.Name, s.Kind)
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

func AddMatchLabelNetworkPolicy(uid string, policy *types.TetragonNetworkPolicy) error {
	return createMatchLabelsPolicy(uid, policy)
}

func addNetworkPolicy(src *types.ProcessTreeKey,
	a *types.TetragonNetworkAction,
	d *types.TetragonNetworkDestination,
	init bool) error {
	quotaBytes := uint64(0)
	resetNS := uint64(0)
	var err error

	file := filepath.Join(bpf.MapPrefixPath(), destinationEndpointMap)
	dstMap, err := ebpf.LoadPinnedMap(file, nil)
	if err != nil {
		logger.GetLogger().WithError(err).WithField("file", file).Warn("Could not open map")
		return err
	}

	defer dstMap.Close()

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
		if err := addSingleDnsPolicy(src, ep, dstMap, quotaBytes, resetNS, denyVal, init); err != nil {
			logger.GetLogger().WithFields(logrus.Fields{
				"cgid":  src.CgroupId,
				"self":  src.Self,
				"quota": quotaBytes,
				"reset": a.QuotaAction,
				"deny":  denyVal,
				"dest":  entry,
			}).WithError(err).Error("TCP quota entry Failed")
		}
	}
	logger.GetLogger().WithFields(logrus.Fields{
		"cgid":  src.CgroupId,
		"self":  src.Self,
		"quota": quotaBytes,
		"reset": a.QuotaAction,
		"dest":  strings.Join(d.Names, " "),
	}).Info("TCP quota added")
	return nil
}

func AddNetworkPolicy(policy *types.TetragonNetworkPolicy, init bool) error {

	d := &policy.Destination
	a := &policy.Action
	// The matchLabels case and wl="",kind="" case will fall throuh to queueWorkloadQuotaPolicy
	src, err := createSrcPolicy(policy)
	if err != nil {
		return err
	}
	if src == nil {
		return nil
	}

	return addNetworkPolicy(src, a, d, init)
}

func removeNetworkPolicy(src *types.ProcessTreeKey, d *types.TetragonNetworkDestination) error {
	var err error

	file := filepath.Join(bpf.MapPrefixPath(), destinationEndpointMap)
	dstMap, err := ebpf.LoadPinnedMap(file, nil)
	if err != nil {
		logger.GetLogger().WithError(err).WithField("file", file).Warn("Could not open map")
		return err
	}
	defer dstMap.Close()

	for _, entry := range d.Names {
		ep := &endpoint.Endpoint{
			Type: endpoint.DnsType,
			Dns:  entry,
		}
		if err := delSingleDnsPolicy(src, ep, dstMap); err != nil {
			logger.GetLogger().WithFields(logrus.Fields{
				"cgid":  src.CgroupId,
				"self":  src.Self,
				"dest":  entry,
			}).WithError(err).Error("TCP quota remove Failed")
		}
	}
	logger.GetLogger().WithFields(logrus.Fields{
		"cgid":  src.CgroupId,
		"self":  src.Self,
		"dest":  strings.Join(d.Names, " "),
	}).Info("TCP quota removed")
	return nil

}

func RemoveNetworkPolicy(_ string, policy *types.TetragonNetworkPolicy) error {
	queueWlLock.Lock()
	defer queueWlLock.Unlock()

	s := &policy.Subject.Workload
	d := &policy.Destination

	delete(queueWl, policy.Subject.Workload)

	src, err := createSrcKey(s.Namespace, s.Name, s.Kind)
	if err != nil {
		// Remove should not throw an error if the policy doesn't exist
		return nil
	}
	if src == nil {
		return nil
	}

	return removeNetworkPolicy(src, d)
}

func RemoveMatchLabelNetworkPolicy(name string, policy *types.TetragonNetworkPolicy) error {
	return nil
}

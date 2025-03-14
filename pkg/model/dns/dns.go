// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon
package dns

import (
	"fmt"
	"sync"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/isovalent/hubble-fgs/pkg/dnsparser"
	"github.com/isovalent/hubble-fgs/pkg/endpoint"

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

	// Programmer for BPF dataplane
	prog DatapathInterface = &BpfProgrammer{}
)

const (
	destinationEndpointMap = "destination_endpoint_map"
)

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
	if err := prog.AddNetworkPolicy(src, &s.Policy.Action, &s.Policy.Destination, true); err != nil {
		return err
	}
	matchLabelPolicy.AddPod(s.Name, epPod)
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
			logger.GetLogger().WithField("namespace", namespace).WithField("workload", wl).Debug("workload info does not exist yet, queuing for workload updates.")
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

func AddMatchLabelNetworkPolicy(uid string, policy *types.TetragonNetworkPolicy) error {
	return createMatchLabelsPolicy(uid, policy)
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

	return prog.AddNetworkPolicy(src, a, d, init)
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

	return prog.RemoveNetworkPolicy(src, d)
}

func RemoveMatchLabelNetworkPolicy(name string, policy *types.TetragonNetworkPolicy) error {
	queueMatchLabelsLock.Lock()
	defer queueMatchLabelsLock.Unlock()

	p, ok := matchLabelPolicy[name]
	if !ok {
		return fmt.Errorf("Could not find policy %s", name)
	}
	matchLabelPolicy.Remove(name)

	for _, epPod := range p.EPPods {
		// This is going to try and update the pod to the next
		// highest priority matching policy. If no such policy
		// exists we drop all policy from the pod.
		if err := checkMatchLabelsPolicy(epPod); err != nil {
			ns := epPod.WorkloadObject.Namespace
			podName := epPod.WorkloadObject.Name
			podKind := epPod.WorkloadType.Kind

			src, err := createSrcKey(ns, podName, podKind)
			if err != nil {
				continue
			}

			prog.RemoveNetworkPolicy(src, &policy.Destination)
			continue
		}
	}
	return nil
}

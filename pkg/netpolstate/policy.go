// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

//go:build !nok8s

package netpolstate

import (
	"fmt"
	"maps"
	"net/netip"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"

	"github.com/isovalent/hubble-fgs/pkg/endpoint"
	"github.com/isovalent/hubble-fgs/pkg/model/matchLabels"
	"github.com/isovalent/hubble-fgs/pkg/model/record"
	"github.com/isovalent/hubble-fgs/pkg/model/types"
	"github.com/isovalent/hubble-fgs/pkg/netpol/servicemap"
	"github.com/isovalent/hubble-fgs/pkg/workloadid"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (state *PolicyState) recordsFromPolicyRemoval(policy *types.TetragonNetworkPolicy) ([]record.DatapathRecord, []record.DatapathRecord, error) {
	subject := state.src[policy.PolicyUID]

	var beforeSubjs []record.DatapathRecord
	var afterSubjs []record.DatapathRecord

	subjectLabels := &matchLabels.LabelSet{
		Labels: policy.Subject.Labels.Equal,
		Policy: policy,
	}

	if subject != nil {
		for _, s := range subject.Subjects {
			records := state.srcAdd(s, subjectLabels, false)
			beforeSubjs = append(beforeSubjs, records...)
		}
	}

	// Generate removal records for serviceSelector policies
	if policy.Destination.ServiceRef != nil {
		for _, obj := range state.localObjects {
			podInfo, ok := obj.(*v1alpha1.PodInfo)
			if !ok {
				continue
			}
			// Generate the same records that CreateServiceSelectorRecords would create
			// so they can be removed
			svcSelRecords, err := state.createServiceSelectorRecordsForPolicy(podInfo, policy)
			if err != nil {
				logger.GetLogger().Warn("Failed to generate serviceSelector removal records", logfields.Error, err)
				continue
			}
			beforeSubjs = append(beforeSubjs, svcSelRecords...)
		}
		// Remove from serviceSelPolicies list
		state.removeServiceSelectorPolicy(policy.PolicyUID)
	}

	state.src.Remove(policy.PolicyUID)
	state.dst.Remove(policy.PolicyUID)

	for _, v := range state.src {
		if v == nil {
			continue
		}
		for _, src := range v.Subjects {
			sRecords, err := state.AddSrcPolicy(src, v.Policy, true)
			if err != nil {
				logger.GetLogger().Warn("AddSrcPolicy error", logfields.Error, err, "src", src)
				continue
			}
			afterSubjs = append(afterSubjs, sRecords...)
		}
	}

	// A key that exists only in the before list can be deleted because
	// nothing is referencing that key anymore. And the after list can
	// be used to update existing rules to their new state.
	zombieSet := record.Diff(beforeSubjs, afterSubjs)
	return zombieSet, afterSubjs, nil
}

func (state *PolicyState) diffExistingRecords(set []record.DatapathRecord) ([]record.DatapathRecord, error) {
	_, existingRecords, err := state.getRecords(state.getAllExistingPolicy())
	if err != nil {
		return nil, fmt.Errorf("failed to get existing records: %w", err)
	}

	return record.Diff(set, existingRecords), nil
}

func (state *PolicyState) RemovePolicy(policy *types.TetragonNetworkPolicy) error {
	state.mu.Lock()
	zombieSet, updateSet, err := state.recordsFromPolicyRemoval(policy)
	if err != nil {
		state.mu.Unlock()
		return err
	}

	// We should avoid trying to add records that are already programmed
	updateSet, err = state.diffExistingRecords(updateSet)
	state.mu.Unlock()
	if err != nil {
		return fmt.Errorf("failed to diff existing records: %w", err)
	}

	// Necessary order to ensure any updates to records are in place before we
	// remove stale records.
	err = state.deps.prog.AddRecords(updateSet, true)
	if err != nil {
		return fmt.Errorf("failed to add records: %w", err)
	}
	err = state.deps.prog.RemoveRecords(zombieSet)
	if err != nil {
		return fmt.Errorf("failed to remove records: %w", err)
	}
	return nil
}

func (deps externalDeps) createSrcKey(namespace, wl, kind string) (*types.ProcessTreeKey, error) {
	var wlid workloadid.WorkloadID
	if namespace != "" {
		var ok bool

		workload := workloadid.WorkloadKey{
			Namespace: namespace,
			Workload:  wl,
			Kind:      kind,
		}

		// If the ID does not yet exist we need to wait for it to be added. This is
		// an imperfect solution. Ideally we would just modify the policyfilter state
		// to preallocate an ID.But, its in OSS and not obvious how to extend it to
		// support this.
		wlid, ok = deps.workloadID.LookupID(workload)
		if !ok {
			logger.GetLogger().Debug("workload info does not exist yet, queuing for workload updates.", "namespace", namespace, "workload", wl)
			return nil, nil
		}
	} else {
		wlid = workloadid.WorkloadID(0)
	}

	return &types.ProcessTreeKey{
		WLID:  uint64(wlid),
		Depth: 0,
		Self:  0,
		Path:  [8]uint64{0, 0, 0, 0, 0, 0, 0, 0},
	}, nil
}

func (state *PolicyState) policyDestRecords(src *types.ProcessTreeKey, action *record.DatapathAction, policy *types.TetragonNetworkPolicy, init bool) []record.DatapathRecord {
	records := []record.DatapathRecord{}

	if policy.Destination.CIDR.IsValid() {
		r, err := addDestSrcCIDRRecords(policy.PolicyUID, &policy.Destination, src, action, init)
		if err != nil {
			logger.GetLogger().Warn("CIDR policy record error", logfields.Error, err, "CIDR", policy.Destination.CIDR)
		}
		records = append(records, r...)
	}

	if policy.Destination.FQDN != nil {
		for _, entry := range policy.Destination.FQDN.Names {
			if len(policy.Destination.Ports) == 0 {
				ep := &endpoint.Endpoint{
					Type: tetragon.EndpointType_ENDPOINT_TYPE_DNS,
					Dns:  entry,
				}
				endpoint := record.DatapathEndpoint{
					EP:   ep,
					Port: 0,
				}
				records = append(records, record.DatapathRecord{
					PolicyUID: policy.PolicyUID,
					Src:       src,
					Endpoint:  endpoint,
					Action:    action,
					Init:      init,
				})
			}

			for _, port := range policy.Destination.Ports {
				ep := &endpoint.Endpoint{
					Type: tetragon.EndpointType_ENDPOINT_TYPE_DNS,
					Dns:  entry,
				}
				endpoint := record.DatapathEndpoint{
					EP:   ep,
					Port: port,
				}
				records = append(records, record.DatapathRecord{
					PolicyUID: policy.PolicyUID,
					Src:       src,
					Endpoint:  endpoint,
					Action:    action,
					Init:      init,
				})
			}
		}
	}

	ls := state.dst[policy.PolicyUID]
	if ls != nil {
		for _, ep := range ls.Endpoints {
			if len(ls.Policy.Destination.Ports) == 0 {
				endpoint := record.DatapathEndpoint{
					EP:   ep,
					Port: 0,
				}

				records = append(records, record.DatapathRecord{
					PolicyUID: policy.PolicyUID,
					Src:       src,
					Endpoint:  endpoint,
					Action:    action,
					Init:      init,
				})
			}
			for _, port := range ls.Policy.Destination.Ports {
				endpoint := record.DatapathEndpoint{
					EP:   ep,
					Port: port,
				}

				records = append(records, record.DatapathRecord{
					PolicyUID: policy.PolicyUID,
					Src:       src,
					Endpoint:  endpoint,
					Action:    action,
					Init:      init,
				})
			}
		}
	}
	return records
}

// Create DstMatchLAbelsPolicy to add new Network Policy
func (state *PolicyState) createDstMatchLabelsPolicy(policy *types.TetragonNetworkPolicy) {
	if len(policy.Destination.Labels.Equal) < 1 {
		return
	}

	ls := &matchLabels.LabelSet{
		Labels: policy.Destination.Labels.Equal,
		Policy: policy,
		Ports:  policy.Destination.Ports,
	}

	state.dst.Add(ls)
}

// Create SrcMatchLAbelsPolicy to add new Network Policy
func (state *PolicyState) createSrcMatchLabelsPolicy(policy *types.TetragonNetworkPolicy) {
	ls := &matchLabels.LabelSet{
		Labels: policy.Subject.Labels.Equal,
		Policy: policy,
	}

	state.src.Add(ls)
}

func (state *PolicyState) createMatchLabelsPolicy(policy *types.TetragonNetworkPolicy) error {
	if len(policy.Destination.Labels.Equal) > 0 {
		state.createDstMatchLabelsPolicy(policy)
	}

	// Store serviceSelector policies for deferred record creation
	if policy.Destination.ServiceRef != nil {
		state.addServiceSelectorPolicy(policy)
	}

	// There are a few possibilities for possible scope.
	// 0. MatchLabels is set then we use this otherwise,
	// 1. fully specified namespace:workload:kind
	// 2. namespace scoped policy e.g. just namespace
	// 3. host scope, no namespace
	if len(policy.Subject.Labels.Equal) > 0 {
		state.createSrcMatchLabelsPolicy(policy)
	}

	return nil
}

// addServiceSelectorPolicy stores a policy with serviceSelector destination
func (state *PolicyState) addServiceSelectorPolicy(policy *types.TetragonNetworkPolicy) {
	state.serviceSelPolicies[policy.PolicyUID] = policy
}

// getServiceSelectorPolicies returns policies matching the given pod labels
func (state *PolicyState) getServiceSelectorPolicies(podLabels map[string]string) []*types.TetragonNetworkPolicy {
	var matching []*types.TetragonNetworkPolicy
	for _, policy := range state.serviceSelPolicies {
		if matchLabelsSubset(policy.Subject.Labels.Equal, podLabels) {
			matching = append(matching, policy)
		}
	}
	return matching
}

// matchLabelsSubset checks if all policy labels are present in pod labels
func matchLabelsSubset(policyLabels, podLabels map[string]string) bool {
	for k, v := range policyLabels {
		if podLabels[k] != v {
			return false
		}
	}
	return true
}

// removeServiceSelectorPolicy removes a policy from the serviceSelPolicies map
func (state *PolicyState) removeServiceSelectorPolicy(policyUID types.TetragonPolicyUniqueID) {
	delete(state.serviceSelPolicies, policyUID)
}

// createServiceSelectorRecordsForPolicy generates records for a specific serviceSelector policy
// and pod. This is the core helper used by both CreateServiceSelectorRecords and policy removal.
func (state *PolicyState) createServiceSelectorRecordsForPolicy(podInfo *v1alpha1.PodInfo, policy *types.TetragonNetworkPolicy) ([]record.DatapathRecord, error) {
	var records []record.DatapathRecord

	// Check if pod matches policy subject labels
	if !matchLabelsSubset(policy.Subject.Labels.Equal, state.deps.mergeNamespaceLabels(podInfo)) {
		return records, nil
	}

	src, err := state.deps.createSrcKey(podInfo.WorkloadObject.Namespace, podInfo.WorkloadObject.Name, podInfo.WorkloadType.Kind)
	if err != nil || src == nil {
		return records, err
	}

	return state.generateServiceSelectorRecords(src, policy)
}

// generateServiceSelectorRecords generates CIDR records for a serviceSelector policy.
// CIDR records are created for the Service ClusterIP and all endpoint IPs to block
// both direct ClusterIP access and direct pod IP access (bypass prevention).
func (state *PolicyState) generateServiceSelectorRecords(src *types.ProcessTreeKey, policy *types.TetragonNetworkPolicy) ([]record.DatapathRecord, error) {
	var records []record.DatapathRecord

	action := calculateAction(&policy.Action)

	svcName := policy.Destination.ServiceRef.Name
	svcNamespace := policy.Destination.ServiceRef.Namespace

	sm := state.GetServiceMap()
	if sm == nil {
		return records, nil
	}
	svcInfo := sm.GetByName(svcNamespace, svcName)

	// CIDR records for ClusterIP and endpoint IPs
	if svcInfo != nil {
		// Block ClusterIP
		if svcInfo.ClusterIP.IsValid() {
			prefixBits := 32
			if svcInfo.ClusterIP.Is6() {
				prefixBits = 128
			}
			cidr := netip.PrefixFrom(svcInfo.ClusterIP, prefixBits)
			// Use the policy's port specification directly:
			// - nil/empty Ports → wildcard record (Port=0, matches all ports)
			// - specific Ports → port-specific records only
			svcDest := &types.TetragonNetworkDestination{
				CIDR:  cidr,
				Ports: policy.Destination.Ports,
			}
			r, err := addDestSrcCIDRRecords(policy.PolicyUID, svcDest, src, action, true)
			if err != nil {
				logger.GetLogger().Warn("CIDR record error", logfields.Error, err)
			}
			records = append(records, r...)
		}

		// Block backend pod IPs (endpoints) to prevent bypass via direct pod access
		endpointIPs := make(map[netip.Addr]bool)
		for _, ep := range svcInfo.Endpoints {
			if ep.IP.IsValid() {
				endpointIPs[ep.IP] = true
			}
		}
		for ip := range endpointIPs {
			records = append(records, generateEndpointCIDRRecords(policy.PolicyUID, src, ip, policy.Destination.Ports, action)...)
		}
	}

	return records, nil
}

func (state *PolicyState) getAllExistingPolicy() []*types.TetragonNetworkPolicy {
	uniquePolicyMap := make(map[types.TetragonPolicyUniqueID]*types.TetragonNetworkPolicy)
	allPolicy := make([]*types.TetragonNetworkPolicy, 0)

	for _, p := range state.src {
		if _, ok := uniquePolicyMap[p.Policy.PolicyUID]; !ok {
			uniquePolicyMap[p.Policy.PolicyUID] = p.Policy
			allPolicy = append(allPolicy, p.Policy)
		}
	}
	for _, p := range state.dst {
		if _, ok := uniquePolicyMap[p.Policy.PolicyUID]; !ok {
			uniquePolicyMap[p.Policy.PolicyUID] = p.Policy
			allPolicy = append(allPolicy, p.Policy)
		}
	}
	// Include serviceSelector policies that may not be in Src/Dst
	for _, p := range state.serviceSelPolicies {
		if _, ok := uniquePolicyMap[p.PolicyUID]; !ok {
			uniquePolicyMap[p.PolicyUID] = p
			allPolicy = append(allPolicy, p)
		}
	}
	return allPolicy
}

func (state *PolicyState) getRecords(currentPolicy []*types.TetragonNetworkPolicy) (*PolicyState, []record.DatapathRecord, error) {
	calculatorRecords := []record.DatapathRecord{}
	calculatorState := state.temporaryEmptyState()
	calculatorState.serviceMap = state.serviceMap

	// Add Policy to calculator state
	for _, p := range currentPolicy {
		err := calculatorState.createMatchLabelsPolicy(p)
		if err != nil {
			return nil, nil, err
		}
	}

	// Calculate current records of before making state change
	for _, p := range state.localObjects {
		r, err := calculatorState.objectAdd(p)
		if err != nil {
			return nil, nil, err
		}
		calculatorRecords = append(calculatorRecords, r...)
	}

	for _, p := range state.remoteObjects {
		r, err := calculatorState.objectAdd(p)
		if err != nil {
			return nil, nil, err
		}
		calculatorRecords = append(calculatorRecords, r...)
	}

	// Create serviceSelector records for existing local objects.
	// This handles the case when a NEW policy is added with EXISTING pods.
	for _, p := range state.localObjects {
		r, err := calculatorState.createServiceSelectorRecords(p)
		if err != nil {
			logger.GetLogger().Warn("GetRecords: failed to create serviceSelector records",
				logfields.Error, err)
			continue
		}
		calculatorRecords = append(calculatorRecords, r...)
	}

	return calculatorState, calculatorRecords, nil
}

// recordsFromPoliciesAddition computes the records generated from the current
// state and policies, then computes the records generated from a fresh state
// contaning the current and new policies. It then returns the new state, the
// records to add and the records to remove (which are the diff between the
// current computed records and the new ones).
//
// Todo, this has lots of low hanging fruit for optimizing duplicate calculations.
func (state *PolicyState) recordsFromPoliciesAddition(policies []*types.TetragonNetworkPolicy) (*PolicyState, []record.DatapathRecord, []record.DatapathRecord, error) {
	// Entry point to Policy state create collect records for current
	// policy state.
	currentPolicy := state.getAllExistingPolicy()
	_, preRecords, err := state.getRecords(currentPolicy)
	if err != nil {
		return nil, nil, nil, err
	}

	// Building new policy set with additional policy
	newPolicy := append(currentPolicy, policies...)

	// Recalculate records using new state with new policy.
	postState := state.temporaryEmptyState()
	postState.localObjects = maps.Clone(state.localObjects)
	postState.remoteObjects = maps.Clone(state.remoteObjects)
	postState.serviceMap = state.serviceMap
	postState, postRecords, err := postState.getRecords(newPolicy)
	if err != nil {
		return nil, nil, nil, err
	}

	// Find datapath record for new policy and the set of records
	// we need to remove.
	removeRecordsSet := record.Diff(preRecords, postRecords)
	return postState, postRecords, removeRecordsSet, nil
}

func (state *PolicyState) AddPolicies(policies []*types.TetragonNetworkPolicy) error {
	state.mu.Lock()
	newState, addSet, removeSet, err := state.recordsFromPoliciesAddition(policies)
	if err != nil {
		state.mu.Unlock()
		return err
	}

	// We should avoid trying to add records that are already programmed
	addSet, err = state.diffExistingRecords(addSet)
	state.mu.Unlock()
	if err != nil {
		return fmt.Errorf("failed to diff existing records: %w", err)
	}

	// Order matters lets add the new set of records. Then second remove any
	// old records that are no longer valid.
	err = state.deps.prog.AddRecords(addSet, false)
	if err != nil {
		return fmt.Errorf("failed to add records: %w", err)
	}
	err = state.deps.prog.RemoveRecords(removeSet)
	if err != nil {
		return fmt.Errorf("failed to remove records: %w", err)
	}

	// Update state only after successful datapath programming
	state.mu.Lock()
	state.writeToState(newState)
	state.mu.Unlock()
	return nil
}

// Entry point to Policy state remove
func (state *PolicyState) RemovePolicies(policies []*types.TetragonNetworkPolicy) error {
	for _, policy := range policies {
		err := state.RemovePolicy(policy)
		if err != nil {
			return err
		}
	}
	return nil
}

func (state *PolicyState) applyServiceSelectorEndpointCIDRDelta(namespace, name string, ipsToAdd, ipsToRemove map[netip.Addr]bool) {
	if len(ipsToAdd) == 0 && len(ipsToRemove) == 0 {
		return
	}

	log := logger.GetLogger().With("service", name, "namespace", namespace)

	// Find all serviceSelector policies targeting this service
	var affectedPolicies []*types.TetragonNetworkPolicy
	for _, policy := range state.serviceSelPolicies {
		if policy.Destination.ServiceRef == nil {
			continue
		}
		if policy.Destination.ServiceRef.Name == name && policy.Destination.ServiceRef.Namespace == namespace {
			affectedPolicies = append(affectedPolicies, policy)
		}
	}

	if len(affectedPolicies) == 0 {
		return
	}

	var removeRecords []record.DatapathRecord
	var addRecords []record.DatapathRecord

	for _, policy := range affectedPolicies {
		action := calculateAction(&policy.Action)

		for _, obj := range state.localObjects {
			podInfo, ok := obj.(*v1alpha1.PodInfo)
			if !ok {
				continue
			}
			if !matchLabelsSubset(policy.Subject.Labels.Equal, state.deps.mergeNamespaceLabels(podInfo)) {
				continue
			}

			src, err := state.deps.createSrcKey(podInfo.WorkloadObject.Namespace, podInfo.WorkloadObject.Name, podInfo.WorkloadType.Kind)
			if err != nil || src == nil {
				continue
			}

			for ip := range ipsToRemove {
				removeRecords = append(removeRecords, generateEndpointCIDRRecords(policy.PolicyUID, src, ip, policy.Destination.Ports, action)...)
			}
			for ip := range ipsToAdd {
				addRecords = append(addRecords, generateEndpointCIDRRecords(policy.PolicyUID, src, ip, policy.Destination.Ports, action)...)
			}
		}
	}

	if len(addRecords) > 0 {
		state.deps.prog.AddRecords(addRecords, false)
	}
	if len(removeRecords) > 0 {
		state.deps.prog.RemoveRecords(removeRecords)
	}

	log.Debug("serviceSelector endpoint CIDR delta applied", "added", len(addRecords), "removed", len(removeRecords))
}

// HandleEndpointChange is called when service endpoints change. It regenerates
// CIDR records for all serviceSelector policies targeting the affected service.
func (state *PolicyState) HandleEndpointChange(namespace, name string, oldEndpoints, newEndpoints []servicemap.EndpointInfo) {
	state.mu.Lock()
	defer state.mu.Unlock()

	// Deduplicate endpoint IPs (endpoints list may have same IP multiple times for different ports)
	oldIPs := make(map[netip.Addr]bool)
	for _, ep := range oldEndpoints {
		if ep.IP.IsValid() {
			oldIPs[ep.IP] = true
		}
	}
	newIPs := make(map[netip.Addr]bool)
	for _, ep := range newEndpoints {
		if ep.IP.IsValid() {
			newIPs[ep.IP] = true
		}
	}

	// Calculate IPs to add (in new but not in old) and IPs to remove (in old but not in new)
	ipsToAdd := make(map[netip.Addr]bool)
	for ip := range newIPs {
		if !oldIPs[ip] {
			ipsToAdd[ip] = true
		}
	}
	ipsToRemove := make(map[netip.Addr]bool)
	for ip := range oldIPs {
		if !newIPs[ip] {
			ipsToRemove[ip] = true
		}
	}

	state.applyServiceSelectorEndpointCIDRDelta(namespace, name, ipsToAdd, ipsToRemove)
}

// HandleServiceDelete removes endpoint CIDR records when a service is deleted.
func (state *PolicyState) HandleServiceDelete(namespace, name string, endpoints []servicemap.EndpointInfo) {
	state.mu.Lock()
	defer state.mu.Unlock()

	// Deduplicate endpoint IPs
	ips := make(map[netip.Addr]bool)
	for _, ep := range endpoints {
		if ep.IP.IsValid() {
			ips[ep.IP] = true
		}
	}

	if len(ips) == 0 {
		return
	}

	state.applyServiceSelectorEndpointCIDRDelta(namespace, name, nil, ips)
}

// generateEndpointCIDRRecords creates CIDR records for a single endpoint IP.
// When ports is nil/empty, a wildcard record (Port=0) is created matching all ports.
// When ports has values, only port-specific records are created.
func generateEndpointCIDRRecords(policyUID types.TetragonPolicyUniqueID, src *types.ProcessTreeKey, ip netip.Addr, ports []uint32, action *record.DatapathAction) []record.DatapathRecord {
	prefixBits := 32
	if ip.Is6() {
		prefixBits = 128
	}
	cidr := netip.PrefixFrom(ip, prefixBits)

	epDest := &types.TetragonNetworkDestination{
		CIDR:  cidr,
		Ports: ports,
	}
	records, err := addDestSrcCIDRRecords(policyUID, epDest, src, action, true)
	if err != nil {
		logger.GetLogger().Warn("CIDR record error for endpoint", logfields.Error, err)
	}

	return records
}

// createServiceSelectorRecords creates datapath records for serviceSelector
// policies that match the given pod. Called from PodAdd and GetRecords.
func (state *PolicyState) createServiceSelectorRecords(pod metav1.Object) ([]record.DatapathRecord, error) {
	var records []record.DatapathRecord

	matchingPolicies := state.getServiceSelectorPolicies(state.deps.mergeNamespaceLabels(pod))
	if len(matchingPolicies) == 0 {
		return records, nil
	}

	src, err := state.deps.createObjectSrcKey(pod)
	if err != nil {
		return records, err
	}
	if src == nil {
		logger.GetLogger().Warn("CreateServiceSelectorRecords: pod not in policyfilter",
			"pod", pod.GetName())
		return records, nil
	}

	for _, policy := range matchingPolicies {
		r, err := state.generateServiceSelectorRecords(src, policy)
		if err != nil {
			logger.GetLogger().Warn("Failed to generate serviceSelector records", logfields.Error, err)
			continue
		}
		records = append(records, r...)
	}

	return records, nil
}

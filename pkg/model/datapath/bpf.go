// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package datapath

import (
	"fmt"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/logger"

	"github.com/isovalent/hubble-fgs/pkg/dnsparser"
	"github.com/isovalent/hubble-fgs/pkg/endpoint"
	"github.com/isovalent/hubble-fgs/pkg/model/record"
	"github.com/isovalent/hubble-fgs/pkg/model/types"
	"github.com/isovalent/hubble-fgs/pkg/netpol/library"
)

var (
	processLock              = sync.Mutex{}
	processTreeBinaryUUIDMap = "process_tree_binary_uid_map"
	processTreeUUIDBinaryMap = "process_tree_uid_binary_map"
	userUID                  = uint32(0)
	userCPU                  = uint32(0xffffffff)
	uidMap                   = make(map[string]uint64)
)

const (
	destinationEndpointMap = "destination_endpoint_map"
)

var (
	// QuotasDNSDomainMappings stores the mappings between the domain and
	// their ID generated after parsing a quota policy. So that we can
	// initialize them once the TCP, UDP, and DNS sensors are online.
	QuotasInitDNSDomainMappings = map[endpoint.Endpoint]uint64{}

	// dnsDomainMap is used to bring DNS/ID mappings up to date at runtime.
	dnsDomainMap = dnsparser.DomainMap{}
)

func (p *BpfProgrammer) initMaybe() {
	p.initProgrammerOnce.Do(func() {
		p.initMap()
		p.endpointAdder = endpoint.MustGet()
		p.policyRepositoryIDReader = library.GetRepository()
		p.records = map[record.RecordKey]record.DatapathRecord{}
	})
}

func (p *BpfProgrammer) AddRecords(records []*record.DatapathRecord, force bool) error {
	p.initMaybe()

	p.recordsMu.Lock()
	defer p.recordsMu.Unlock()

	for _, r := range records {
		key := r.ToKey()
		if _, found := p.records[key]; found {
			// This record is already programmed
			continue
		}

		err := p.addRecord(r, force)
		if err != nil {
			return err
		}

		p.records[key] = *r
	}
	return nil
}

func (p *BpfProgrammer) conflictUpdateMap(key types.DestinationEndpointKey, value types.DestinationEndpointValue) error {

	lookupValue := &types.DestinationEndpointValue{}
	if err := p.dstMap.Lookup(key, lookupValue); err == nil {
		lookupAction := lookupValue.TxAction & record.PolicyMask
		valueAction := value.TxAction & record.PolicyMask
		if lookupAction >= valueAction {
			return nil
		}
	}

	return p.dstMap.Update(key, value, 0)
}

// This call will destroy key and value they can not be used after this.
func (p *BpfProgrammer) populateStatEntry(key types.DestinationEndpointKey, value types.DestinationEndpointValue) error {
	value.TxAction = record.PolicyNone // we want rules for stats, not to impact verdict
	value.Policy = 0
	// RuleId is already 0 from addRecord

	// 2  (src,  *  , local_id, destination, local_nsid).TX += skb->len
	if key.DestinationPort != 0 {
		key.DestinationPort = 0
		value.Port = 0
		if err := p.conflictUpdateMap(key, value); err != nil {
			return err
		}
	}

	// 3  (src,  *  ,    *    , destination, local_nsid).TX += skb->len
	if key.LocalId != 0 {
		key.LocalId = 0
		if err := p.conflictUpdateMap(key, value); err != nil {
			return err
		}
	}

	// 4  (src,  *  ,    *    , *, local_nsid).TX += skb->len
	if key.DestinationId != 0 {
		key.DestinationId = 0
		if err := p.conflictUpdateMap(key, value); err != nil {
			return err
		}
	}

	return nil
}

// src *types.ProcessTreeKey, ep *endpoint.Endpoint, quota, reset, deny uint64, init bool) error {
// what was init for again?
func (p *BpfProgrammer) addRecord(r *record.DatapathRecord, force bool) error {
	var addr [2]uint64
	var dst uint64
	var err error

	if r.Endpoint.EP != nil {
		dst, err = p.endpointAdder.AddEndpoint(*r.Endpoint.EP)
		if err != nil {
			p.AddError++
			return fmt.Errorf("failed to add endpoint for record %s: %w", r, err)
		}
	} else {
		dst = 0
	}

	// A rather annoying ordering problem occurs where we are consuming
	// quota DNS policy through TCP policy and that may or may not have
	// initialized the DNS/UDP sensors yet. If DNS is not yet initialized
	// we need to wait until it comes up to instantiate the domain map
	// entry. Rather than try to sync modules and this code add a retry
	// logic and backoff to do the map update later. This backoffs with
	// x2 each iteration.
	if r.Init {
		if r.Endpoint.EP != nil && r.Endpoint.EP.Dns != "" {
			if err := dnsDomainMap.Update(r.Endpoint.EP.Dns, dst); err != nil {
				QuotasInitDNSDomainMappings[*r.Endpoint.EP] = dst
				go scheduleDomainMapFlush()
			}
		}
	} else {
		if r.Endpoint.EP != nil && r.Endpoint.EP.Dns != "" {
			QuotasInitDNSDomainMappings[*r.Endpoint.EP] = dst
			go scheduleDomainMapFlush()
		}
	}

	if r.Endpoint.EP != nil && r.Endpoint.EP.Type == tetragon.EndpointType_ENDPOINT_TYPE_CIDR {
		if err := p.lpmMap.Write(r.Endpoint.EP.CIDR, dst); err != nil {
			return fmt.Errorf("failed to write LPM for record %s: %w", r, err)
		}
	}

	id, ok := p.policyRepositoryIDReader.GetId(r.PolicyUID.PolicyName)
	if !ok {
		logger.GetLogger().Warn("programmer unable to map policy name to ID", "Policy", r.PolicyUID.PolicyName)
	}

	ruleID, ok := p.policyRepositoryIDReader.GetRuleId(r.PolicyUID)
	if !ok {
		logger.GetLogger().Warn("programmer unable to map policy rule to ID", "Policy", r.PolicyUID.PolicyName, "Rule", r.PolicyUID.RuleName)
	}

	key := types.DestinationEndpointKey{
		LocalId:           r.Src.Self,
		LocalNSId:         r.Src.NSID,
		DestinationId:     dst,
		DestinationSource: types.DestinationSourceUser,
		DestinationPort:   uint64(r.Endpoint.Port),
	}

	value := types.DestinationEndpointValue{
		TxQuota:        0,
		TxLimit:        r.Action.QuotaLimit,
		TxDrops:        0,
		TxAction:       r.Action.Action,
		KtimeLastReset: 0,
		KtimeTxReset:   r.Action.ResetTime,
		TxBytes:        0,
		RxBytes:        0,
		Policy:         id,
		RuleID:         ruleID,
		IPv6:           0,
		KtimeCreate:    0,
		AddrCreate:     addr,
		Port:           uint64(r.Endpoint.Port),
		// Mark as policy template - BPF will clear this flag when real traffic flows
		Flags: types.DestFlagPolicyTemplateOnly,
	}

	lookupValue := &types.DestinationEndpointValue{}
	err = p.dstMap.Lookup(key, lookupValue)
	if err == nil {
		lookupAction := lookupValue.TxAction & record.PolicyMask
		valueAction := value.TxAction & record.PolicyMask

		// key exist and the action is the same,
		// policy and rule assosciated are the same, nothing to do
		if lookupAction == valueAction &&
			lookupValue.Policy == value.Policy &&
			lookupValue.RuleID == value.RuleID {
			return nil
		}
		// key exists, we don't force, and the existing action is
		// "superior" (with order none < allow < deny), ignore
		if !force && lookupAction > valueAction {
			return nil
		}
	}

	if err := p.dstMap.Update(key, value, 0); err != nil {
		p.AddError++
		return fmt.Errorf("failed to update the destination map for record %s: %w", r, err)
	}

	// This is the default rules ID.
	value.RuleID = 0

	// If the EP is wildcarded we need to capture all destinations from
	// any source (EPBF, Userspace, DNS) so we need some extra records.
	// The normal path captures Userspace sources.
	if dst == uint64(0) {
		key.DestinationSource = types.DestinationSourceBPF
		if err := p.conflictUpdateMap(key, value); err != nil {
			p.AddError++
			return fmt.Errorf("failed to update destination map for source BPF for record %s: %w", r, err)
		}

		key.DestinationSource = types.DestinationSourceDNS
		if err := p.conflictUpdateMap(key, value); err != nil {
			p.AddError++
			return fmt.Errorf("failed to update destination map for source DNS for record %s: %w", r, err)
		}
	} else if !force {
		if err := p.populateStatEntry(key, value); err != nil {
			p.AddError++
			return fmt.Errorf("failed to populate stat entry for record %s: %w", r, err)
		}
	}

	p.Add++
	return nil
}

func (p *BpfProgrammer) removeRecord(r *record.DatapathRecord) error {
	var addr [2]uint64
	src := r.Src
	ep := r.Endpoint.EP

	dst := uint64(0)
	if ep != nil {
		var err error

		dst, err = p.endpointAdder.AddEndpoint(*ep)
		if err != nil {
			p.DelError++
			return fmt.Errorf("failed to add endpoint for record %s: %w", r, err)
		}
	}

	if r.Endpoint.EP != nil && r.Endpoint.EP.Type == tetragon.EndpointType_ENDPOINT_TYPE_CIDR {
		if err := p.lpmMap.Delete(r.Endpoint.EP.CIDR); err != nil {
			return fmt.Errorf("failed to delete entry LPM for record %s: %w", r, err)
		}
	}

	// On delete leave dnsDomainMap, it should be managed as its own object!

	// Ideally we would keep all the values here and just update the TxDeny, TxQuota and
	// TxLimit fields. Unfortunately its hard to do a partial update without doing multiple
	// reads. So for now zero entry, but keep the key/value in the map its not obvious
	// to me that we need to move it given the connection is likely still around.
	key := types.DestinationEndpointKey{
		LocalId:           src.Self,
		LocalNSId:         src.NSID,
		DestinationId:     dst,
		DestinationSource: types.DestinationSourceUser,
		DestinationPort:   uint64(r.Endpoint.Port),
	}

	value := types.DestinationEndpointValue{
		TxQuota:        0,
		TxLimit:        0,
		TxDrops:        0,
		TxAction:       0,
		KtimeLastReset: 0,
		KtimeTxReset:   0,
		TxBytes:        0,
		RxBytes:        0,
		Policy:         0,
		RuleID:         0,
		IPv6:           0,
		KtimeCreate:    0,
		AddrCreate:     addr,
		Port:           0,
	}

	// We can't delete this just because the policy is lost we still want to kep stats.
	if err := p.dstMap.Update(key, value, 0); err != nil {
		p.DelError++
		return fmt.Errorf("failed to update the destination map for record %s: %w", r, err)
	}

	// If the EP is wildcarded we need to remove all destinations from
	// any source (EPBF, Userspace, DNS) so we need some extra records.
	if dst == uint64(0) {
		key.DestinationSource = types.DestinationSourceBPF
		if err := p.dstMap.Update(key, value, 0); err != nil {
			p.DelError++
			return fmt.Errorf("failed to update destination map for source BPF for record %s: %w", r, err)
		}

		key.DestinationSource = types.DestinationSourceDNS
		if err := p.dstMap.Update(key, value, 0); err != nil {
			p.DelError++
			return fmt.Errorf("failed to update destination map for source DNS for record %s: %w", r, err)
		}
	}
	p.Del++
	return nil
}

func (p *BpfProgrammer) RemoveRecords(records []*record.DatapathRecord) error {
	p.initMaybe()

	p.recordsMu.Lock()
	defer p.recordsMu.Unlock()

	for _, r := range records {
		key := r.ToKey()
		if _, found := p.records[key]; !found {
			// This record is not programmed
			continue
		}

		err := p.removeRecord(r)
		if err != nil {
			return err
		}

		delete(p.records, key)
	}
	return nil
}

type processTreeBinaryUIDKey struct {
	binary [PATH_SIZE]byte
	args   [PATH_SIZE]byte
}

func (k processTreeBinaryUIDKey) String() string {
	return fmt.Sprintf("processTreeBinaryUIDKey: %s-%s", k.binary, k.args)
}

type processTreeID struct {
	uid uint32
	cpu uint32 // Contains both cpu (31 bits) and ignore_args (1 bit)
}

// SetCPU sets the CPU value (31 bits), preserving the ignore_args bit
func (id *processTreeID) SetCPU(cpu uint32) {
	id.cpu = (id.cpu & 0x80000000) | (cpu & 0x7FFFFFFF)
}

// GetCPU returns the CPU value (31 bits)
func (id *processTreeID) GetCPU() uint32 {
	return id.cpu & 0x7FFFFFFF
}

// SetIgnoreArgs sets the ignore_args bit
func (id *processTreeID) SetIgnoreArgs(ignoreArgs bool) {
	if ignoreArgs {
		id.cpu |= 0x80000000
	} else {
		id.cpu &= 0x7FFFFFFF
	}
}

// GetIgnoreArgs returns the ignore_args bit
func (id *processTreeID) GetIgnoreArgs() bool {
	return (id.cpu & 0x80000000) != 0
}

func (id processTreeID) String() string {
	return fmt.Sprintf("processTreeID: %d-%d (ignore_args: %v)", id.uid, id.GetCPU(), id.GetIgnoreArgs())
}

func (p *BpfProgrammer) GetBinaryId(binaryName string, ignoreArgs bool) (uint64, error) {
	var process = [PATH_SIZE]byte{0}
	var zero = [PATH_SIZE]byte{0}

	copy(process[:], binaryName)

	p.initMaybe()

	uidKey := processTreeBinaryUIDKey{
		binary: process,
		args:   zero,
	}

	processLock.Lock()
	defer processLock.Unlock()

	id, ok := uidMap[binaryName]
	if ok {
		return id, nil
	}

	userUID++
	processID := processTreeID{}
	processID.uid = userUID
	processID.SetCPU(userCPU)
	processID.SetIgnoreArgs(ignoreArgs)

	if err := p.binaryMap.Update(uidKey, processID, ebpf.UpdateAny); err != nil {
		return uint64(0), fmt.Errorf("failed to update the bpf binary map: %w", err)
	}

	if err := p.uidBpfMap.Update(processID, uidKey, ebpf.UpdateAny); err != nil {
		return uint64(0), fmt.Errorf("failed to update the bpf uid map: %w", err)
	}

	id = uint64(uint64(userUID) | (uint64(processID.cpu) << 32))
	uidMap[binaryName] = id
	return id, nil
}

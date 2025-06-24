package datapath

import (
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/isovalent/hubble-fgs/pkg/dnsparser"
	"github.com/isovalent/hubble-fgs/pkg/endpoint"
	"github.com/isovalent/hubble-fgs/pkg/model/record"
	"github.com/isovalent/hubble-fgs/pkg/model/types"
	"github.com/isovalent/hubble-fgs/pkg/netpol/library"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3/lpm"
)

var (
	dstMap             *ebpf.Map
	binaryMap          *ebpf.Map
	uidBpfMap          *ebpf.Map
	initProgrammerOnce sync.Once
	lpmMap             *lpm.LPMMap
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

func initMap() {
	var err error

	file := filepath.Join(bpf.MapPrefixPath(), destinationEndpointMap)
	dstMap, err = ebpf.LoadPinnedMap(file, nil)
	if err != nil {
		logger.GetLogger().Error(fmt.Sprintf("failed to pin DestinationMap (%s): %v", file, err))
	}

	file = filepath.Join(bpf.MapPrefixPath(), processTreeBinaryUUIDMap)
	binaryMap, err = ebpf.LoadPinnedMap(file, nil)
	if err != nil {
		logger.GetLogger().Warn("failed to open file", "file", file, logfields.Error, err)
	}

	file = filepath.Join(bpf.MapPrefixPath(), processTreeUUIDBinaryMap)
	uidBpfMap, err = ebpf.LoadPinnedMap(file, nil)
	if err != nil {
		logger.GetLogger().Warn("failed to open file", "file", file, logfields.Error, err)
	}

	lpmMap, err = lpm.NewLPM()
	if err != nil {
		logger.GetLogger().Warn("failed to create LPM programmer", logfields.Error, err)
	}
}

func (p *BpfProgrammer) AddRecords(records []*record.DatapathRecord, force bool) error {
	for _, r := range records {
		p.AddSingleRecord(r, force)
	}
	return nil
}

func scheduleDomainMapFlush() {
	var err error
	retries := 10

	for i := 0; i < retries; i++ {
		for endpoint, id := range QuotasInitDNSDomainMappings {
			if err = dnsDomainMap.Update(endpoint.Dns, id); err != nil {
				break
			}
		}
		if err == nil {
			return
		}
		logger.GetLogger().Debug("retry domain mapping", logfields.Error, err)
		time.Sleep(time.Duration(i) * time.Second)
	}
	logger.GetLogger().Warn("failed to program domain map policy incomplete")
}

func conflictUpdateMap(key *types.DestinationEndpointKey, value *types.DestinationEndpointValue) error {

	lookupValue := &types.DestinationEndpointValue{}
	if err := dstMap.Lookup(key, lookupValue); err == nil {
		lookupAction := lookupValue.TxAction & record.PolicyMask
		valueAction := value.TxAction & record.PolicyMask
		if lookupAction >= valueAction {
			return nil
		}
	}

	return dstMap.Update(key, value, 0)
}

// This call will destroy key and value they can not be used after this.
func populateStatEntry(key *types.DestinationEndpointKey, value *types.DestinationEndpointValue) error {
	value.TxAction = record.PolicyNone // we want rules for stats, not to impact verdict

	// 2  (src,  *  , local_id, destination, local_nsid).TX += skb->len
	if key.DestinationPort != 0 {
		key.DestinationPort = 0
		value.Port = 0
		if err := conflictUpdateMap(key, value); err != nil {
			return err
		}
	}

	// 3  (src,  *  ,    *    , destination, local_nsid).TX += skb->len
	if key.LocalId != 0 {
		key.LocalId = 0
		if err := conflictUpdateMap(key, value); err != nil {
			return err
		}
	}

	// 4  (src,  *  ,    *    , *, local_nsid).TX += skb->len
	if key.DestinationId != 0 {
		key.DestinationId = 0
		if err := conflictUpdateMap(key, value); err != nil {
			return err
		}
	}

	return nil
}

// src *types.ProcessTreeKey, ep *endpoint.Endpoint, quota, reset, deny uint64, init bool) error {
// what was init for again?
func (p *BpfProgrammer) AddSingleRecord(r *record.DatapathRecord, force bool) error {
	var addr [2]uint64
	var dst uint64
	var err error

	initProgrammerOnce.Do(func() { initMap() })

	if r.Endpoint.EP != nil {
		c := endpoint.MustGet()
		dst, err = c.AddEndpoint(*r.Endpoint.EP)
		if err != nil {
			p.AddError++
			logger.GetLogger().Warn("Failed to add endpoint for quota", logfields.Error, err)
			return err
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
		if err := lpmMap.Write(r.Endpoint.EP.Ip, dst); err != nil {
			logger.GetLogger().Warn("Failed to create LPM id", logfields.Error, err)
			return err
		}
	}

	id, ok := library.GetId(r.Policy.Name)
	if !ok {
		logger.GetLogger().Warn("programmer unable to map policy name to ID", "Policy", r.Policy.Name)
	}

	ruleID, ok := library.GetRuleId(r.Policy.Name, r.Policy.Rule)
	if !ok {
		logger.GetLogger().Warn("programmer unable to map policy rule to ID", "Policy", r.Policy.Name, "Rule", r.Policy.Rule)
	}

	key := &types.DestinationEndpointKey{
		LocalId:           r.Src.Self,
		LocalNSId:         r.Src.NSID,
		DestinationId:     dst,
		DestinationSource: types.DestinationSourceUser,
		DestinationPort:   uint64(r.Endpoint.Port),
	}

	value := &types.DestinationEndpointValue{
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
	}

	lookupValue := &types.DestinationEndpointValue{}
	err = dstMap.Lookup(key, lookupValue)
	if err == nil {
		lookupAction := lookupValue.TxAction & record.PolicyMask
		valueAction := value.TxAction & record.PolicyMask

		// key exist and the action is the same, ignore
		if lookupAction == valueAction {
			return nil
		}
		// key exists, we don't force, and the existing action is
		// "superior" (with order none < allow < deny), ignore
		if !force && lookupAction > valueAction {
			return nil
		}
	}

	if err := dstMap.Update(key, value, 0); err != nil {
		p.AddError++
		return err
	}

	// This is the default rules ID.
	value.RuleID = 0

	// If the EP is wildcarded we need to capture all destinations from
	// any source (EPBF, Userspace, DNS) so we need some extra records.
	// The normal path captures Userspace sources.
	if dst == uint64(0) {
		key.DestinationSource = types.DestinationSourceBPF
		if err := conflictUpdateMap(key, value); err != nil {
			p.AddError++
			return err
		}

		key.DestinationSource = types.DestinationSourceDNS
		if err := conflictUpdateMap(key, value); err != nil {
			p.AddError++
			return err
		}
	} else if !force {
		if err := populateStatEntry(key, value); err != nil {
			p.AddError++
			return err
		}
	}

	p.Add++
	return nil
}

func (p *BpfProgrammer) RemoveSingleRecord(r *record.DatapathRecord) error {
	var addr [2]uint64
	src := r.Src
	ep := r.Endpoint.EP

	initProgrammerOnce.Do(func() { initMap() })

	dst := uint64(0)
	if ep != nil {
		var err error

		c := endpoint.MustGet()
		dst, err = c.AddEndpoint(*ep)
		if err != nil {
			p.DelError++
			logger.GetLogger().Warn("Failed to add endpoint for quota", logfields.Error, err)
			return err
		}
	}

	if r.Endpoint.EP != nil && r.Endpoint.EP.Type == tetragon.EndpointType_ENDPOINT_TYPE_CIDR {
		if err := lpmMap.Delete(r.Endpoint.EP.Ip); err != nil {
			logger.GetLogger().Warn("Failed to delete LPM entry", logfields.Error, err)
			return err
		}
	}

	// On delete leave dnsDomainMap, it should be managed as its own object!

	// Ideally we would keep all the values here and just update the TxDeny, TxQuota and
	// TxLimit fields. Unfortunately its hard to do a partial update without doing multiple
	// reads. So for now zero entry, but keep the key/value in the map its not obvious
	// to me that we need to move it given the connection is likely still around.
	key := &types.DestinationEndpointKey{
		LocalId:           src.Self,
		LocalNSId:         src.NSID,
		DestinationId:     dst,
		DestinationSource: types.DestinationSourceUser,
		DestinationPort:   uint64(r.Endpoint.Port),
	}

	value := &types.DestinationEndpointValue{
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
	if err := dstMap.Update(key, value, 0); err != nil {
		p.DelError++
		return err
	}

	// If the EP is wildcarded we need to remove all destinations from
	// any source (EPBF, Userspace, DNS) so we need some extra records.
	if dst == uint64(0) {
		key.DestinationSource = types.DestinationSourceBPF
		if err := dstMap.Update(key, value, 0); err != nil {
			p.DelError++
			return err
		}

		key.DestinationSource = types.DestinationSourceDNS
		if err := dstMap.Update(key, value, 0); err != nil {
			p.DelError++
			return err
		}
	}
	p.Del++
	return nil
}

func (p *BpfProgrammer) RemoveRecords(records []*record.DatapathRecord) error {
	for _, r := range records {
		p.RemoveSingleRecord(r)
	}
	return nil
}

type processTreeBinaryUIDKey struct {
	binary [256]byte
	args   [256]byte
}

type processTreeID struct {
	uid uint32
	cpu uint32
}

func (p *BpfProgrammer) GetBinaryId(binaryName string) (uint64, error) {
	var process = [256]byte{0}
	var zero = [256]byte{0}

	copy(process[:], binaryName)

	initProgrammerOnce.Do(func() { initMap() })

	uidKey := &processTreeBinaryUIDKey{
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
	processID := &processTreeID{}
	processID.uid = userUID
	processID.cpu = userCPU
	if err := binaryMap.Update(uidKey, processID, ebpf.UpdateAny); err != nil {
		return uint64(0), fmt.Errorf("failed to update the bpf binary map: %w", err)
	}

	if err := uidBpfMap.Update(processID, uidKey, ebpf.UpdateAny); err != nil {
		return uint64(0), fmt.Errorf("failed to update the bpf uid map: %w", err)
	}

	id = uint64(uint64(userUID) | (uint64(userCPU) << 32))
	uidMap[binaryName] = id
	return id, nil
}

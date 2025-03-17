package datapath

import (
	"fmt"
	"path/filepath"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/isovalent/hubble-fgs/pkg/dnsparser"
	"github.com/isovalent/hubble-fgs/pkg/endpoint"
	"github.com/isovalent/hubble-fgs/pkg/model/record"
	"github.com/isovalent/hubble-fgs/pkg/model/types"
)

var (
	dstMap             *ebpf.Map
	initProgrammerOnce sync.Once
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
		logger.GetLogger().Errorf("failed to pin DestinationMap (%s): %v", file, err)
	}
}

func (p *BpfProgrammer) AddRecords(records []*record.DatapathRecord) error {
	for _, r := range records {
		p.AddSingleRecord(r)
	}
	return nil
}

// src *types.ProcessTreeKey, ep *endpoint.Endpoint, quota, reset, deny uint64, init bool) error {
// what was init for again?
func (p *BpfProgrammer) AddSingleRecord(r *record.DatapathRecord) error {
	var addr [2]uint64
	var dst uint64
	var err error

	initProgrammerOnce.Do(func() { initMap() })

	if r.EP != nil {
		c := endpoint.Get()
		dst, err = c.AddEndpoint(*r.EP)
		if err != nil {
			p.AddError++
			logger.GetLogger().WithError(err).Warn("Failed to add endpoint for quota")
			return err
		}
	} else {
		dst = 0
	}

	// A rather annoying ordering problem occurs where we are consuming
	// quota DNS policy through TCP policy and that may or may not have
	// initialized the DNS/UDP sensors yet. If DNS is not yet initialized
	// we need to wait until it comes up. So we check init state. And
	// if this update is through a path already fully initialized we
	// add it directly to the map otherwise we do a bulk update in init
	// path.
	if r.Init {
		if r.EP != nil {
			if err := dnsDomainMap.Update(r.EP.Dns, dst); err != nil {
				p.AddError++
				return fmt.Errorf("failed to write BPF domain maps: %w", err)
			}
		}
	} else {
		if r.EP != nil {
			QuotasInitDNSDomainMappings[*r.EP] = dst
		}
	}

	key := &types.DestinationEndpointKey{
		LocalId:           r.Src.Self,
		LocalNSId:         r.Src.CgroupId,
		DestinationId:     dst,
		DestinationSource: types.DestinationSourceUser,
		DestinationPort:   0,
	}

	value := &types.DestinationEndpointValue{
		TxQuota:        0,
		TxLimit:        r.Action.Quota,
		TxDrops:        0,
		TxDeny:         r.Action.Deny,
		KtimeLastReset: 0,
		KtimeTxReset:   r.Action.Reset,
		TxBytes:        0,
		RxBytes:        0,
		Pad0:           0,
		IPv6:           0,
		KtimeCreate:    0,
		AddrCreate:     addr,
		Port:           0,
	}

	if err := dstMap.Update(key, value, 0); err != nil {
		p.AddError++
		return err
	}

	p.Add++
	return nil
}

func (p *BpfProgrammer) RemoveSingleRecord(r *record.DatapathRecord) error {
	var addr [2]uint64
	src := r.Src
	ep := r.EP

	initProgrammerOnce.Do(func() { initMap() })

	dst := uint64(0)
	if ep != nil {
		var err error

		c := endpoint.Get()
		dst, err = c.AddEndpoint(*ep)
		if err != nil {
			p.DelError++
			logger.GetLogger().WithError(err).Warn("Failed to add endpoint for quota")
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

	// We can't delete this just because the policy is lost we still want to kep stats.
	if err := dstMap.Update(key, value, 0); err != nil {
		p.DelError++
		return err
	}

	p.Del++
	return nil
}

func (p *BpfProgrammer) RemoveRecords(records []*record.DatapathRecord) (int, error) {
	for _, r := range records {
		p.RemoveSingleRecord(r)
	}
	return len(records), nil
}

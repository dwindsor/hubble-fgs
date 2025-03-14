package dns

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/isovalent/hubble-fgs/pkg/endpoint"
	"github.com/isovalent/hubble-fgs/pkg/model/types"
	"github.com/sirupsen/logrus"
)

type DatapathInterface interface {
	// Add network policy to BPF datapath, network policy is three parts
	// three parts: Subject, Destination and Action. The init bool is a
	// slightly unpleasant artifact of the API that is needed to tell
	// BPF programming side if this is part of the init flow. In init not
	// all BPF maps may be online yet.
	AddNetworkPolicy(src *types.ProcessTreeKey,
		a *types.TetragonNetworkAction,
		d *types.TetragonNetworkDestination,
		init bool) error

	// Add single dns policy. Raw interface to program a specific rule in
	// the datapath when necessary and may or may not be part of a full
	// network policy. The subject and destination (EP is raw form of
	// destination) give the location. The bpf Map is included to allow
	// reuse without open/close ops. And finllay quota, reset, deny give
	// the action in open coded form.
	AddSinglePolicy(src *types.ProcessTreeKey,
		ep *endpoint.Endpoint,
		dstMap *ebpf.Map,
		quota, reset, deny uint64, init bool) error

	// Remopve Network Policy, will lookup the key/destination and remove
	// it from the BPF datapath.
	RemoveNetworkPolicy(src *types.ProcessTreeKey,
		d *types.TetragonNetworkDestination) error

	RemoveSinglePolicy(src *types.ProcessTreeKey,
		ep *endpoint.Endpoint,
		dstMap *ebpf.Map) error
}

type BpfProgrammer struct {
	Add      uint64
	AddError uint64
	Del      uint64
	DelError uint64
}

func (p *BpfProgrammer) AddNetworkPolicy(src *types.ProcessTreeKey,
	a *types.TetragonNetworkAction,
	d *types.TetragonNetworkDestination,
	init bool) error {
	quotaBytes := uint64(0)
	resetNS := uint64(0)
	var err error

	file := filepath.Join(bpf.MapPrefixPath(), destinationEndpointMap)
	dstMap, err := ebpf.LoadPinnedMap(file, nil)
	if err != nil {
		p.AddError++
		logger.GetLogger().WithError(err).WithField("file", file).Warn("Could not open map")
		return err
	}

	defer dstMap.Close()

	if a.QuotaAction != nil {
		resetNS, err = quotaToNs(a.QuotaAction.Reset)
		if err != nil {
			p.AddError++
			logger.GetLogger().WithError(err).Warn("failed to conver reset time")
			return err
		}

		quotaBytes, err = strconv.ParseUint(a.QuotaAction.Quota, 10, 64)
		if err != nil {
			p.AddError++
			return err
		}
	}

	denyVal := uint64(0)
	if a.EnforceAction != nil && a.EnforceAction.Deny {
		denyVal = uint64(1)
	}

	for _, entry := range d.FQDN.Names {
		ep := &endpoint.Endpoint{
			Type: endpoint.DnsType,
			Dns:  entry,
		}
		if err := p.AddSinglePolicy(src, ep, dstMap, quotaBytes, resetNS, denyVal, init); err != nil {
			logger.GetLogger().WithFields(logrus.Fields{
				"Errors": p.AddError,
				"Policy": p.Add + 1,
				"cgid":   src.CgroupId,
				"self":   src.Self,
				"quota":  quotaBytes,
				"reset":  a.QuotaAction,
				"deny":   denyVal,
				"dest":   entry,
			}).WithError(err).Error("TCP quota entry Failed")
		}
	}
	logger.GetLogger().WithFields(logrus.Fields{
		"Policy": p.Add,
		"cgid":   src.CgroupId,
		"self":   src.Self,
		"quota":  quotaBytes,
		"reset":  a.QuotaAction,
		"dest":   strings.Join(d.FQDN.Names, " "),
	}).Info("TCP quota added")
	return nil
}

func (p *BpfProgrammer) RemoveNetworkPolicy(src *types.ProcessTreeKey, d *types.TetragonNetworkDestination) error {
	var err error

	file := filepath.Join(bpf.MapPrefixPath(), destinationEndpointMap)
	dstMap, err := ebpf.LoadPinnedMap(file, nil)
	if err != nil {
		p.DelError++
		logger.GetLogger().WithError(err).WithField("file", file).Warn("Could not open map")
		return err
	}
	defer dstMap.Close()

	for _, entry := range d.FQDN.Names {
		ep := &endpoint.Endpoint{
			Type: endpoint.DnsType,
			Dns:  entry,
		}
		if err := p.RemoveSinglePolicy(src, ep, dstMap); err != nil {
			logger.GetLogger().WithFields(logrus.Fields{
				"Errors": p.DelError,
				"Policy": p.Del,
				"cgid":   src.CgroupId,
				"self":   src.Self,
				"dest":   entry,
			}).WithError(err).Error("TCP quota remove Failed")
		}
	}
	logger.GetLogger().WithFields(logrus.Fields{
		"Policy": p.Del,
		"cgid":   src.CgroupId,
		"self":   src.Self,
		"dest":   strings.Join(d.FQDN.Names, " "),
	}).Info("TCP quota removed")
	return nil

}

func (p *BpfProgrammer) AddSinglePolicy(src *types.ProcessTreeKey, ep *endpoint.Endpoint, dstMap *ebpf.Map, quota, reset, deny uint64, init bool) error {
	var addr [2]uint64

	c := endpoint.Get()
	dst, err := c.AddEndpoint(*ep)
	if err != nil {
		p.AddError++
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
			p.AddError++
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
		p.AddError++
		return err
	}

	p.Add++
	return nil
}

func (p *BpfProgrammer) RemoveSinglePolicy(src *types.ProcessTreeKey, ep *endpoint.Endpoint, dstMap *ebpf.Map) error {
	var addr [2]uint64

	c := endpoint.Get()
	dst, err := c.AddEndpoint(*ep)
	if err != nil {
		p.DelError++
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
		p.DelError++
		return err
	}

	p.Del++
	return nil
}

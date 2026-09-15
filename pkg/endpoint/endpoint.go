// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package endpoint

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"

	"github.com/cilium/tetragon/pkg/logger/logfields"
	corev1 "k8s.io/api/core/v1"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/logger"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/stretchr/testify/mock"

	"github.com/isovalent/hubble-fgs/pkg/metrics/dnsmetrics"
	"github.com/isovalent/hubble-fgs/pkg/option"
)

type Source struct {
	Ip string
}

type endpointIdentity struct {
	Type      tetragon.EndpointType
	Dns       string
	Kind      string
	Namespace string
	Name      string
	CIDR      netip.Prefix
}

type Endpoint struct {
	endpointIdentity
	UID string
}

func (e *Endpoint) String() string {
	return fmt.Sprintf("wl(%s:%s:%s) dns(%s) cidr(%s)", e.Kind, e.Namespace, e.Name, e.Dns, e.CIDR)
}

var _ EndpointCache = &Cache{}
var _ EndpointCache = &FakeCache{}

type EndpointCache interface {
	// AddIpServiceMap adds a Kubernetes service to the endpoint cache.
	AddIpServiceMap(epService *corev1.Service) error
	AddIpPodMap(epPod *v1alpha1.PodInfo)
	AddIpDnsMap(dns *tetragon.DnsInfo)
	AddEndpoint(ep Endpoint) (uint64, error)
	LookupID(lookup uint64) (value Endpoint, ok bool)
	LookupIP(ip net.IP) (uint64, error)
	LookupIPv4Raw(addr uint32) (uint64, error)
	DebugEndpointMap() ([]uint64, []*Endpoint)
}

type EndpointAdder interface {
	AddEndpoint(ep Endpoint) (uint64, error)
}

type Cache struct {
	cache       *lru.Cache[uint64, Endpoint]
	revCache    *lru.Cache[endpointIdentity, uint64]
	endpointMap *ebpf.Map
}

var (
	cache           EndpointCache
	endpointIdMap   = "tg_endpoint_id_map"
	initGlobalCache sync.Once

	idLock sync.Mutex
	id     = uint64(1)
)

type endpointKey struct {
	Addr [2]uint64
}

type endpointValue struct {
	Id uint64
}

func (c *Cache) DebugEndpointMap() ([]uint64, []*Endpoint) {
	keys := c.cache.Keys()
	values := c.cache.Values()
	endpoints := make([]*Endpoint, 0)

	for _, v := range values {
		endpoints = append(endpoints, &v)
	}
	return keys, endpoints
}

// Helper routine requires correct locking and should only be used from
// insertNew and insertKnown.
func (c *Cache) insertEndpoint(ep Endpoint, key uint64) {
	if c.cache.Add(key, ep) {
		dnsmetrics.DnsCacheEvictions().Inc()
	}
	if c.revCache.Add(ep.endpointIdentity, key) {
		dnsmetrics.DnsCacheEvictions().Inc()
	}
}

func (c *Cache) insertNewEndpoint(ep Endpoint) uint64 {
	idLock.Lock()
	defer idLock.Unlock()

	dstId := id
	c.insertEndpoint(ep, dstId)
	id++
	return dstId
}

func (c *Cache) insertKnownEndpoint(ep Endpoint, key uint64) {
	idLock.Lock()
	defer idLock.Unlock()

	c.insertEndpoint(ep, key)
}

func (c *Cache) AddEndpoint(ep Endpoint) (uint64, error) {
	dstId, ok := c.revCache.Get(ep.endpointIdentity)
	if !ok {
		dstId = c.insertNewEndpoint(ep)
	} else {
		c.cache.Add(dstId, ep)
	}
	logger.GetLogger().Debug("PolicyID allocated", "id", dstId)
	return dstId, nil
}

func (c *Cache) LookupID(lookup uint64) (value Endpoint, ok bool) {
	return c.cache.Get(lookup)
}

func (c *Cache) LookupIP(ip net.IP) (uint64, error) {
	var (
		key   endpointKey
		value endpointValue
	)

	key.Addr[0] = uint64(binary.LittleEndian.Uint32(ip[0:]))
	key.Addr[1] = 0

	if err := c.endpointMap.Lookup(&key, &value); err != nil {
		return 0, err
	}
	return value.Id, nil
}

func (c *Cache) LookupIPv4Raw(addr uint32) (uint64, error) {
	var (
		key   endpointKey
		value endpointValue
	)
	key.Addr[0] = uint64(addr)
	if err := c.endpointMap.Lookup(&key, &value); err != nil {
		return 0, err
	}
	return value.Id, nil
}

func (c *Cache) AddIpServiceMap(epService *corev1.Service) error {
	var (
		key   endpointKey
		value endpointValue
	)

	ep := Endpoint{
		Type:      tetragon.EndpointType_ENDPOINT_TYPE_SERVICE,
		Namespace: epService.Namespace,
		Name:      epService.Name,
		UID:       string(epService.UID),
	}

	// Notice pods may reuse IPs in this case we just update the
	// ip->id entry. However we keep the ID->EP mapping for later
	// use either from gRPC reporting and/or future Pod mappings.
	if idExists, ok := c.revCache.Get(ep.endpointIdentity); ok {
		value.Id = idExists
		c.cache.Add(idExists, ep)
	} else {
		value.Id = c.insertNewEndpoint(ep)
	}

	// We could do external IPs as well if needed.
	for _, ip := range epService.Spec.ClusterIPs {
		ipEncoded4 := net.ParseIP(ip).To4()
		if ipEncoded4 != nil {
			key.Addr[0] = uint64(binary.LittleEndian.Uint32(ipEncoded4[0:]))
			key.Addr[1] = 0
		} else {
			continue
		}
		if err := c.endpointMap.Update(key, value, 0); err != nil {
			return err
		}
	}
	return nil
}

func (c *Cache) AddIpPodMap(epPod *v1alpha1.PodInfo) {
	var (
		key   endpointKey
		value endpointValue
	)

	ep := Endpoint{
		Type:      tetragon.EndpointType_ENDPOINT_TYPE_POD,
		Kind:      epPod.WorkloadType.Kind,
		Namespace: epPod.WorkloadObject.Namespace,
		Name:      epPod.WorkloadObject.Name,
	}

	// Notice pods may reuse IPs in this case we just update the
	// ip->id entry. However we keep the ID->EP mapping for later
	// use either from gRPC reporting and/or future Pod mappings.
	if idExists, ok := c.revCache.Get(ep.endpointIdentity); ok {
		value.Id = idExists
	} else {
		value.Id = c.insertNewEndpoint(ep)
	}

	for _, ip := range epPod.Status.PodIPs {
		ipEncoded4 := net.ParseIP(ip.IP).To4()
		if ipEncoded4 != nil {
			key.Addr[0] = uint64(binary.LittleEndian.Uint32(ipEncoded4[0:]))
			key.Addr[1] = 0
		} else {
			continue
		}
		if err := c.endpointMap.Update(key, value, 0); err != nil {
			logger.GetLogger().Warn("Could not update endpoint map", logfields.Error, err)
			continue
		}
	}
}

func (c *Cache) AddIpDnsMap(dns *tetragon.DnsInfo) {
	if !dns.Response {
		return
	}

	var (
		key   endpointKey
		value endpointValue
	)

	ep := Endpoint{
		Type: tetragon.EndpointType_ENDPOINT_TYPE_DNS,
		Dns:  strings.Join(dns.Names, ","),
	}

	for _, ip := range dns.Ips {
		ipEncoded4 := net.ParseIP(ip).To4()
		if ipEncoded4 != nil {
			key.Addr[0] = uint64(binary.LittleEndian.Uint32(ipEncoded4[0:]))
			key.Addr[1] = 0
		} else {
			continue
		}

		// We might get overlapping IP->[]DNSNames mappings in this
		// case lets just aggregate them and create a superset of
		// all possible names that may be behind the IP. Its not
		// possible to know precisely which one the session is attached
		// to anyways in most cases without L7 visibility. e.g. in
		// HTTP the endpoint may be determined by the Host field.
		var tmp endpointValue
		if err := c.endpointMap.Lookup(key, &tmp); err == nil {
			epExists, ok := c.cache.Get(tmp.Id)
			if !ok {
				logger.GetLogger().Warn("AddIpDnsMap BPF map and user cache out of sync", logfields.Error, err)
				continue
			}

			newNameSet := strings.Split(ep.Dns, ",")
			oldNameSet := strings.Split(epExists.Dns, ",")
			for _, name := range oldNameSet {
				found := slices.Contains(newNameSet, name)
				if !found {
					newNameSet = append(newNameSet, name)
				}
			}
			if len(newNameSet) != len(oldNameSet) {
				ep.Dns = strings.Join(newNameSet, ",")
				c.insertKnownEndpoint(ep, tmp.Id)
			}
		} else {
			// This endpoint may have a preconfigured userspace ID. In that
			// case, preserve the existing mapping.
			idExists, ok := c.revCache.Get(ep.endpointIdentity)
			if ok {
				value.Id = idExists
			} else {
				value.Id = c.insertNewEndpoint(ep)
			}

			if err := c.endpointMap.Update(key, value, 0); err != nil {
				logger.GetLogger().Warn("Could not update endpoint map", logfields.Error, err)
				continue
			}
		}
	}
}

type FakeCache struct {
	mock.Mock
}

func (fc *FakeCache) AddIpServiceMap(epService *corev1.Service) error {
	args := fc.Called(epService)
	return args.Error(0)
}

func (fc *FakeCache) AddIpPodMap(_ *v1alpha1.PodInfo) {
}

func (fc *FakeCache) AddIpDnsMap(_ *tetragon.DnsInfo) {
}

func (fc *FakeCache) AddEndpoint(_ Endpoint) (uint64, error) {
	return 0, fmt.Errorf("FakeCache: AddIpServiceMap not implemented")
}

func (fc *FakeCache) LookupID(_ uint64) (value Endpoint, ok bool) {
	return Endpoint{}, false
}

func (fc *FakeCache) LookupIP(_ net.IP) (uint64, error) {
	return 0, fmt.Errorf("FakeCache: LookupIP not implemented")
}

func (fc *FakeCache) LookupIPv4Raw(_ uint32) (uint64, error) {
	return 0, fmt.Errorf("FakeCache: LookupIPv4Raw not implemented")
}

func (fc *FakeCache) DebugEndpointMap() ([]uint64, []*Endpoint) {
	return nil, nil
}

func MustGet() EndpointCache {
	initGlobalCache.Do(func() {
		var err error
		if !option.Config.EnableApplicationModel {
			cache = &FakeCache{}
		} else {
			cache, err = newCache()
			if err != nil {
				logger.GetLogger().Warn("Could not initialize endpoint model", logfields.Error, err)
			}
		}
	})
	return cache
}

package endpoint

import (
	"encoding/binary"
	"net"
	"path/filepath"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/logger"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/isovalent/hubble-fgs/pkg/metrics/dnsmetrics"
	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"
)

type Type int

const (
	UnknownType Type = 0
	DnsType     Type = 1
	PodType     Type = 2
	IpType      Type = 3
)

type Endpoint struct {
	Type      Type
	Dns       string
	Kind      string
	Namespace string
	Name      string
	Ip        string
}

type Cache struct {
	cache    *lru.Cache[uint64, Endpoint]
	revCache *lru.Cache[Endpoint, uint64]
}

var (
	cache           *Cache
	endpointIdMap   = "tg_endpoint_id_map"
	initGlobalCache sync.Once

	idLock sync.Mutex
	id     = uint64(1)
)

func newCache() (*Cache, error) {
	if cache != nil {
		return cache, nil
	}

	logger.GetLogger().WithField("size", enterpriseOption.Config.EndpointCacheSize).Info("Initializing Endpoint cache")
	fwdlru, err := lru.New[uint64, Endpoint](enterpriseOption.Config.EndpointCacheSize)
	if err != nil {
		return nil, err
	}
	revLru, err := lru.New[Endpoint, uint64](enterpriseOption.Config.EndpointCacheSize)
	if err != nil {
		return nil, err
	}

	cache = &Cache{
		cache:    fwdlru,
		revCache: revLru,
	}

	return cache, nil
}

type endpointKey struct {
	Addr [2]uint64
}

type endpointValue struct {
	Id uint64
}

// Helper routine requires correct locking and should only be used from
// insertNew and insertKnown.
func (c *Cache) insertEndpoint(ep Endpoint, key uint64) {
	if c.cache.Add(key, ep) {
		dnsmetrics.DnsCacheEvictions().Inc()
	}
	if c.revCache.Add(ep, key) {
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
	dstId, ok := c.revCache.Get(ep)
	if !ok {
		dstId = c.insertNewEndpoint(ep)
	}
	logger.GetLogger().WithField("id", dstId).Info("PolicyID allocated")
	return dstId, nil
}

func (c *Cache) LookupID(lookup uint64) (value Endpoint, ok bool) {
	return c.cache.Get(lookup)
}

func (c *Cache) LookupIP(ip net.IP) (uint64, error) {
	file := filepath.Join(bpf.MapPrefixPath(), endpointIdMap)
	m, err := ebpf.LoadPinnedMap(file, nil)
	if err != nil {
		return 0, err
	}
	defer m.Close()

	var (
		key   endpointKey
		value endpointValue
	)

	key.Addr[0] = uint64(binary.LittleEndian.Uint32(ip[0:]))
	key.Addr[1] = 0

	if err := m.Lookup(&key, &value); err != nil {
		return 0, err
	}
	return value.Id, nil
}

func (c *Cache) AddIpPodMap(epPod *v1alpha1.PodInfo) {
	file := filepath.Join(bpf.MapPrefixPath(), endpointIdMap)
	m, err := ebpf.LoadPinnedMap(file, nil)
	if err != nil {
		logger.GetLogger().WithError(err).WithField("file", file).Warn("Could not open map")
		return
	}
	defer m.Close()

	var (
		key   endpointKey
		value endpointValue
	)

	ep := Endpoint{
		Type:      PodType,
		Kind:      epPod.WorkloadType.Kind,
		Namespace: epPod.WorkloadObject.Namespace,
		Name:      epPod.WorkloadObject.Name,
	}

	// Notice pods may reuse IPs in this case we just update the
	// ip->id entry. However we keep the ID->EP mapping for later
	// use either from gRPC reporting and/or future Pod mappings.
	if idExists, ok := c.revCache.Get(ep); ok {
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
		if err := m.Update(key, value, 0); err != nil {
			logger.GetLogger().WithError(err).Warn("Could not update endpoint map")
			continue
		}
	}
}

func (c *Cache) AddIpDnsMap(dns *tetragon.DnsInfo) {
	if !dns.Response {
		return
	}

	file := filepath.Join(bpf.MapPrefixPath(), endpointIdMap)
	m, err := ebpf.LoadPinnedMap(file, nil)
	if err != nil {
		logger.GetLogger().WithError(err).WithField("file", file).Warn("Could not open map")
		return
	}
	defer m.Close()

	var (
		key   endpointKey
		value endpointValue
	)

	ep := Endpoint{
		Type: DnsType,
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
		if err := m.Lookup(key, &tmp); err == nil {
			epExists, ok := c.cache.Get(tmp.Id)
			if !ok {
				logger.GetLogger().WithError(err).Warn("AddIpDnsMap BPF map and user cache out of sync")
				continue
			}

			newNameSet := strings.Split(ep.Dns, ",")
			oldNameSet := strings.Split(epExists.Dns, ",")
			for _, name := range oldNameSet {
				found := false
				for _, check := range newNameSet {
					if check == name {
						found = true
						break
					}
				}
				if !found {
					newNameSet = append(newNameSet, name)
				}
			}
			ep.Dns = strings.Join(newNameSet, ",")
			c.insertKnownEndpoint(ep, tmp.Id)
		} else {
			// Its possible this EP has a preconfigured ID from
			// a QOS policy. In that case we need to map to that
			// value.
			idExists, ok := c.revCache.Get(ep)
			if ok {
				value.Id = idExists
			} else {
				value.Id = c.insertNewEndpoint(ep)
			}

			if err := m.Update(key, value, 0); err != nil {
				logger.GetLogger().WithError(err).Warn("Could not update endpoint map")
				continue
			}
		}
	}
}

func Get() *Cache {
	initGlobalCache.Do(func() {
		var err error

		cache, err = newCache()
		if err != nil {
			logger.GetLogger().WithError(err).Warn("Could not initialize endpoint model")
		}
	})
	return cache
}

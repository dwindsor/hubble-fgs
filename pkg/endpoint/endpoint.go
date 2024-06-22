package endpoint

import (
	"encoding/binary"
	"net"
	"path/filepath"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/logger"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/isovalent/hubble-fgs/pkg/metrics/dnsmetrics"
	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"
)

type Cache struct {
	cache *lru.Cache[uint64, []string]
}

var (
	cache           *Cache
	id              uint64
	endpointIdMap   = "tg_endpoint_id_map"
	initGlobalCache sync.Once
)

func newCache() (*Cache, error) {
	if cache != nil {
		return cache, nil
	}

	logger.GetLogger().WithField("size", enterpriseOption.Config.EndpointCacheSize).Info("Initializing Endpoint cache")
	lru, err := lru.New[uint64, []string](enterpriseOption.Config.EndpointCacheSize)
	if err != nil {
		return nil, err
	}

	cache = &Cache{cache: lru}
	return cache, nil
}

type endpointKey struct {
	Addr [2]uint64
}

type endpointValue struct {
	Id uint64
}

func (c *Cache) AddIp(dns *tetragon.DnsInfo) {
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

	for _, ip := range dns.Ips {
		if c.cache.Add(id, dns.Names) {
			dnsmetrics.DnsCacheEvictions().Inc()
		}

		ipEncoded := net.ParseIP(ip).To16()
		key.Addr[0] = binary.LittleEndian.Uint64(ipEncoded)
		key.Addr[1] = binary.LittleEndian.Uint64(ipEncoded[8:])
		value.Id = id

		if err := m.Update(key, value, 0); err != nil {
			logger.GetLogger().WithError(err).Warn("Could not update endpoint map")
			continue
		}
		id++
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

package dns

import (
	"fmt"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/logger"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/isovalent/hubble-fgs/pkg/metrics/dnsmetrics"
	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"
)

type Cache struct {
	cache *lru.Cache[string, []string]
}

var (
	LazyDns = false
	cache   *Cache
)

func init() {
	NewCache()
}

func NewCache() (*Cache, error) {
	if cache != nil {
		return cache, nil
	}

	logger.GetLogger().WithField("size", enterpriseOption.Config.DnsCacheSize).Info("Initializing DNS cache")
	lru, err := lru.New[string, []string](enterpriseOption.Config.DnsCacheSize)
	if err != nil {
		return nil, err
	}

	cache = &Cache{cache: lru}
	return cache, nil
}

func ResizeCache(size int) error {
	if cache == nil {
		if _, err := NewCache(); err != nil {
			return err
		}
	}

	cache.cache.Resize(size)
	return nil
}

func (c *Cache) GetIp(ip string) ([]string, error) {
	entry, ok := c.cache.Get(ip)
	if !ok {
		dnsmetrics.DnsCacheErrors(ip, dnsmetrics.DnsCacheErrorTetragonMissingEntry).Inc()
		return nil, fmt.Errorf("no dns entry found")
	}
	return entry, nil
}

func (c *Cache) AddIp(dns *tetragon.DnsInfo) {
	if !dns.Response {
		return
	}

	for _, ip := range dns.Ips {
		if c.cache.Add(ip, dns.Names) {
			dnsmetrics.DnsCacheEvictions().Inc()
		}
	}
}

func CiliumDnsEnabled() bool {
	return LazyDns
}

func Get() *Cache {
	return cache
}

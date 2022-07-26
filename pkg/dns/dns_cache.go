package dns

import (
	"fmt"

	"github.com/cilium/tetragon/api/v1/tetragon"
	lru "github.com/hashicorp/golang-lru"
)

type Cache struct {
	cache *lru.Cache
}

var (
	LazyDns             = false
	dnsDefaultCacheSize = 1024

	cache *Cache
)

func init() {
	NewCache()
}

func NewCache() (*Cache, error) {
	if cache != nil {
		return cache, nil
	}

	lru, err := lru.New(dnsDefaultCacheSize)
	if err != nil {
		return nil, err
	}

	cache = &Cache{cache: lru}
	return cache, nil
}

func (c *Cache) GetIp(ip string) ([]string, error) {
	entry, ok := c.cache.Get(ip)
	if !ok {
		return nil, fmt.Errorf("no dns entry found")
	}
	return entry.([]string), nil
}

func (c *Cache) AddIp(dns *tetragon.DnsInfo) {
	if !dns.Response {
		return
	}

	for _, ip := range dns.Ips {
		c.cache.Add(ip, dns.Names)
	}
}

func CiliumDnsEnabled() bool {
	return LazyDns
}

func Get() *Cache {
	return cache
}

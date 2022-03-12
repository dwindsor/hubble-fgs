package grpc

import (
	"fmt"

	lru "github.com/hashicorp/golang-lru"
	"github.com/isovalent/hubble-fgs/api/v1/fgs"
)

var (
	dnsDefaultCacheSize = 1024
)

type dnsCache struct {
	cache *lru.Cache
}

func newDnsCache() (*dnsCache, error) {
	lru, err := lru.New(dnsDefaultCacheSize)
	if err != nil {
		return nil, err
	}
	return &dnsCache{
		cache: lru,
	}, nil
}

func (c *dnsCache) GetIp(ip string) ([]string, error) {
	entry, ok := c.cache.Get(ip)
	if !ok {
		return nil, fmt.Errorf("no dns entry found")
	}
	return entry.([]string), nil
}

func (c *dnsCache) AddIp(dns *fgs.DnsInfo) {
	if !dns.Response {
		return
	}

	for _, ip := range dns.Ips {
		c.cache.Add(ip, dns.Names)
	}
}

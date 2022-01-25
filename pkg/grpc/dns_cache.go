package grpc

import (
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

func (c *dnsCache) GetIp(ip string) []string {
	// There is a race we still need to handle where
	// dnsEvent is handled after network event due to
	// events happening on different cpus. To fix we
	// will have kernel map we can consult that is
	// done with barriers and order is conserved. The
	// fix is TBD.
	entry, ok := c.cache.Get(ip)
	if !ok {
		return nil
	}
	return entry.([]string)
}

func (c *dnsCache) AddIp(dns *fgs.DnsInfo) {
	if !dns.Response {
		return
	}

	for _, ip := range dns.Ips {
		c.cache.Add(ip, dns.Names)
	}
}

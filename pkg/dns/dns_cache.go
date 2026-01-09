// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package dns

import (
	"fmt"
	"net/netip"
	"sync"

	"github.com/cilium/tetragon/pkg/logger"
	lru "github.com/hashicorp/golang-lru/v2"

	"github.com/cilium/tetragon/api/v1/tetragon"

	"github.com/isovalent/hubble-fgs/pkg/dnsparser"
	"github.com/isovalent/hubble-fgs/pkg/metrics/dnsmetrics"
	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"
)

// Cache is a DNS cache that is backed by a userspace cache in the case we are
// using the userspace DNS parser, and/or a BPF map in the case we use the
// in-kernel BPF DNS parser.
type Cache struct {
	isBPFDNSParserEnabled bool
	// userspaceCache is an LRU populated by the userspace DNS parser
	userspaceCache *lru.Cache[string, []string]
	// ipToDomainMap is a BPF map populated by the BPF DNS parser
	ipToDomainMap *dnsparser.IPToDomainMap
}

var (
	cache    *Cache
	initOnce sync.Once
)

func NewCache() (*Cache, error) {
	if cache != nil {
		return cache, nil
	}

	newCache := &Cache{
		isBPFDNSParserEnabled: enterpriseOption.Config.EnableBPFDNSParser,
	}

	logger.GetLogger().Info("Initializing userspace DNS cache", "size", enterpriseOption.Config.DnsCacheSize)
	var err error
	newCache.userspaceCache, err = lru.New[string, []string](enterpriseOption.Config.DnsCacheSize)
	if err != nil {
		return nil, err
	}

	return newCache, nil
}

func ResizeCache(size int) {
	cache := Get()
	cache.userspaceCache.Resize(size)
}

func (c *Cache) LookupDomains(ip string) ([]string, error) {
	domains := []string{}

	// First lookup the BPF map
	if c.isBPFDNSParserEnabled {
		// Lazy load the BPF maps
		if c.ipToDomainMap == nil {
			ipToDomainMap, err := dnsparser.LoadNewIPToDomainMap()
			if err != nil {
				return nil, fmt.Errorf("failed to load the IP to Domain maps: %w", err)
			}
			c.ipToDomainMap = &ipToDomainMap
		}

		nIP, err := netip.ParseAddr(ip)
		if err != nil {
			return nil, fmt.Errorf("failed to convert IP %q: %w", ip, err)
		}
		//  TODO, can't really use the default inner map here
		domain, err := c.ipToDomainMap.Lookup(dnsparser.DefaultInnerMapID, nIP)
		if err != nil {
			return nil, fmt.Errorf("failed to lookup domain in BPF maps: %w", err)
		}
		if domain != "" {
			domains = append(domains, domain)
		}
	}

	// If the BPF map lookup was unsuccessful, try the userspace cache
	if len(domains) == 0 {
		entries, ok := c.userspaceCache.Get(ip)
		if !ok {
			dnsmetrics.DnsCacheMisses().Inc()
			return domains, nil
		}
		domains = append(domains, entries...)
	}

	return domains, nil
}

func (c *Cache) AddIp(dns *tetragon.DnsInfo) {
	if !dns.Response {
		return
	}

	for _, ip := range dns.Ips {
		if c.userspaceCache.Add(ip, dns.Names) {
			dnsmetrics.DnsCacheEvictions().Inc()
		}
	}
}

func Get() *Cache {
	initOnce.Do(func() {
		var err error
		cache, err = NewCache()
		if err != nil {
			panic(err)
		}
	})
	return cache
}

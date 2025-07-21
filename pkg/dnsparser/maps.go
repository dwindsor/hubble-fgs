// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package dnsparser

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"runtime"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/isovalent/hubble-fgs/pkg/api/dnsapi"
	"github.com/isovalent/hubble-fgs/pkg/endpoint"
	"github.com/isovalent/hubble-fgs/pkg/model/types"
)

const (
	ErrorMapName = "tg_dns_error_map"

	// Process tree related maps
	DomainToIDMapName  = "tg_bpf_domain_map"
	IDToDomainMapName  = "tg_bpf_domain_rev_map"
	IPToIDMapsName     = "tg_dns_ip_id"
	GlobalDNSIDMapName = "tg_glb_dns_id"

	RequestIDMapName = "tg_dns_req_id_map"

	dnsMaxNameSize = 255
)

type IpMap struct {
	ipMap *ebpf.Map
}

type ErrorMap struct {
	errMap *ebpf.Map
}

type DNSID struct {
	ID     uint64
	Source uint64
}

// InitializeDNSMapsWithLocalhost fills the DNS map with localhost related
// entries. Indeed, RFC 6761 specifies in its section 6.3 that:
//
// Users are free to use localhost names as they would any other domain names.
// Users may assume that IPv4 and IPv6 address queries for localhost names will
// always resolve to the respective IP loopback address.
//
// Most well implemented software will not resolve localhost (like curl, see
// https://daniel.haxx.se/blog/2021/05/31/curl-localhost-as-a-local-host/), so
// we need to pre-fill those information since we might not see the DNS pkt.
func InitializeDNSMapsWithLocalhost() error {
	// The ID must come from userspace, and as such, this will only work if
	// the application model is enabled (otherwise the userspace endpoint
	// cache isn't enabled)
	userspaceEndpointCache := endpoint.MustGet()
	id, err := userspaceEndpointCache.AddEndpoint(endpoint.Endpoint{
		Type: tetragon.EndpointType_ENDPOINT_TYPE_DNS,
		Dns:  "localhost",
	})
	if err != nil {
		return fmt.Errorf("failed to add the localhost endpoint: %w", err)
	}

	// Update the IP to ID link
	IPToIDMapsFile := filepath.Join(bpf.MapPrefixPath(), IPToIDMapsName)
	IPToIDMapsRaw, err := ebpf.LoadPinnedMap(IPToIDMapsFile, nil)
	if err != nil {
		return fmt.Errorf("failed loading %s map: %w", IPToIDMapsFile, err)
	}
	defer IPToIDMapsRaw.Close()
	dnsIPToIDMaps := NewIPToIDMaps(IPToIDMapsRaw)

	err = dnsIPToIDMaps.Update(netip.MustParseAddr("127.0.0.1"), DNSID{id, types.DestinationSourceUser})
	if err != nil {
		return fmt.Errorf("failed adding the 127.0.0.1 IP as localhost endpoint: %w", err)
	}
	err = dnsIPToIDMaps.Update(netip.MustParseAddr("::1"), DNSID{id, types.DestinationSourceUser})
	if err != nil {
		return fmt.Errorf("failed adding the ::1 IP as localhost endpoint: %w", err)
	}

	// Update the domain maps (direct and reverse using DomainMap)
	dnsDomainMap := DomainMap{}
	err = dnsDomainMap.Update("localhost", id)
	if err != nil {
		return fmt.Errorf("failed updating the domain<->ID maps with localhost: %w", err)
	}
	dnsDomainMap.CloseMaps()

	return nil
}

func NewErrorMap(m *ebpf.Map) ErrorMap {
	return ErrorMap{
		errMap: m,
	}
}

func (m ErrorMap) ReadUnique() (int, error) {
	entries := m.errMap.Iterate()

	var key uint32
	perCPUValue := make([]uint32, runtime.NumCPU())

	for entries.Next(&key, perCPUValue) {
		for _, value := range perCPUValue {
			if value != 0 {
				return int(key), nil
			}
		}
	}

	if err := entries.Err(); err != nil {
		return 0, fmt.Errorf("failed to iterate over entries: %w", err)
	}

	return 0, nil
}

func (m ErrorMap) ReadAll() ([]int, error) {
	entries := m.errMap.Iterate()

	var key uint32
	perCPUValue := make([]uint32, runtime.NumCPU())
	values := make([]int, m.errMap.MaxEntries())

	for entries.Next(&key, perCPUValue) {
		for _, value := range perCPUValue {
			values[key] += int(value)
		}
	}

	if err := entries.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate over entries: %w", err)
	}

	return values, nil
}

func (m ErrorMap) Clear() error {
	size := int(m.errMap.MaxEntries())
	keys := make([]uint32, size)
	for i := range size {
		keys[i] = uint32(i)
	}

	clearValues := make([]uint32, size*runtime.NumCPU())
	if _, err := m.errMap.BatchUpdate(keys, clearValues, &ebpf.BatchOptions{}); err != nil {
		return fmt.Errorf("failed to batch update values: %w", err)
	}

	return nil
}

func Values[K comparable](m *ebpf.Map) (map[K]string, error) {
	entries := m.Iterate()

	var key K
	value := make([]byte, dnsMaxNameSize+1)

	actualIPMaps := map[K]string{}

	for entries.Next(&key, value) {
		str, _, _ := bytes.Cut(value, []byte("\x00"))
		actualIPMaps[key] = string(str)
	}

	if err := entries.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate over entries: %w", err)
	}

	return actualIPMaps, nil
}

func (m IpMap) Values() (map[dnsapi.IPAddr]string, error) {
	return Values[dnsapi.IPAddr](m.ipMap)
}

type IDToDomainMap struct {
	idToDomainMap *ebpf.Map
}

func NewIDToDomainMap(idToDomainMap *ebpf.Map) IDToDomainMap {
	return IDToDomainMap{
		idToDomainMap: idToDomainMap,
	}
}

func (m IDToDomainMap) Values() (map[DNSID]string, error) {
	return Values[DNSID](m.idToDomainMap)
}

func (m IDToDomainMap) Lookup(id DNSID) (string, error) {
	value := make([]byte, dnsMaxNameSize+1)
	err := m.idToDomainMap.Lookup(&id, &value)
	if err != nil {
		return "", err
	}
	str, _, _ := bytes.Cut(value, []byte("\x00"))
	return string(str), nil
}

func Clear[K comparable](m *ebpf.Map) error {
	var keys []K
	var cur, next K

	for err := m.NextKey(nil, &next); ; err = m.NextKey(cur, &next) {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to iterate keys: %w", err)
		}
		keys = append(keys, next)
		cur = next
	}

	if _, err := m.BatchDelete(keys, &ebpf.BatchOptions{}); err != nil {
		return fmt.Errorf("failed to batch delete keys %v: %w", keys, err)
	}

	return nil
}

func (m IDToDomainMap) Clear() error {
	return Clear[DNSID](m.idToDomainMap)
}

type DomainToIDMap struct {
	domainToIDMap *ebpf.Map
}

func NewDomainToIDMap(domainToIDMap *ebpf.Map) DomainToIDMap {
	return DomainToIDMap{
		domainToIDMap: domainToIDMap,
	}
}

func (m DomainToIDMap) Values() (map[string]DNSID, error) {
	entries := m.domainToIDMap.Iterate()

	key := make([]byte, dnsMaxNameSize+1)
	var value DNSID

	actualIPMaps := map[string]DNSID{}

	for entries.Next(key, &value) {
		str, _, _ := bytes.Cut(key, []byte("\x00"))
		actualIPMaps[string(str)] = value
	}

	if err := entries.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate over entries: %w", err)
	}

	return actualIPMaps, nil
}

func (m DomainToIDMap) Clear() error {
	return Clear[[dnsMaxNameSize + 1]byte](m.domainToIDMap)
}

type IPToIDMaps struct {
	ipToIDMaps *ebpf.Map
}

func NewIPToIDMaps(ipToIDMaps *ebpf.Map) IPToIDMaps {
	return IPToIDMaps{
		ipToIDMaps: ipToIDMaps,
	}
}

func (m IPToIDMaps) Values() (map[netip.Addr]DNSID, error) {
	entries := m.ipToIDMaps.Iterate()

	var key dnsapi.IPAddr
	var value DNSID

	actualMap := map[netip.Addr]DNSID{}

	for entries.Next(&key, &value) {
		actualMap[key.Get()] = value
	}

	if err := entries.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate over entries: %w", err)
	}

	return actualMap, nil
}

func (m IPToIDMaps) Lookup(ip netip.Addr) (DNSID, error) {
	key := dnsapi.NewIPAddr(ip)
	var value DNSID
	err := m.ipToIDMaps.Lookup(&key, &value)
	if err != nil {
		return DNSID{}, err
	}
	return value, nil
}

func (m IPToIDMaps) Clear() error {
	return Clear[dnsapi.IPAddr](m.ipToIDMaps)
}

func (m IPToIDMaps) Update(ip netip.Addr, id DNSID) error {
	var key dnsapi.IPAddr
	key.Set(ip)
	err := m.ipToIDMaps.Update(&key, &id, ebpf.UpdateAny)
	if err != nil {
		return fmt.Errorf("failed to update the key %s with value %d: %w", key, id, err)
	}
	return nil
}

// DomainMap combines domainToID and idToDomain maps for operation that needs to
// be done on both objects.
type DomainMap struct {
	DomainToIDMap
	IDToDomainMap
}

func (m *DomainMap) CloseMaps() error {
	err1 := m.domainToIDMap.Close()
	err2 := m.idToDomainMap.Close()
	return errors.Join(err1, err2)
}

func (m *DomainMap) loadPinnedIDToDomainMap() error {
	if m.idToDomainMap != nil {
		return nil
	}
	idToDomainMapFile := filepath.Join(bpf.MapPrefixPath(), IDToDomainMapName)
	var err error
	m.idToDomainMap, err = ebpf.LoadPinnedMap(idToDomainMapFile, nil)
	if err != nil {
		return err
	}
	return nil
}

func (m *DomainMap) loadPinnedDomainToIDMap() error {
	if m.domainToIDMap != nil {
		return nil
	}
	domainToIDMapFile := filepath.Join(bpf.MapPrefixPath(), DomainToIDMapName)
	var err error
	m.domainToIDMap, err = ebpf.LoadPinnedMap(domainToIDMapFile, nil)
	if err != nil {
		return err
	}
	return nil
}

// Update simultaneously updates the domain to ID and ID to domain maps with the
// domain and ID given.
func (m *DomainMap) Update(domain string, id uint64) error {
	if len(domain) > dnsMaxNameSize {
		return fmt.Errorf("domain is too long: len(%s)=%d > %d", domain, len(domain), dnsMaxNameSize)
	}

	// First lookup that the DNS parser didn't already parsed this domain
	if m.domainToIDMap == nil {
		if err := m.loadPinnedDomainToIDMap(); err != nil {
			return fmt.Errorf("failed to open map %s: %w", DomainToIDMapName, err)
		}
	}

	domainBytes := make([]byte, dnsMaxNameSize+1)
	for i, l := range domain {
		domainBytes[i] = byte(l)
	}
	var idValue DNSID

	err := m.domainToIDMap.Lookup(domainBytes, &idValue)
	// lookup for genuine error apart from ErrKeyNotExist
	if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("failed to lookup the bpf domain rev map: %w", err)
	}
	// entry already exists and was parsed by the DNS parser, "normal"
	// execution flow is errors.Is(err, ebpf.ErrKeyNotExist) here
	if err == nil {
		switch idValue.Source {
		case types.DestinationSourceDNS:
			// The kernel learned the mapping already, but lets teach
			// it the soruceUser variant as well because the policy
			// will be behind the Source User value.
			logger.GetLogger().Debug("overwrite kernel DestinationSourceDNS with DestinationUserSource")
		case types.DestinationSourceUser:
			// This is not an error userspace is using the map as
			// the cache.
			return nil
		}
	}

	if m.idToDomainMap == nil {
		if err := m.loadPinnedIDToDomainMap(); err != nil {
			return fmt.Errorf("failed to open map %s: %w", IDToDomainMapName, err)
		}
	}

	idValueUpdate := DNSID{
		ID:     id,
		Source: types.DestinationSourceUser,
	}
	err = m.domainToIDMap.Update(domainBytes, idValueUpdate, ebpf.UpdateAny)
	if err != nil {
		return fmt.Errorf("failed to update the bpf domain map: %w", err)
	}
	err = m.idToDomainMap.Update(idValueUpdate, domainBytes, ebpf.UpdateAny)
	if err != nil {
		return fmt.Errorf("failed to update the bpf domain rev map: %w", err)
	}

	return nil
}

func (m *DomainMap) Domain(id uint64) (string, error) {
	if m.idToDomainMap == nil {
		if err := m.loadPinnedIDToDomainMap(); err != nil {
			return "", fmt.Errorf("failed to open map %s: %w", IDToDomainMapName, err)
		}
	}

	key := DNSID{
		ID:     id,
		Source: types.DestinationSourceDNS,
	}
	domain := make([]byte, dnsMaxNameSize)
	err := m.idToDomainMap.Lookup(&key, &domain)
	if err != nil {
		return "", fmt.Errorf("failed to lookup domain for id %d: %w", id, err)
	}
	domain, _, _ = bytes.Cut(domain, []byte("\x00"))
	return string(domain), nil
}

type IPToDomainMap struct {
	ipToIDMaps    IPToIDMaps
	idToDomainMap IDToDomainMap
}

func NewIPToDomainMap(ipToIDMaps, idToDomainMap *ebpf.Map) IPToDomainMap {
	return IPToDomainMap{
		ipToIDMaps:    NewIPToIDMaps(ipToIDMaps),
		idToDomainMap: NewIDToDomainMap(idToDomainMap),
	}
}

func LoadNewIPToDomainMap() (IPToDomainMap, error) {
	ipToIDMapsFile := bpf.MapPath(IPToIDMapsName)
	ipToIDMaps, err := ebpf.LoadPinnedMap(ipToIDMapsFile, nil)
	if err != nil {
		return IPToDomainMap{}, fmt.Errorf("fail to load pinned map %s: %w", ipToIDMapsFile, err)
	}

	idToDomainMapFile := bpf.MapPath(IDToDomainMapName)
	idToDomainMap, err := ebpf.LoadPinnedMap(idToDomainMapFile, nil)
	if err != nil {
		return IPToDomainMap{}, fmt.Errorf("fail to load pinned map %s: %w", idToDomainMapFile, err)
	}

	return NewIPToDomainMap(ipToIDMaps, idToDomainMap), nil
}

func (m IPToDomainMap) Close() error {
	err1 := m.idToDomainMap.idToDomainMap.Close()
	err2 := m.ipToIDMaps.ipToIDMaps.Close()
	return errors.Join(err1, err2)
}

func (m IPToDomainMap) Clear() error {
	err1 := m.ipToIDMaps.Clear()
	err2 := m.idToDomainMap.Clear()
	return errors.Join(err1, err2)
}

func (m IPToDomainMap) Values() (map[netip.Addr]string, error) {
	ipToID, err := m.ipToIDMaps.Values()
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve values of ip to ID map: %w", err)
	}

	idToDomain, err := m.idToDomainMap.Values()
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve values of id to domain map: %w", err)
	}

	ipToDomain := map[netip.Addr]string{}
	for ip, id := range ipToID {
		ipToDomain[ip] = idToDomain[id]
	}
	return ipToDomain, nil
}

func (m IPToDomainMap) Lookup(ip netip.Addr) (string, error) {
	id, err := m.ipToIDMaps.Lookup(ip)
	if err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return "", nil
		}
		return "", fmt.Errorf("failed to lookup for IP %s id: %w", ip, err)
	}
	domain, err := m.idToDomainMap.Lookup(id)
	if err != nil {
		return "", fmt.Errorf("failed to find domain associated with ID %d: %w", id, err)
	}
	return domain, nil
}

type GlobalDNSIDMap struct {
	globalDNSIDMap *ebpf.Map
}

func NewGlobalDNSIDMap(globalDNSIDMap *ebpf.Map) GlobalDNSIDMap {
	return GlobalDNSIDMap{
		globalDNSIDMap: globalDNSIDMap,
	}
}

func (m *GlobalDNSIDMap) Reset() error {
	var key uint32
	var value uint64

	return m.globalDNSIDMap.Update(&key, &value, ebpf.UpdateAny)
}

type RequestIDMap struct {
	requestIDMap *ebpf.Map
}

func NewRequestIDMap(requestIDMap *ebpf.Map) RequestIDMap {
	return RequestIDMap{
		requestIDMap: requestIDMap,
	}
}

func (m RequestIDMap) Update(id uint32, domain string) error {
	value := make([]byte, dnsMaxNameSize+1)
	copy(value, domain)
	err := m.requestIDMap.Update(&id, &value, ebpf.UpdateAny)
	if err != nil {
		return fmt.Errorf("failed to update map with key %d and value %s: %w", id, value, err)
	}
	return nil
}

func (m RequestIDMap) Lookup(id uint32) (string, error) {
	value := make([]byte, dnsMaxNameSize+1)
	err := m.requestIDMap.Lookup(&id, &value)
	if err != nil {
		return "", fmt.Errorf("failed to lookup map with key %d: %w", id, err)
	}
	str, _, _ := bytes.Cut(value, []byte("\x00"))
	return string(str), nil
}

func (m RequestIDMap) KeyMissing(id uint32) (bool, error) {
	_, err := m.Lookup(id)
	if err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return true, nil
		}
		return false, err
	}
	return false, nil
}

func (m RequestIDMap) Clear() error {
	return Clear[uint32](m.requestIDMap)
}

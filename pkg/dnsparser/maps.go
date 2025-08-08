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
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/cgroups"
	"github.com/cilium/tetragon/pkg/cgroups/fsscan"
	"github.com/cilium/tetragon/pkg/logger"

	"github.com/cilium/tetragon/api/v1/tetragon"

	"github.com/isovalent/hubble-fgs/pkg/api/dnsapi"
	"github.com/isovalent/hubble-fgs/pkg/endpoint"
	"github.com/isovalent/hubble-fgs/pkg/model/types"
	"github.com/isovalent/hubble-fgs/pkg/option"
)

const (
	ErrorMapName = "tg_dns_error_map"

	// Process tree related maps
	DomainToIDMapName  = "tg_dns_fqdn_id"
	IDToDomainMapName  = "tg_dns_id_fqdn"
	IPToIDMapsName     = "tg_dns_ip_id"
	GlobalDNSIDMapName = "tg_glb_dns_id"

	RequestIDMapName = "tg_dns_req_id_map"

	AllocationIDMapName      = "tg_dns_alloc_id"
	CgroupIDToAllocIDMapName = "tg_dns_cgid_aid"
	KubepodsCgroupIDMapName  = "tg_kpod_cgid"

	PerPodFeatureName = "DNS_PARSER_PER_POD_ENABLED"

	dnsMaxNameSize = 255

	// The max number of pod for the IPToID map resize and the cgidToAllocid.
	// The IPToID index 0 is reserved for the (default) host map.
	MaxNumberOfPods      = 1024
	IPToIDMapsToPrealloc = 10
	DefaultInnerMapID    = 0
)

var IPToIDMapsAllocated uint32

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

// PopulateKubepodsCgroupIDMap scans the filesystem for the "kubepods.slice"
// cgroup directory and writes its cgroup ID into the appropriate map for
// datapath use.
func PopulateKubepodsCgroupIDMap() error {
	mapFile := filepath.Join(bpf.MapPrefixPath(), KubepodsCgroupIDMapName)
	kpodCgidMap, err := ebpf.LoadPinnedMap(mapFile, nil)
	if err != nil {
		return fmt.Errorf("failed to load %q map: %w", mapFile, err)
	}
	defer kpodCgidMap.Close()

	fsscanner := fsscan.New()
	podDir, err := fsscanner.FindPodPath("kubepods.slice")
	if err != nil {
		return fmt.Errorf("failed to find kubepods.slice cgroup directory: %w", err)
	}

	if podDir == "" {
		return errors.New("kubepods.slice was not found in the cgroup hierarchy")
	}

	cgid, err := cgroups.GetCgroupIdFromPath(podDir)
	if err != nil {
		return fmt.Errorf("failed getting the cgroup ID from the cgroup directory: %w", err)
	}

	var zero uint32
	err = kpodCgidMap.Update(zero, cgid, 0)
	if err != nil {
		return fmt.Errorf("failed to update the kubepods cgroupID map with cgid: %w", err)
	}

	return nil
}

// These functions (this one plus the IP to ID related one) fill the DNS map
// with localhost related entries. Indeed, RFC 6761 specifies in its section 6.3
// that:
//
// Users are free to use localhost names as they would any other domain names.
// Users may assume that IPv4 and IPv6 address queries for localhost names will
// always resolve to the respective IP loopback address.
//
// Most well implemented software will not resolve localhost (like curl, see
// https://daniel.haxx.se/blog/2021/05/31/curl-localhost-as-a-local-host/), so
// we need to pre-fill those information since we might not see the DNS pkt.
func PopulateDomainMapsWithLocalhost() error {
	id, err := createOrGetLocalhostID()
	if err != nil {
		return err
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

func createOrGetLocalhostID() (uint64, error) {
	// The ID must come from userspace, and as such, this will only work if
	// the application model is enabled (otherwise the userspace endpoint
	// cache isn't enabled)
	userspaceEndpointCache := endpoint.MustGet()
	id, err := userspaceEndpointCache.AddEndpoint(endpoint.Endpoint{
		Type: tetragon.EndpointType_ENDPOINT_TYPE_DNS,
		Dns:  "localhost",
	})
	if err != nil {
		return 0, fmt.Errorf("failed to add the localhost endpoint: %w", err)
	}
	return id, nil
}

func CreatePreallocInnerIPToIDMaps() error {
	ipToIDMapsFile := filepath.Join(bpf.MapPrefixPath(), IPToIDMapsName)
	ipToIDMapsRaw, err := ebpf.LoadPinnedMap(ipToIDMapsFile, nil)
	if err != nil {
		return fmt.Errorf("failed to load %q map: %w", ipToIDMapsFile, err)
	}
	defer ipToIDMapsRaw.Close()

	ipToIDMaps := NewIPToIDMaps(ipToIDMapsRaw)
	return ipToIDMaps.createPreallocMaps()
}

func PopulateIPToIDMapsWithLocalhost() error {
	ipToIDMapsFile := filepath.Join(bpf.MapPrefixPath(), IPToIDMapsName)
	ipToIDMapsRaw, err := ebpf.LoadPinnedMap(ipToIDMapsFile, nil)
	if err != nil {
		return fmt.Errorf("failed to load %q map: %w", ipToIDMapsFile, err)
	}
	defer ipToIDMapsRaw.Close()

	ipToIDMaps := NewIPToIDMaps(ipToIDMapsRaw)
	return ipToIDMaps.populateWithLocalhostPreallocMaps()
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

func (m IPToIDMaps) populateWithLocalhost(mapID uint32) error {
	id, err := createOrGetLocalhostID()
	if err != nil {
		return err
	}

	// Update the IP to ID link
	err = m.Update(mapID, netip.MustParseAddr("127.0.0.1"), DNSID{id, types.DestinationSourceUser})
	if err != nil {
		return fmt.Errorf("failed adding the 127.0.0.1 IP as localhost endpoint: %w", err)
	}
	err = m.Update(mapID, netip.MustParseAddr("::1"), DNSID{id, types.DestinationSourceUser})
	if err != nil {
		return fmt.Errorf("failed adding the ::1 IP as localhost endpoint: %w", err)
	}

	return nil
}

func (m IPToIDMaps) injectNewInnerMap(mapID uint32) error {
	// Key and value needs to be defined for kernels before (at min)
	// 6.6. For recent versions, KeySize and ValueSize are enough.
	innerDefault, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:    fmt.Sprintf("tg_dns_ip_id_%d", mapID),
		Type:    ebpf.LRUHash,
		KeySize: uint32(unsafe.Sizeof(dnsapi.IPAddr{})),
		Key: &btf.Struct{
			Size: uint32(unsafe.Sizeof(dnsapi.IPAddr{})),
		},
		ValueSize: uint32(unsafe.Sizeof(DNSID{})),
		Value: &btf.Struct{
			Size: uint32(unsafe.Sizeof(DNSID{})),
		},
		MaxEntries: uint32(option.Config.ProcessTreeCacheSize),
	})

	if err != nil {
		return fmt.Errorf("error creating a new inner DNSIPToID map: %w", err)
	}

	err = m.ipToIDMaps.Put(mapID, uint32(innerDefault.FD()))
	if err != nil {
		return fmt.Errorf("error putting the new inner DNSIPToID map: %w", err)
	}
	return nil
}

func (m IPToIDMaps) createPreallocMaps() error {
	mapsToPrealloc := uint32(1)
	if option.Config.EnableBPFDNSPerPod {
		mapsToPrealloc = IPToIDMapsToPrealloc
	}

	for i := uint32(0); i < mapsToPrealloc; i++ {
		err := m.injectNewInnerMap(i)
		if err != nil {
			return fmt.Errorf("failed to create the IP to ID inner map with alloc ID %d: %w", i, err)
		}
		IPToIDMapsAllocated++
	}

	return nil
}

func (m IPToIDMaps) populateWithLocalhostPreallocMaps() error {
	mapsToPrealloc := uint32(1)
	if option.Config.EnableBPFDNSPerPod {
		mapsToPrealloc = IPToIDMapsToPrealloc
	}

	for i := uint32(0); i < mapsToPrealloc; i++ {
		err := m.populateWithLocalhost(i)
		if err != nil {
			return fmt.Errorf("failed to populate the DNS maps with localhost: %w", err)
		}
	}

	return nil
}

func (m IPToIDMaps) openInnerMap(mapID uint32) (*ebpf.Map, error) {
	var innerMapID ebpf.MapID
	err := m.ipToIDMaps.Lookup(mapID, &innerMapID)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve inner map %d: %w", mapID, err)
	}
	dnsIPToIDMap, err := ebpf.NewMapFromID(innerMapID)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve inner map from ID %d: %w", innerMapID, err)
	}
	return dnsIPToIDMap, nil
}

func (m IPToIDMaps) Values(mapID uint32) (map[netip.Addr]DNSID, error) {
	dnsIPToIDMap, err := m.openInnerMap(mapID)
	if err != nil {
		return nil, err
	}
	defer dnsIPToIDMap.Close()

	entries := dnsIPToIDMap.Iterate()

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

func (m IPToIDMaps) Lookup(mapID uint32, ip netip.Addr) (DNSID, error) {
	dnsIPToIDMap, err := m.openInnerMap(mapID)
	if err != nil {
		return DNSID{}, err
	}
	defer dnsIPToIDMap.Close()

	key := dnsapi.NewIPAddr(ip)
	var value DNSID
	err = dnsIPToIDMap.Lookup(&key, &value)
	if err != nil {
		return DNSID{}, err
	}
	return value, nil
}

func (m IPToIDMaps) Clear(mapID uint32) error {
	dnsIPToIDMap, err := m.openInnerMap(mapID)
	if err != nil {
		return err
	}
	defer dnsIPToIDMap.Close()
	return Clear[dnsapi.IPAddr](dnsIPToIDMap)
}

func (m IPToIDMaps) Update(mapID uint32, ip netip.Addr, id DNSID) error {
	dnsIPToIDMap, err := m.openInnerMap(mapID)
	if err != nil {
		return err
	}
	defer dnsIPToIDMap.Close()

	var key dnsapi.IPAddr
	key.Set(ip)
	err = dnsIPToIDMap.Update(&key, &id, ebpf.UpdateAny)
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
	err1 := m.ipToIDMaps.Clear(DefaultInnerMapID)
	err2 := m.idToDomainMap.Clear()
	return errors.Join(err1, err2)
}

func (m IPToDomainMap) Values() (map[netip.Addr]string, error) {
	ipToID, err := m.ipToIDMaps.Values(DefaultInnerMapID)
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
	id, err := m.ipToIDMaps.Lookup(DefaultInnerMapID, ip)
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

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
	"encoding/binary"
	"fmt"
	"net/netip"
	"runtime"

	"github.com/cilium/ebpf"
	"github.com/isovalent/hubble-fgs/pkg/api/dnsapi"
	"github.com/isovalent/hubble-fgs/pkg/model/types"
)

const (
	IPToDomainMapName = "tg_dns_ip_map"
	ErrorMapName      = "tg_dns_error_map"

	// Process tree related maps
	DomainToIDMapName    = "tg_bpf_domain_map"
	IDToDomainMapName    = "tg_bpf_domain_rev_map"
	DNSEndpointIDMapName = "tg_dns_endpoint_id_map"

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

func NewIPMap(m *ebpf.Map) IpMap {
	return IpMap{
		ipMap: m,
	}
}

func Clear[K any](m *ebpf.Map) error {
	entries := m.Iterate()

	keys := []K{}
	var key K
	value := make([]byte, dnsMaxNameSize+1)

	for entries.Next(&key, value) {
		keys = append(keys, key)
	}

	if err := entries.Err(); err != nil {
		return fmt.Errorf("failed to iterate over entries: %w", err)
	}

	if _, err := m.BatchDelete(keys, &ebpf.BatchOptions{}); err != nil {
		return fmt.Errorf("failed to batch delete keys %v: %w", keys, err)
	}

	return nil
}

func (m IpMap) Clear() error {
	return Clear[dnsapi.IPAddr](m.ipMap)
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
	entries := m.domainToIDMap.Iterate()

	keys := [][256]byte{}
	key := make([]byte, dnsMaxNameSize+1)
	var value DNSID

	for entries.Next(key, &value) {
		array := [256]byte{}
		copy(array[:], key)
		keys = append(keys, array)
	}

	if err := entries.Err(); err != nil {
		return fmt.Errorf("failed to iterate over entries: %w", err)
	}

	if _, err := m.domainToIDMap.BatchDelete(keys, &ebpf.BatchOptions{}); err != nil {
		return fmt.Errorf("failed to batch delete keys %v: %w", keys, err)
	}

	return nil
}

type DNSEndpointIDMap struct {
	dnsEndpointIDMap *ebpf.Map
}

func NewDNSEndpointIDMap(dnsEndpointIDMap *ebpf.Map) DNSEndpointIDMap {
	return DNSEndpointIDMap{
		dnsEndpointIDMap: dnsEndpointIDMap,
	}
}

func (m DNSEndpointIDMap) Values() (map[netip.Addr]DNSID, error) {
	entries := m.dnsEndpointIDMap.Iterate()

	var key types.EndpointIdKey
	var value DNSID

	actualMap := map[netip.Addr]DNSID{}

	for entries.Next(&key, &value) {
		// TODO, this only support IPv4 for now, see and use
		// pkg/api/dnsapi/IPAddr for IPv6 support in pstree
		b := [4]byte{}
		binary.LittleEndian.PutUint32(b[:], uint32(key.Addr[0]))
		ip := netip.AddrFrom4(b)
		actualMap[ip] = value
	}

	if err := entries.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate over entries: %w", err)
	}

	return actualMap, nil
}

func (m DNSEndpointIDMap) Clear() error {
	entries := m.dnsEndpointIDMap.Iterate()

	keys := []types.EndpointIdKey{}
	var key types.EndpointIdKey
	var value DNSID

	for entries.Next(&key, &value) {
		keys = append(keys, key)
	}

	if err := entries.Err(); err != nil {
		return fmt.Errorf("failed to iterate over entries: %w", err)
	}

	if _, err := m.dnsEndpointIDMap.BatchDelete(keys, &ebpf.BatchOptions{}); err != nil {
		return fmt.Errorf("failed to batch delete keys %v: %w", keys, err)
	}

	return nil
}

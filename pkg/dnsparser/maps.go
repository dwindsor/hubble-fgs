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
)

const (
	IPToDomainMapName = "tg_dns_ip_map"
	ErrorMapName      = "tg_dns_error_map"
)

type IpMap struct {
	ipMap *ebpf.Map
}

type ErrorMap struct {
	errMap *ebpf.Map
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

type IPAddr struct {
	Addr    [2]uint64
	AFINET6 bool
	_       [7]uint8
}

func newIPAddr(a netip.Addr) IPAddr {
	i := IPAddr{}
	i.Set(a)
	return i
}

func (ip IPAddr) String() string {
	return ip.Get().String()
}

func (ip IPAddr) Get() netip.Addr {
	if ip.AFINET6 {
		b := [16]byte{}
		binary.LittleEndian.PutUint64(b[:], ip.Addr[0])
		binary.LittleEndian.PutUint64(b[8:], ip.Addr[1])
		return netip.AddrFrom16(b)
	}

	b := [4]byte{}
	binary.LittleEndian.PutUint32(b[:], uint32(ip.Addr[0]))
	return netip.AddrFrom4(b)
}

func (ip *IPAddr) Set(addr netip.Addr) {
	if addr.Is4() {
		ip.Addr[0] = uint64(binary.LittleEndian.Uint32(addr.AsSlice()))
	} else {
		ip.Addr[0] = binary.LittleEndian.Uint64(addr.AsSlice()[:8])
		ip.Addr[1] = binary.LittleEndian.Uint64(addr.AsSlice()[8:])
		ip.AFINET6 = true
	}
}

func (m IpMap) Clear() error {
	entries := m.ipMap.Iterate()

	keys := []IPAddr{}
	var key IPAddr
	value := make([]byte, 255)

	for entries.Next(&key, value) {
		keys = append(keys, key)
	}

	if err := entries.Err(); err != nil {
		return fmt.Errorf("failed to iterate over entries: %w", err)
	}

	if _, err := m.ipMap.BatchDelete(keys, &ebpf.BatchOptions{}); err != nil {
		return fmt.Errorf("failed to batch delete keys %v: %w", keys, err)
	}

	return nil
}

func (m IpMap) Values() (map[IPAddr]string, error) {
	entries := m.ipMap.Iterate()

	var key IPAddr
	value := make([]byte, 255)

	actualIPMaps := map[IPAddr]string{}

	for entries.Next(&key, value) {
		str, _, _ := bytes.Cut(value, []byte("\x00"))
		actualIPMaps[key] = string(str)
	}

	if err := entries.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate over entries: %w", err)
	}

	return actualIPMaps, nil
}

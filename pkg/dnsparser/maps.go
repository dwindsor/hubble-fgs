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
	"net"
	"runtime"
	"strings"

	"github.com/cilium/ebpf"
)

const (
	IP4ToDomainMapName = "ip_map"
	ErrorMapName       = "tg_dns_error_map"
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

func (m ErrorMap) String() (string, error) {
	entries := m.errMap.Iterate()
	out := strings.Builder{}

	var key uint32
	perCPUValue := make([]uint32, runtime.NumCPU())

	for entries.Next(&key, perCPUValue) {
		out.WriteString(fmt.Sprintf("key: %d, value: %v\n", key, perCPUValue))
	}

	if err := entries.Err(); err != nil {
		return "", fmt.Errorf("failed to iterate over entries: %w", err)
	}

	return out.String(), nil
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

func (m IpMap) Clear() error {
	entries := m.ipMap.Iterate()

	keys := []uint32{}
	var key uint32
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

func (m IpMap) String() (string, error) {
	entries := m.ipMap.Iterate()

	var key uint32
	value := make([]byte, 255)
	out := strings.Builder{}

	for entries.Next(&key, value) {
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, key)
		str, _, _ := bytes.Cut(value, []byte("\x00"))
		out.WriteString(fmt.Sprintf("key: %s, value: %s\n", ip, string(str)))
	}

	if err := entries.Err(); err != nil {
		return "", fmt.Errorf("failed to iterate over entries: %w", err)
	}

	return out.String(), nil
}

func (m IpMap) Values() (map[uint32]string, error) {
	entries := m.ipMap.Iterate()

	var key uint32
	value := make([]byte, 255)

	actualIPMaps := map[uint32]string{}

	for entries.Next(&key, value) {
		str, _, _ := bytes.Cut(value, []byte("\x00"))
		actualIPMaps[key] = string(str)
	}

	if err := entries.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate over entries: %w", err)
	}

	return actualIPMaps, nil
}

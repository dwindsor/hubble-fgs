// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package lpm

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
)

type KernelLPMTrie4 struct {
	prefix uint32
	addr   uint32
}

type KernelLPMTrie6 struct {
	prefix uint32
	addr   [16]byte
}

type ValueMap struct {
	Data map[[8]byte]struct{}
}

const (
	Addr4lpmMapName = "addr4lpm_map"
	Addr6lpmMapName = "addr6lpm_map"
)

type LPMMap interface {
	Write(ip string, id uint64) error
	Delete(ip string) error
}

type lpmMapImpl struct {
	addr6 *ebpf.Map
	addr4 *ebpf.Map
}

func (lpm *lpmMapImpl) writeIP4(ip string, id uint64) error {
	addr, maskLen, err := parseAddr(ip)
	if err != nil {
		return fmt.Errorf("writeIp4 can not parse %s: %w", ip, err)
	}
	ip4 := binary.LittleEndian.Uint32(addr)
	val := KernelLPMTrie4{prefix: maskLen, addr: ip4}
	if err := lpm.addr4.Update(val, id, 0); err != nil {
		logger.GetLogger().Error(fmt.Sprintf("Failed to program LPM4 %s->%d", ip, id), logfields.Error, err)
	}
	return nil
}

func (lpm *lpmMapImpl) writeIP6(ip string, id uint64) error {
	addr, maskLen, err := parseAddr(ip)
	if err != nil {
		return fmt.Errorf("writeIp6 can not parse %s: %w", ip, err)
	}
	var addrSlice [16]byte
	copy(addrSlice[:], addr)
	val := KernelLPMTrie6{prefix: maskLen, addr: addrSlice}
	if err := lpm.addr6.Update(val, id, 0); err != nil {
		logger.GetLogger().Error(fmt.Sprintf("Failed to program LPM6 %s->%d", ip, id), logfields.Error, err)
	}
	return nil
}

func (lpm *lpmMapImpl) deleteIP4(ip string) error {
	addr, maskLen, err := parseAddr(ip)
	if err != nil {
		return fmt.Errorf("writeIp4 can not parse %s: %w", ip, err)
	}
	ip4 := binary.LittleEndian.Uint32(addr)
	val := KernelLPMTrie4{prefix: maskLen, addr: ip4}
	if err := lpm.addr4.Delete(val); err != nil {
		logger.GetLogger().Error(fmt.Sprintf("Failed to delete LPM4 %s", ip), logfields.Error, err)
	}
	return nil
}

func (lpm *lpmMapImpl) deleteIP6(ip string) error {
	addr, maskLen, err := parseAddr(ip)
	if err != nil {
		return fmt.Errorf("writeIp6 can not parse %s: %w", ip, err)
	}
	var addrSlice [16]byte
	copy(addrSlice[:], addr)
	val := KernelLPMTrie6{prefix: maskLen, addr: addrSlice}
	if err := lpm.addr6.Delete(val); err != nil {
		logger.GetLogger().Error(fmt.Sprintf("Failed to delete LPM6 %s", ip), logfields.Error, err)
	}
	return nil
}

func (lpm *lpmMapImpl) Write(ip string, id uint64) error {
	var err error

	if strings.Contains(ip, ":") {
		err = lpm.writeIP6(ip, id)
	} else {
		err = lpm.writeIP4(ip, id)
	}
	return err
}

func (lpm *lpmMapImpl) Delete(ip string) error {
	var err error

	if strings.Contains(ip, ":") {
		err = lpm.deleteIP6(ip)
	} else {
		err = lpm.deleteIP4(ip)
	}
	return err
}

func parseAddr(v string) ([]byte, uint32, error) {
	ipaddr := net.ParseIP(v)
	if ipaddr != nil {
		ipaddr4 := ipaddr.To4()
		if ipaddr4 != nil {
			return ipaddr4, 32, nil
		}
		ipaddr6 := ipaddr.To16()
		if ipaddr6 != nil {
			return ipaddr6, 128, nil
		}
		return nil, 0, errors.New("IP address is not valid: does not parse as IPv4 or IPv6")
	}
	vParts := strings.Split(v, "/")
	if len(vParts) != 2 {
		return nil, 0, errors.New("IP address is not valid: should be in format ADDR or ADDR/MASKLEN")
	}
	ipaddr = net.ParseIP(vParts[0])
	if ipaddr == nil {
		return nil, 0, errors.New("IP CIDR is not valid: address part does not parse as IPv4 or IPv6")
	}
	maskLen, err := strconv.ParseUint(vParts[1], 10, 32)
	if err != nil {
		return nil, 0, errors.New("IP CIDR is not valid: mask part does not parse")
	}
	ipaddr4 := ipaddr.To4()
	if ipaddr4 != nil {
		if maskLen <= 32 {
			return ipaddr4, uint32(maskLen), nil
		}
		return nil, 0, errors.New("IP CIDR is not valid: IPv4 mask len must be <= 32")
	}
	ipaddr6 := ipaddr.To16()
	if ipaddr6 != nil {
		if maskLen <= 128 {
			return ipaddr6, uint32(maskLen), nil
		}
		return nil, 0, errors.New("IP CIDR is not valid: IPv6 mask len must be <= 128")
	}
	return nil, 0, errors.New("IP CIDR is not valid: address part does not parse")
}

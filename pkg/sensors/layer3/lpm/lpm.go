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
	"fmt"
	"net/netip"

	"github.com/cilium/ebpf"
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
	Write(cidr netip.Prefix, id uint64) error
	Delete(cidr netip.Prefix) error
}

type lpmMapImpl struct {
	addr6 *ebpf.Map
	addr4 *ebpf.Map
}

func (lpm *lpmMapImpl) writeIP4(cidr netip.Prefix, id uint64) error {
	val := KernelLPMTrie4{
		prefix: uint32(cidr.Bits()),
		addr:   binary.LittleEndian.Uint32(cidr.Addr().AsSlice()),
	}
	if err := lpm.addr4.Update(val, id, 0); err != nil {
		return fmt.Errorf("failed to update the addr4 LPM with %s->%d: %w", cidr, id, err)
	}
	return nil
}

func (lpm *lpmMapImpl) writeIP6(cidr netip.Prefix, id uint64) error {
	val := KernelLPMTrie6{prefix: uint32(cidr.Bits()), addr: cidr.Addr().As16()}
	if err := lpm.addr6.Update(val, id, 0); err != nil {
		return fmt.Errorf("failed to update the addr6 LPM with %s->%d: %w", cidr, id, err)
	}
	return nil
}

func (lpm *lpmMapImpl) deleteIP4(cidr netip.Prefix) error {
	val := KernelLPMTrie4{
		prefix: uint32(cidr.Bits()),
		addr:   binary.LittleEndian.Uint32(cidr.Addr().AsSlice()),
	}
	if err := lpm.addr4.Delete(val); err != nil {
		return fmt.Errorf("failed to delete entry %s in LPM4: %w", cidr, err)
	}
	return nil
}

func (lpm *lpmMapImpl) deleteIP6(cidr netip.Prefix) error {
	val := KernelLPMTrie6{prefix: uint32(cidr.Bits()), addr: cidr.Addr().As16()}
	if err := lpm.addr6.Delete(val); err != nil {
		return fmt.Errorf("failed to delete entry %s in LPM6: %w", cidr, err)
	}
	return nil
}

func (lpm *lpmMapImpl) Write(cidr netip.Prefix, id uint64) error {
	var err error

	if cidr.Addr().Is6() {
		err = lpm.writeIP6(cidr, id)
	} else {
		err = lpm.writeIP4(cidr, id)
	}
	return err
}

func (lpm *lpmMapImpl) Delete(cidr netip.Prefix) error {
	var err error

	if cidr.Addr().Is6() {
		err = lpm.deleteIP6(cidr)
	} else {
		err = lpm.deleteIP4(cidr)
	}
	return err
}

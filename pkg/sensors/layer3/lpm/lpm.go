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

const (
	Addr4lpmMapName = "addr4lpm_map"
	Addr6lpmMapName = "addr6lpm_map"
)

type LPMMap interface {
	Write(cidr netip.Prefix, id uint64) error
	Delete(cidr netip.Prefix) error
}

type lpmBackend interface {
	writeIP4(cidr netip.Prefix, id uint64) error
	writeIP6(cidr netip.Prefix, id uint64) error
	deleteIP4(cidr netip.Prefix) error
	deleteIP6(cidr netip.Prefix) error
}

type lpmMapImpl struct {
	lpmBackend

	// refCount keeps track how many records are needing a specific CIDR
	// because the TRIE maps can't account for this.
	refCount map[netip.Prefix]int

	// refIDs keeps track of the mapping between the CIDRs and the ID to
	// avoid cases where you add two times the same CIDR with different IDs
	refIDs map[netip.Prefix]uint64
}

type ebpfBackend struct {
	addr6 *ebpf.Map
	addr4 *ebpf.Map
}

func (b *ebpfBackend) writeIP4(cidr netip.Prefix, id uint64) error {
	val := KernelLPMTrie4{
		prefix: uint32(cidr.Bits()),
		addr:   binary.LittleEndian.Uint32(cidr.Addr().AsSlice()),
	}
	if err := b.addr4.Update(val, id, ebpf.UpdateNoExist); err != nil {
		return fmt.Errorf("failed to update the addr4 LPM with %s->%d: %w", cidr, id, err)
	}
	return nil
}

func (b *ebpfBackend) writeIP6(cidr netip.Prefix, id uint64) error {
	val := KernelLPMTrie6{prefix: uint32(cidr.Bits()), addr: cidr.Addr().As16()}
	if err := b.addr6.Update(val, id, ebpf.UpdateNoExist); err != nil {
		return fmt.Errorf("failed to update the addr6 LPM with %s->%d: %w", cidr, id, err)
	}
	return nil
}

func (b *ebpfBackend) deleteIP4(cidr netip.Prefix) error {
	val := KernelLPMTrie4{
		prefix: uint32(cidr.Bits()),
		addr:   binary.LittleEndian.Uint32(cidr.Addr().AsSlice()),
	}
	if err := b.addr4.Delete(val); err != nil {
		return fmt.Errorf("failed to delete entry %s in LPM4: %w", cidr, err)
	}
	return nil
}

func (b *ebpfBackend) deleteIP6(cidr netip.Prefix) error {
	val := KernelLPMTrie6{prefix: uint32(cidr.Bits()), addr: cidr.Addr().As16()}
	if err := b.addr6.Delete(val); err != nil {
		return fmt.Errorf("failed to delete entry %s in LPM6: %w", cidr, err)
	}
	return nil
}

func (lpm *lpmMapImpl) Write(cidr netip.Prefix, id uint64) error {
	if count, found := lpm.refCount[cidr]; found {
		if lpm.refIDs[cidr] != id {
			return fmt.Errorf("failed to write same CIDR %s with another ID %d, already existing with ID %d", cidr, id, lpm.refIDs[cidr])
		}
		lpm.refCount[cidr] = count + 1
		return nil
	}

	// This might be slow when having a lot of CIDR ranges
	for writtenCIDR := range lpm.refCount {
		if writtenCIDR.Overlaps(cidr) {
			return fmt.Errorf("failed to write entry with key %s, it would overlap existing key %s", cidr, writtenCIDR)
		}
	}

	var err error
	if cidr.Addr().Is6() {
		err = lpm.writeIP6(cidr, id)
	} else {
		err = lpm.writeIP4(cidr, id)
	}
	if err != nil {
		return err
	}
	lpm.refCount[cidr]++
	lpm.refIDs[cidr] = id
	return nil
}

func (lpm *lpmMapImpl) Delete(cidr netip.Prefix) error {
	count, found := lpm.refCount[cidr]
	if !found {
		return nil
	}

	// Sanity check: this should never happen since we only increment from 1
	// and decrement down to 1 before deletion. If triggered, it indicates a bug.
	if count < 1 {
		return fmt.Errorf("ref count for %s %d is too low, this is a bug, please report", cidr, count)
	}

	// There are still records referencing this, do not remove yet
	if count > 1 {
		lpm.refCount[cidr]--
		return nil
	}

	var err error
	if cidr.Addr().Is6() {
		err = lpm.deleteIP6(cidr)
	} else {
		err = lpm.deleteIP4(cidr)
	}
	if err != nil {
		return err
	}
	delete(lpm.refCount, cidr)
	delete(lpm.refIDs, cidr)
	return nil
}

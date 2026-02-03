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
	"errors"
	"net/netip"
	"testing"
)

// mockBPFBackend implements bpfBackend for testing without real BPF maps.
type mockBPFBackend struct {
	ip4Entries map[netip.Prefix]uint64
	ip6Entries map[netip.Prefix]uint64

	// Error injection for testing error paths
	writeIP4Err  error
	writeIP6Err  error
	deleteIP4Err error
	deleteIP6Err error
}

func newMockBPFBackend() *mockBPFBackend {
	return &mockBPFBackend{
		ip4Entries: make(map[netip.Prefix]uint64),
		ip6Entries: make(map[netip.Prefix]uint64),
	}
}

func (m *mockBPFBackend) writeIP4(cidr netip.Prefix, id uint64) error {
	if m.writeIP4Err != nil {
		return m.writeIP4Err
	}
	m.ip4Entries[cidr] = id
	return nil
}

func (m *mockBPFBackend) writeIP6(cidr netip.Prefix, id uint64) error {
	if m.writeIP6Err != nil {
		return m.writeIP6Err
	}
	m.ip6Entries[cidr] = id
	return nil
}

func (m *mockBPFBackend) deleteIP4(cidr netip.Prefix) error {
	if m.deleteIP4Err != nil {
		return m.deleteIP4Err
	}
	delete(m.ip4Entries, cidr)
	return nil
}

func (m *mockBPFBackend) deleteIP6(cidr netip.Prefix) error {
	if m.deleteIP6Err != nil {
		return m.deleteIP6Err
	}
	delete(m.ip6Entries, cidr)
	return nil
}

// hasIP4Entry checks if an IPv4 entry exists in the mock BPF map
func (m *mockBPFBackend) hasIP4Entry(cidr netip.Prefix) bool {
	_, ok := m.ip4Entries[cidr]
	return ok
}

// hasIP6Entry checks if an IPv6 entry exists in the mock BPF map
func (m *mockBPFBackend) hasIP6Entry(cidr netip.Prefix) bool {
	_, ok := m.ip6Entries[cidr]
	return ok
}

// testLPMMap wraps lpmMapImpl with a mockBPFBackend for testing
type testLPMMap struct {
	*lpmMapImpl
	mock *mockBPFBackend
}

func newTestLPMMap() *testLPMMap {
	mock := newMockBPFBackend()
	return &testLPMMap{
		lpmMapImpl: &lpmMapImpl{
			lpmBackend: mock,
			refCount:   make(map[netip.Prefix]int),
			refIDs:     make(map[netip.Prefix]uint64),
		},
		mock: mock,
	}
}

// getRefCount returns the current refcount for a CIDR (for test assertions)
func (t *testLPMMap) getRefCount(cidr netip.Prefix) int {
	return t.refCount[cidr]
}

func TestWrite_IPv4_SingleEntry(t *testing.T) {
	m := newTestLPMMap()
	cidr := netip.MustParsePrefix("10.0.0.0/24")

	err := m.Write(cidr, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !m.mock.hasIP4Entry(cidr) {
		t.Error("expected IPv4 entry to be written to BPF map")
	}
	if m.getRefCount(cidr) != 1 {
		t.Errorf("expected refcount=1, got %d", m.getRefCount(cidr))
	}
}

func TestWrite_IPv6_SingleEntry(t *testing.T) {
	m := newTestLPMMap()
	cidr := netip.MustParsePrefix("2001:db8::/32")

	err := m.Write(cidr, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !m.mock.hasIP6Entry(cidr) {
		t.Error("expected IPv6 entry to be written to BPF map")
	}
	if m.getRefCount(cidr) != 1 {
		t.Errorf("expected refcount=1, got %d", m.getRefCount(cidr))
	}
}

func TestWrite_RefCount_Increment(t *testing.T) {
	m := newTestLPMMap()
	cidr := netip.MustParsePrefix("10.0.0.0/24")

	// First write
	if err := m.Write(cidr, 1); err != nil {
		t.Fatalf("first write failed: %v", err)
	}
	if m.getRefCount(cidr) != 1 {
		t.Errorf("expected refcount=1 after first write, got %d", m.getRefCount(cidr))
	}

	// Second write of same CIDR should increment refcount
	if err := m.Write(cidr, 1); err != nil {
		t.Fatalf("second write failed: %v", err)
	}
	if m.getRefCount(cidr) != 2 {
		t.Errorf("expected refcount=2 after second write, got %d", m.getRefCount(cidr))
	}

	// Third write
	if err := m.Write(cidr, 1); err != nil {
		t.Fatalf("third write failed: %v", err)
	}
	if m.getRefCount(cidr) != 3 {
		t.Errorf("expected refcount=3 after third write, got %d", m.getRefCount(cidr))
	}
}

func TestWrite_RefCount_NoExtraBPFWrites(t *testing.T) {
	m := newTestLPMMap()
	cidr := netip.MustParsePrefix("10.0.0.0/24")

	// First write creates BPF entry
	if err := m.Write(cidr, 1); err != nil {
		t.Fatalf("first write failed: %v", err)
	}

	// Inject error to verify no BPF write happens on refcount increment
	m.mock.writeIP4Err = errors.New("should not be called")

	// Second write should only increment refcount, not call writeIP4
	if err := m.Write(cidr, 1); err != nil {
		t.Fatalf("second write should succeed without BPF write: %v", err)
	}
}

func TestWrite_Overlapping_IPv4(t *testing.T) {
	m := newTestLPMMap()

	// Write a /24 network
	cidr1 := netip.MustParsePrefix("10.0.0.0/24")
	if err := m.Write(cidr1, 1); err != nil {
		t.Fatalf("first write failed: %v", err)
	}

	// Try to write overlapping /16 (contains the /24)
	cidr2 := netip.MustParsePrefix("10.0.0.0/16")
	err := m.Write(cidr2, 2)
	if err == nil {
		t.Error("expected error for overlapping CIDR, got nil")
	}

	// Try to write overlapping /32 (contained in the /24)
	cidr3 := netip.MustParsePrefix("10.0.0.1/32")
	err = m.Write(cidr3, 3)
	if err == nil {
		t.Error("expected error for overlapping CIDR, got nil")
	}

	// Verify original entry still has refcount=1
	if m.getRefCount(cidr1) != 1 {
		t.Errorf("expected refcount=1 for original CIDR, got %d", m.getRefCount(cidr1))
	}
}

func TestWrite_Overlapping_IPv6(t *testing.T) {
	m := newTestLPMMap()

	// Write a /64 network
	cidr1 := netip.MustParsePrefix("2001:db8::/64")
	if err := m.Write(cidr1, 1); err != nil {
		t.Fatalf("first write failed: %v", err)
	}

	// Try to write overlapping /32 (contains the /64)
	cidr2 := netip.MustParsePrefix("2001:db8::/32")
	err := m.Write(cidr2, 2)
	if err == nil {
		t.Error("expected error for overlapping CIDR, got nil")
	}

	// Try to write overlapping /128 (contained in the /64)
	cidr3 := netip.MustParsePrefix("2001:db8::1/128")
	err = m.Write(cidr3, 3)
	if err == nil {
		t.Error("expected error for overlapping CIDR, got nil")
	}
}

func TestWrite_NonOverlapping(t *testing.T) {
	m := newTestLPMMap()

	// Write non-overlapping CIDRs
	cidrs := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/24"),
		netip.MustParsePrefix("10.0.1.0/24"),
		netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("172.16.0.0/12"),
	}

	for i, cidr := range cidrs {
		if err := m.Write(cidr, uint64(i)); err != nil {
			t.Errorf("write failed for %s: %v", cidr, err)
		}
	}

	// Verify all entries exist
	for _, cidr := range cidrs {
		if m.getRefCount(cidr) != 1 {
			t.Errorf("expected refcount=1 for %s, got %d", cidr, m.getRefCount(cidr))
		}
	}
}

func TestWrite_BPFError_IPv4(t *testing.T) {
	m := newTestLPMMap()
	m.mock.writeIP4Err = errors.New("BPF map full")

	cidr := netip.MustParsePrefix("10.0.0.0/24")
	err := m.Write(cidr, 1)
	if err == nil {
		t.Error("expected error from BPF write, got nil")
	}

	// Verify refcount was not incremented on error
	if m.getRefCount(cidr) != 0 {
		t.Errorf("expected refcount=0 after failed write, got %d", m.getRefCount(cidr))
	}
}

func TestWrite_BPFError_IPv6(t *testing.T) {
	m := newTestLPMMap()
	m.mock.writeIP6Err = errors.New("BPF map full")

	cidr := netip.MustParsePrefix("2001:db8::/32")
	err := m.Write(cidr, 1)
	if err == nil {
		t.Error("expected error from BPF write, got nil")
	}

	// Verify refcount was not incremented on error
	if m.getRefCount(cidr) != 0 {
		t.Errorf("expected refcount=0 after failed write, got %d", m.getRefCount(cidr))
	}
}

func TestDelete_IPv4_SingleEntry(t *testing.T) {
	m := newTestLPMMap()
	cidr := netip.MustParsePrefix("10.0.0.0/24")

	// Write then delete
	if err := m.Write(cidr, 1); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	if err := m.Delete(cidr); err != nil {
		t.Fatalf("delete failed: %v", err)
	}

	// Verify BPF entry removed and refcount cleared
	if m.mock.hasIP4Entry(cidr) {
		t.Error("expected IPv4 entry to be deleted from BPF map")
	}
	if m.getRefCount(cidr) != 0 {
		t.Errorf("expected refcount=0 after delete, got %d", m.getRefCount(cidr))
	}
}

func TestDelete_IPv6_SingleEntry(t *testing.T) {
	m := newTestLPMMap()
	cidr := netip.MustParsePrefix("2001:db8::/32")

	// Write then delete
	if err := m.Write(cidr, 1); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	if err := m.Delete(cidr); err != nil {
		t.Fatalf("delete failed: %v", err)
	}

	// Verify BPF entry removed and refcount cleared
	if m.mock.hasIP6Entry(cidr) {
		t.Error("expected IPv6 entry to be deleted from BPF map")
	}
	if m.getRefCount(cidr) != 0 {
		t.Errorf("expected refcount=0 after delete, got %d", m.getRefCount(cidr))
	}
}

func TestDelete_RefCount_Decrement(t *testing.T) {
	m := newTestLPMMap()
	cidr := netip.MustParsePrefix("10.0.0.0/24")

	// Write 3 times
	for i := 0; i < 3; i++ {
		if err := m.Write(cidr, 1); err != nil {
			t.Fatalf("write %d failed: %v", i+1, err)
		}
	}
	if m.getRefCount(cidr) != 3 {
		t.Fatalf("expected refcount=3, got %d", m.getRefCount(cidr))
	}

	// First delete: refcount 3->2, BPF entry remains
	if err := m.Delete(cidr); err != nil {
		t.Fatalf("first delete failed: %v", err)
	}
	if m.getRefCount(cidr) != 2 {
		t.Errorf("expected refcount=2 after first delete, got %d", m.getRefCount(cidr))
	}
	if !m.mock.hasIP4Entry(cidr) {
		t.Error("BPF entry should still exist with refcount > 0")
	}

	// Second delete: refcount 2->1, BPF entry remains
	if err := m.Delete(cidr); err != nil {
		t.Fatalf("second delete failed: %v", err)
	}
	if m.getRefCount(cidr) != 1 {
		t.Errorf("expected refcount=1 after second delete, got %d", m.getRefCount(cidr))
	}
	if !m.mock.hasIP4Entry(cidr) {
		t.Error("BPF entry should still exist with refcount > 0")
	}

	// Third delete: refcount 1->0, BPF entry removed
	if err := m.Delete(cidr); err != nil {
		t.Fatalf("third delete failed: %v", err)
	}
	if m.getRefCount(cidr) != 0 {
		t.Errorf("expected refcount=0 after third delete, got %d", m.getRefCount(cidr))
	}
	if m.mock.hasIP4Entry(cidr) {
		t.Error("BPF entry should be removed when refcount reaches 0")
	}
}

func TestDelete_RefCount_NoBPFDeleteUntilZero(t *testing.T) {
	m := newTestLPMMap()
	cidr := netip.MustParsePrefix("10.0.0.0/24")

	// Write twice
	if err := m.Write(cidr, 1); err != nil {
		t.Fatalf("first write failed: %v", err)
	}
	if err := m.Write(cidr, 1); err != nil {
		t.Fatalf("second write failed: %v", err)
	}

	// Inject error to verify no BPF delete happens when refcount > 1
	m.mock.deleteIP4Err = errors.New("should not be called")

	// First delete should only decrement refcount, not call deleteIP4
	if err := m.Delete(cidr); err != nil {
		t.Fatalf("first delete should succeed without BPF delete: %v", err)
	}
	if m.getRefCount(cidr) != 1 {
		t.Errorf("expected refcount=1, got %d", m.getRefCount(cidr))
	}
}

func TestDelete_NonExistent(t *testing.T) {
	m := newTestLPMMap()
	cidr := netip.MustParsePrefix("10.0.0.0/24")

	// Delete non-existent entry should succeed (no-op)
	err := m.Delete(cidr)
	if err != nil {
		t.Errorf("delete of non-existent entry should succeed, got: %v", err)
	}
}

func TestDelete_BPFError_IPv4(t *testing.T) {
	m := newTestLPMMap()
	cidr := netip.MustParsePrefix("10.0.0.0/24")

	// Write entry
	if err := m.Write(cidr, 1); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	// Inject BPF error
	m.mock.deleteIP4Err = errors.New("BPF delete failed")

	// Delete should fail
	err := m.Delete(cidr)
	if err == nil {
		t.Error("expected error from BPF delete, got nil")
	}

	// Refcount should remain (entry not deleted from tracking)
	if m.getRefCount(cidr) != 1 {
		t.Errorf("expected refcount=1 after failed delete, got %d", m.getRefCount(cidr))
	}
}

func TestDelete_BPFError_IPv6(t *testing.T) {
	m := newTestLPMMap()
	cidr := netip.MustParsePrefix("2001:db8::/32")

	// Write entry
	if err := m.Write(cidr, 1); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	// Inject BPF error
	m.mock.deleteIP6Err = errors.New("BPF delete failed")

	// Delete should fail
	err := m.Delete(cidr)
	if err == nil {
		t.Error("expected error from BPF delete, got nil")
	}

	// Refcount should remain (entry not deleted from tracking)
	if m.getRefCount(cidr) != 1 {
		t.Errorf("expected refcount=1 after failed delete, got %d", m.getRefCount(cidr))
	}
}

func TestWriteDelete_MixedIPv4IPv6(t *testing.T) {
	m := newTestLPMMap()

	cidr4 := netip.MustParsePrefix("10.0.0.0/24")
	cidr6 := netip.MustParsePrefix("2001:db8::/32")

	// Write both
	if err := m.Write(cidr4, 1); err != nil {
		t.Fatalf("IPv4 write failed: %v", err)
	}
	if err := m.Write(cidr6, 2); err != nil {
		t.Fatalf("IPv6 write failed: %v", err)
	}

	// Verify both exist
	if !m.mock.hasIP4Entry(cidr4) {
		t.Error("expected IPv4 entry")
	}
	if !m.mock.hasIP6Entry(cidr6) {
		t.Error("expected IPv6 entry")
	}

	// Delete IPv4, verify IPv6 remains
	if err := m.Delete(cidr4); err != nil {
		t.Fatalf("IPv4 delete failed: %v", err)
	}
	if m.mock.hasIP4Entry(cidr4) {
		t.Error("IPv4 entry should be deleted")
	}
	if !m.mock.hasIP6Entry(cidr6) {
		t.Error("IPv6 entry should remain")
	}

	// Delete IPv6
	if err := m.Delete(cidr6); err != nil {
		t.Fatalf("IPv6 delete failed: %v", err)
	}
	if m.mock.hasIP6Entry(cidr6) {
		t.Error("IPv6 entry should be deleted")
	}
}

func TestWrite_SameCIDR_DifferentID(t *testing.T) {
	m := newTestLPMMap()
	cidr := netip.MustParsePrefix("10.0.0.0/24")

	// First write with id=1
	if err := m.Write(cidr, 1); err != nil {
		t.Fatalf("first write failed: %v", err)
	}

	// Second write with id=2 (same CIDR, different ID) should fail
	err := m.Write(cidr, 2)
	if err == nil {
		t.Error("expected error when writing same CIDR with different ID, got nil")
	}

	// Verify refcount remains 1 (second write was rejected)
	if m.getRefCount(cidr) != 1 {
		t.Errorf("expected refcount=1, got %d", m.getRefCount(cidr))
	}

	// Verify BPF entry still has original ID
	if m.mock.ip4Entries[cidr] != 1 {
		t.Errorf("expected BPF entry id=1, got %d", m.mock.ip4Entries[cidr])
	}
}

func TestWrite_SameCIDR_SameID(t *testing.T) {
	m := newTestLPMMap()
	cidr := netip.MustParsePrefix("10.0.0.0/24")

	// First write with id=1
	if err := m.Write(cidr, 1); err != nil {
		t.Fatalf("first write failed: %v", err)
	}

	// Second write with same id=1 should succeed and increment refcount
	if err := m.Write(cidr, 1); err != nil {
		t.Fatalf("second write with same ID failed: %v", err)
	}

	// Verify refcount is 2
	if m.getRefCount(cidr) != 2 {
		t.Errorf("expected refcount=2, got %d", m.getRefCount(cidr))
	}

	// Verify BPF entry still has original ID
	if m.mock.ip4Entries[cidr] != 1 {
		t.Errorf("expected BPF entry id=1, got %d", m.mock.ip4Entries[cidr])
	}
}

func TestOverlapping_AdjacentCIDRs(t *testing.T) {
	m := newTestLPMMap()

	// Adjacent /24 networks should NOT overlap
	cidr1 := netip.MustParsePrefix("10.0.0.0/24")
	cidr2 := netip.MustParsePrefix("10.0.1.0/24")

	if err := m.Write(cidr1, 1); err != nil {
		t.Fatalf("first write failed: %v", err)
	}
	if err := m.Write(cidr2, 2); err != nil {
		t.Fatalf("second write should succeed for adjacent CIDR: %v", err)
	}

	if m.getRefCount(cidr1) != 1 || m.getRefCount(cidr2) != 1 {
		t.Error("both CIDRs should have refcount=1")
	}
}

func TestOverlapping_ExactSameCIDR(t *testing.T) {
	m := newTestLPMMap()

	cidr := netip.MustParsePrefix("10.0.0.0/24")

	// Writing exact same CIDR should increment refcount, not error
	if err := m.Write(cidr, 1); err != nil {
		t.Fatalf("first write failed: %v", err)
	}
	if err := m.Write(cidr, 1); err != nil {
		t.Fatalf("second write of same CIDR should succeed: %v", err)
	}

	if m.getRefCount(cidr) != 2 {
		t.Errorf("expected refcount=2 for same CIDR, got %d", m.getRefCount(cidr))
	}
}

func TestDelete_AfterOverlapAttempt(t *testing.T) {
	m := newTestLPMMap()

	cidr1 := netip.MustParsePrefix("10.0.0.0/24")
	cidr2 := netip.MustParsePrefix("10.0.0.0/16") // overlaps

	// Write first CIDR
	if err := m.Write(cidr1, 1); err != nil {
		t.Fatalf("first write failed: %v", err)
	}

	// Attempt overlapping write (should fail)
	if err := m.Write(cidr2, 2); err == nil {
		t.Fatal("overlapping write should fail")
	}

	// Delete first CIDR
	if err := m.Delete(cidr1); err != nil {
		t.Fatalf("delete failed: %v", err)
	}

	// Now the previously overlapping CIDR should succeed
	if err := m.Write(cidr2, 2); err != nil {
		t.Fatalf("write should succeed after deleting overlapping CIDR: %v", err)
	}

	if m.getRefCount(cidr2) != 1 {
		t.Errorf("expected refcount=1 for cidr2, got %d", m.getRefCount(cidr2))
	}
}

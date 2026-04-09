// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package ha

import (
	"context"
	"testing"
	"time"

	hastore "github.com/isovalent/hubble-fgs/pkg/nxos/store/ha"
	"github.com/isovalent/hubble-fgs/pkg/nxos/types"
)

// newSettlingManager creates a manager with a small settling window for fast tests.
func newSettlingManager(ctx context.Context) (*manager, hastore.Store) {
	haStore := hastore.NewStore(ctx)
	mgr := NewManager(
		WithHAStoreForManager(haStore),
		WithLocalIP("10.0.0.1"),
		WithDeviceInfoProvider(func() LocalDeviceInfo {
			return LocalDeviceInfo{Model: "N9K-C9364C", SWVersion: "10.5(1)", LbMode: "symmetric_hash"}
		}),
	).(*manager)
	mgr.peerPolicySettlingWindow = 10 * time.Millisecond
	return mgr, haStore
}

// addPeerWithPolicyTrue adds a peer to haStore with HACritPeerPolicy=true (criterion currently OK).
func addPeerWithPolicyTrue(ctx context.Context, haStore hastore.Store, peer string) {
	haStore.SetPeer(ctx, peer, types.HAPeerState{
		IP:                peer,
		Connected:         true,
		MemberCriteria:    make(types.HACriteria),
		ServiceCriteria:   make(types.HACriteria),
		AdjacencyCriteria: make(types.HACriteria),
	})
	haStore.UpdatePeerAdjacencyCriterion(ctx, peer, types.HACritPeerPolicy, true)
}

// policyMismatchInfo returns a HAPeerMember whose PolicyRev differs from the local default ("").
// With local PolicyCheck=false and PolicyRev="", a peer PolicyRev of "v2" causes a mismatch.
func policyMismatchInfo() types.HAPeerMember {
	return types.HAPeerMember{
		Model:     "N9K-C9364C",
		SWVersion: "10.5(1)",
		LbMode:    "symmetric_hash",
		Service:   types.SvcStateSuccess,
		PolicyRev: "v2",
	}
}

// policyMatchInfo returns a HAPeerMember whose PolicyRev matches the local default ("").
func policyMatchInfo() types.HAPeerMember {
	return types.HAPeerMember{
		Model:     "N9K-C9364C",
		SWVersion: "10.5(1)",
		LbMode:    "symmetric_hash",
		Service:   types.SvcStateSuccess,
		PolicyRev: "",
	}
}

// TestPeerPolicySettling_SuppressesDegradation verifies that HACritPeerPolicy
// stays true during the settling window when ComputePeerPolicy returns false.
func TestPeerPolicySettling_SuppressesDegradation(t *testing.T) {
	ctx := context.Background()
	mgr, haStore := newSettlingManager(ctx)
	addPeerWithPolicyTrue(ctx, haStore, "10.0.0.2")

	// Policy mismatch — should start settling but keep criterion true.
	mgr.ProcessMemberInfo(ctx, "10.0.0.2", policyMismatchInfo())

	peer, ok := haStore.Peer("10.0.0.2")
	if !ok {
		t.Fatal("peer not found in store")
	}
	if !peer.AdjacencyCriteria[types.HACritPeerPolicy] {
		t.Error("expected HACritPeerPolicy=true during settling window, got false")
	}
	if _, settling := mgr.peerPolicySettlingStart["10.0.0.2"]; !settling {
		t.Error("expected settling to be active after first mismatch")
	}
}

// TestPeerPolicySettling_AppliesAfterExpiry verifies that HACritPeerPolicy goes
// false after the settling window expires with a persistent mismatch.
func TestPeerPolicySettling_AppliesAfterExpiry(t *testing.T) {
	ctx := context.Background()
	mgr, haStore := newSettlingManager(ctx)
	addPeerWithPolicyTrue(ctx, haStore, "10.0.0.2")

	// First call — starts settling window.
	mgr.ProcessMemberInfo(ctx, "10.0.0.2", policyMismatchInfo())

	// Wait for the window to expire.
	time.Sleep(20 * time.Millisecond)

	// Second call — window has expired, degradation should be applied.
	mgr.ProcessMemberInfo(ctx, "10.0.0.2", policyMismatchInfo())

	peer, ok := haStore.Peer("10.0.0.2")
	if !ok {
		t.Fatal("peer not found in store")
	}
	if peer.AdjacencyCriteria[types.HACritPeerPolicy] {
		t.Error("expected HACritPeerPolicy=false after settling window expired, got true")
	}
	if _, settling := mgr.peerPolicySettlingStart["10.0.0.2"]; settling {
		t.Error("expected settling state to be cleared after expiry")
	}
}

// TestPeerPolicySettling_ClearsOnRecovery verifies that when policy converges
// (ComputePeerPolicy returns true), the settling window is cleared immediately
// and the criterion is updated to true.
func TestPeerPolicySettling_ClearsOnRecovery(t *testing.T) {
	ctx := context.Background()
	mgr, haStore := newSettlingManager(ctx)
	addPeerWithPolicyTrue(ctx, haStore, "10.0.0.2")

	// Start settling.
	mgr.ProcessMemberInfo(ctx, "10.0.0.2", policyMismatchInfo())
	if _, settling := mgr.peerPolicySettlingStart["10.0.0.2"]; !settling {
		t.Fatal("expected settling to be active")
	}

	// Policy converges — settling should clear and criterion stay true.
	mgr.ProcessMemberInfo(ctx, "10.0.0.2", policyMatchInfo())

	if _, settling := mgr.peerPolicySettlingStart["10.0.0.2"]; settling {
		t.Error("expected settling state to be cleared on recovery")
	}
	peer, ok := haStore.Peer("10.0.0.2")
	if !ok {
		t.Fatal("peer not found in store")
	}
	if !peer.AdjacencyCriteria[types.HACritPeerPolicy] {
		t.Error("expected HACritPeerPolicy=true after recovery, got false")
	}
}

// TestPeerPolicySettling_SkipsWhenAlreadyFalse verifies that no settling starts
// when the criterion is already false in the haStore.
func TestPeerPolicySettling_SkipsWhenAlreadyFalse(t *testing.T) {
	ctx := context.Background()
	mgr, haStore := newSettlingManager(ctx)

	// Peer starts with criterion already false (never set to true).
	haStore.SetPeer(ctx, "10.0.0.2", types.HAPeerState{
		IP:                "10.0.0.2",
		Connected:         true,
		MemberCriteria:    make(types.HACriteria),
		ServiceCriteria:   make(types.HACriteria),
		AdjacencyCriteria: make(types.HACriteria),
	})
	haStore.UpdatePeerAdjacencyCriterion(ctx, "10.0.0.2", types.HACritPeerPolicy, false)

	// Policy mismatch — but criterion is already false, so no settling should start.
	mgr.ProcessMemberInfo(ctx, "10.0.0.2", policyMismatchInfo())

	if _, settling := mgr.peerPolicySettlingStart["10.0.0.2"]; settling {
		t.Error("expected no settling when criterion is already false")
	}
}

// TestPeerPolicySettling_PerPeerIndependent verifies that settling state is
// independent for each peer — one peer's mismatch does not affect another.
func TestPeerPolicySettling_PerPeerIndependent(t *testing.T) {
	ctx := context.Background()
	mgr, haStore := newSettlingManager(ctx)
	addPeerWithPolicyTrue(ctx, haStore, "10.0.0.2")
	addPeerWithPolicyTrue(ctx, haStore, "10.0.0.3")

	// Peer 2 gets a mismatch, peer 3 gets a match.
	mgr.ProcessMemberInfo(ctx, "10.0.0.2", policyMismatchInfo())
	mgr.ProcessMemberInfo(ctx, "10.0.0.3", policyMatchInfo())

	// Peer 2 should be settling; peer 3 should not be.
	if _, settling := mgr.peerPolicySettlingStart["10.0.0.2"]; !settling {
		t.Error("expected peer 10.0.0.2 to be settling")
	}
	if _, settling := mgr.peerPolicySettlingStart["10.0.0.3"]; settling {
		t.Error("expected peer 10.0.0.3 not to be settling")
	}

	// Peer 2 criterion should still be true (suppressed); peer 3 criterion should be true.
	peer2, _ := haStore.Peer("10.0.0.2")
	if !peer2.AdjacencyCriteria[types.HACritPeerPolicy] {
		t.Error("expected peer 10.0.0.2 HACritPeerPolicy=true during settling")
	}
	peer3, _ := haStore.Peer("10.0.0.3")
	if !peer3.AdjacencyCriteria[types.HACritPeerPolicy] {
		t.Error("expected peer 10.0.0.3 HACritPeerPolicy=true after match")
	}
}

// TestPeerPolicySettling_ClearedOnDisconnectPeer verifies that DisconnectPeer
// clears the settling state for the disconnected peer.
func TestPeerPolicySettling_ClearedOnDisconnectPeer(t *testing.T) {
	ctx := context.Background()
	mgr, haStore := newSettlingManager(ctx)
	addPeerWithPolicyTrue(ctx, haStore, "10.0.0.2")

	// Start settling.
	mgr.ProcessMemberInfo(ctx, "10.0.0.2", policyMismatchInfo())
	if _, settling := mgr.peerPolicySettlingStart["10.0.0.2"]; !settling {
		t.Fatal("expected settling to be active before disconnect")
	}

	// Inject a mock client directly so DisconnectPeer has a client to close,
	// avoiding the ConnectPeer code path which requires a device store for port lookup.
	mgr.mu.Lock()
	mgr.peerClients["10.0.0.2"] = NewMockClient()
	mgr.mu.Unlock()

	// Disconnect — settling state should be cleared.
	if err := mgr.DisconnectPeer("10.0.0.2"); err != nil {
		t.Fatalf("DisconnectPeer failed: %v", err)
	}

	if _, settling := mgr.peerPolicySettlingStart["10.0.0.2"]; settling {
		t.Error("expected settling state to be cleared after DisconnectPeer")
	}
}

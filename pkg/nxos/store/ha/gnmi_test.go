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

	gnmiproto "github.com/openconfig/gnmi/proto/gnmi"
)

// stringUpdate builds a gNMI Update with a string_val, matching real NX-OS notifications.
func stringUpdate(val string) *gnmiproto.Update {
	return &gnmiproto.Update{
		Val: &gnmiproto.TypedValue{
			Value: &gnmiproto.TypedValue_StringVal{
				StringVal: val,
			},
		},
	}
}

func TestHandleGnmiNotification_AdminStateEnabled(t *testing.T) {
	ctx := context.Background()
	store := NewStore(ctx).(*haStore)

	// Matches real NX-OS: path=".../ha-items/adminState" update=val:{string_val:"enabled"}
	path := "device:/System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/ha-items/adminState"
	store.HandleGnmiNotification(ctx, path, stringUpdate("enabled"), false)

	if store.Enabled() != "enabled" {
		t.Errorf("expected Enabled=enabled, got %q", store.Enabled())
	}
}

func TestHandleGnmiNotification_AdminStateDisabled(t *testing.T) {
	ctx := context.Background()
	store := NewStore(ctx).(*haStore)

	// "shut" trigger sends adminState=disabled
	path := "device:/System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/ha-items/adminState"
	store.HandleGnmiNotification(ctx, path, stringUpdate("disabled"), false)

	if store.Enabled() != "disabled" {
		t.Errorf("expected Enabled=disabled, got %q", store.Enabled())
	}
}

func TestHandleGnmiNotification_SwitchState(t *testing.T) {
	ctx := context.Background()
	store := NewStore(ctx).(*haStore)

	path := "device:/System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/ha-items/nxHaOperState"
	store.HandleGnmiNotification(ctx, path, stringUpdate("ha-ready"), false)

	if store.SwitchState() != "ha-ready" {
		t.Errorf("expected SwitchState=ha-ready, got %q", store.SwitchState())
	}
}

func TestHandleGnmiNotification_SwitchStateNotInitialized(t *testing.T) {
	ctx := context.Background()
	store := NewStore(ctx).(*haStore)

	// "no loopback" / "ha with nothing configured" sends ha-not-initialized
	path := "device:/System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/ha-items/nxHaOperState"
	store.HandleGnmiNotification(ctx, path, stringUpdate("ha-not-initialized"), false)

	if store.SwitchState() != "ha-not-initialized" {
		t.Errorf("expected SwitchState=ha-not-initialized, got %q", store.SwitchState())
	}
}

func TestHandleGnmiNotification_HaSourceIP(t *testing.T) {
	ctx := context.Background()
	store := NewStore(ctx).(*haStore)

	path := "device:/System/sas-items/state-items/agent-items/SasAgent-list[svcName=hypershield]/agentHaSrcIntfAddr"
	store.HandleGnmiNotification(ctx, path, stringUpdate("151.152.1.1"), false)

	if store.HaIP() != "151.152.1.1" {
		t.Errorf("expected HaIP=151.152.1.1, got %q", store.HaIP())
	}
}

func TestHandleGnmiNotification_HaSourceIPCleared(t *testing.T) {
	ctx := context.Background()
	store := NewStore(ctx).(*haStore)

	// Set initial IP
	path := "device:/System/sas-items/state-items/agent-items/SasAgent-list[svcName=hypershield]/agentHaSrcIntfAddr"
	store.HandleGnmiNotification(ctx, path, stringUpdate("151.152.1.1"), false)

	// "no loopback" clears to 0.0.0.0
	store.HandleGnmiNotification(ctx, path, stringUpdate("0.0.0.0"), false)

	if store.HaIP() != "0.0.0.0" {
		t.Errorf("expected HaIP=0.0.0.0, got %q", store.HaIP())
	}
}

func TestHandleGnmiNotification_PeerIpAddr(t *testing.T) {
	ctx := context.Background()
	store := NewStore(ctx).(*haStore)

	// Real NX-OS sends individual ipAddr leaf for each peer
	path := "device:/System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/ha-items/peer-items/HaPeer-list[ipAddr=151.152.1.2]/ipAddr"
	store.HandleGnmiNotification(ctx, path, stringUpdate("151.152.1.2"), false)

	peer, ok := store.Peer("151.152.1.2")
	if !ok {
		t.Fatal("expected peer 151.152.1.2 to exist after ipAddr update")
	}
	if peer.IP != "151.152.1.2" {
		t.Errorf("expected peer.IP=151.152.1.2, got %q", peer.IP)
	}
	// New peer should default to not-started
	if peer.IpConfigState != PeerIpCfgStateNotStarted {
		t.Errorf("expected IpConfigState=%q for new peer, got %q", PeerIpCfgStateNotStarted, peer.IpConfigState)
	}
}

func TestHandleGnmiNotification_PeerIpConfigState(t *testing.T) {
	ctx := context.Background()
	store := NewStore(ctx).(*haStore)

	peerIP := "151.152.1.2"
	basePath := "device:/System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/ha-items/peer-items/HaPeer-list[ipAddr=" + peerIP + "]"

	// First, ipAddr arrives (creates the peer)
	store.HandleGnmiNotification(ctx, basePath+"/ipAddr", stringUpdate(peerIP), false)
	// Then ipConfigState arrives
	store.HandleGnmiNotification(ctx, basePath+"/ipConfigState", stringUpdate("success"), false)

	peer, ok := store.Peer(peerIP)
	if !ok {
		t.Fatal("expected peer to exist")
	}
	if peer.IpConfigState != PeerIpCfgStateSuccess {
		t.Errorf("expected IpConfigState=%q, got %q", PeerIpCfgStateSuccess, peer.IpConfigState)
	}
}

func TestHandleGnmiNotification_PeerIpConfigStateNotStarted(t *testing.T) {
	ctx := context.Background()
	store := NewStore(ctx).(*haStore)

	peerIP := "151.152.1.2"
	basePath := "device:/System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/ha-items/peer-items/HaPeer-list[ipAddr=" + peerIP + "]"

	// Peer initially has success state
	store.HandleGnmiNotification(ctx, basePath+"/ipAddr", stringUpdate(peerIP), false)
	store.HandleGnmiNotification(ctx, basePath+"/ipConfigState", stringUpdate("success"), false)

	// "no loopback" sends ipConfigState=not-started
	store.HandleGnmiNotification(ctx, basePath+"/ipConfigState", stringUpdate("not-started"), false)

	peer, ok := store.Peer(peerIP)
	if !ok {
		t.Fatal("expected peer to exist")
	}
	if peer.IpConfigState != PeerIpCfgStateNotStarted {
		t.Errorf("expected IpConfigState=%q, got %q", PeerIpCfgStateNotStarted, peer.IpConfigState)
	}
}

func TestHandleGnmiNotification_PeerDelete(t *testing.T) {
	ctx := context.Background()
	store := NewStore(ctx).(*haStore)

	peerIP := "151.152.1.2"
	basePath := "device:/System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/ha-items/peer-items/HaPeer-list[ipAddr=" + peerIP + "]"

	// Add peer first
	store.HandleGnmiNotification(ctx, basePath+"/ipAddr", stringUpdate(peerIP), false)

	// "no peer" sends isDelete=true with nil update (without "device:" prefix per logs)
	deletePath := "System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/ha-items/peer-items/HaPeer-list[ipAddr=" + peerIP + "]"
	store.HandleGnmiNotification(ctx, deletePath, nil, true)

	if _, ok := store.Peer(peerIP); ok {
		t.Error("expected peer to be removed after delete notification")
	}
}

func TestHandleGnmiNotification_BootSequence(t *testing.T) {
	ctx := context.Background()
	store := NewStore(ctx).(*haStore)

	peerIP := "151.152.1.2"
	peerBase := "device:/System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/ha-items/peer-items/HaPeer-list[ipAddr=" + peerIP + "]"

	// Simulate boot sequence from logs: adminState, nxHaOperState, peer ipAddr, peer ipConfigState, agentHaSrcIntfAddr
	store.HandleGnmiNotification(ctx,
		"device:/System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/ha-items/adminState",
		stringUpdate("enabled"), false)
	store.HandleGnmiNotification(ctx,
		"device:/System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/ha-items/nxHaOperState",
		stringUpdate("ha-ready"), false)
	store.HandleGnmiNotification(ctx, peerBase+"/ipAddr", stringUpdate(peerIP), false)
	store.HandleGnmiNotification(ctx, peerBase+"/ipConfigState", stringUpdate("success"), false)
	store.HandleGnmiNotification(ctx,
		"device:/System/sas-items/state-items/agent-items/SasAgent-list[svcName=hypershield]/agentHaSrcIntfAddr",
		stringUpdate("151.152.1.1"), false)

	if store.Enabled() != "enabled" {
		t.Errorf("expected Enabled=enabled, got %q", store.Enabled())
	}
	if store.SwitchState() != "ha-ready" {
		t.Errorf("expected SwitchState=ha-ready, got %q", store.SwitchState())
	}
	if store.HaIP() != "151.152.1.1" {
		t.Errorf("expected HaIP=151.152.1.1, got %q", store.HaIP())
	}
	peer, ok := store.Peer(peerIP)
	if !ok {
		t.Fatal("expected peer to exist after boot sequence")
	}
	if peer.IP != peerIP {
		t.Errorf("expected peer.IP=%s, got %q", peerIP, peer.IP)
	}
	if peer.IpConfigState != PeerIpCfgStateSuccess {
		t.Errorf("expected IpConfigState=%q, got %q", PeerIpCfgStateSuccess, peer.IpConfigState)
	}
}

func TestHandleGnmiNotification_NoHaDeleteSequence(t *testing.T) {
	ctx := context.Background()
	store := NewStore(ctx).(*haStore)

	peerIP := "151.152.1.2"
	peerBase := "device:/System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/ha-items/peer-items/HaPeer-list[ipAddr=" + peerIP + "]"

	// Set up initial state (boot)
	store.HandleGnmiNotification(ctx,
		"device:/System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/ha-items/adminState",
		stringUpdate("enabled"), false)
	store.HandleGnmiNotification(ctx, peerBase+"/ipAddr", stringUpdate(peerIP), false)
	store.HandleGnmiNotification(ctx, peerBase+"/ipConfigState", stringUpdate("success"), false)
	store.HandleGnmiNotification(ctx,
		"device:/System/sas-items/state-items/agent-items/SasAgent-list[svcName=hypershield]/agentHaSrcIntfAddr",
		stringUpdate("151.152.1.1"), false)

	// "no ha" sequence from logs: peer delete (nil update), then agentHaSrcIntfAddr=0.0.0.0
	deletePath := "System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/ha-items/peer-items/HaPeer-list[ipAddr=" + peerIP + "]"
	store.HandleGnmiNotification(ctx, deletePath, nil, true)
	store.HandleGnmiNotification(ctx,
		"device:/System/sas-items/state-items/agent-items/SasAgent-list[svcName=hypershield]/agentHaSrcIntfAddr",
		stringUpdate("0.0.0.0"), false)

	if _, ok := store.Peer(peerIP); ok {
		t.Error("expected peer to be removed after 'no ha'")
	}
	if store.HaIP() != "0.0.0.0" {
		t.Errorf("expected HaIP=0.0.0.0 after 'no ha', got %q", store.HaIP())
	}
}

func TestHandleGnmiNotification_HaItemsContainerDelete(t *testing.T) {
	ctx := context.Background()
	store := NewStore(ctx).(*haStore)

	// Set up HA state
	store.HandleGnmiNotification(ctx,
		"device:/System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/ha-items/adminState",
		stringUpdate("enabled"), false)
	store.HandleGnmiNotification(ctx,
		"device:/System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/ha-items/nxHaOperState",
		stringUpdate("ha-ready"), false)
	store.HandleGnmiNotification(ctx,
		"device:/System/sas-items/state-items/agent-items/SasAgent-list[svcName=hypershield]/agentHaSrcIntfAddr",
		stringUpdate("10.1.1.1"), false)
	peerBase := "device:/System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/ha-items/peer-items/HaPeer-list[ipAddr=10.0.0.1]"
	store.HandleGnmiNotification(ctx, peerBase+"/ipAddr", stringUpdate("10.0.0.1"), false)
	// Set HA local state and leader directly (normally set by HA state machine)
	store.SetLeader(ctx, true)
	store.mu.Lock()
	store.localState.HaState = "ha-ready"
	store.localState.CriteriaRecoveryPending = true
	store.mu.Unlock()
	// Set svc-domain criterion that should be preserved
	store.UpdateLocalCriterion(ctx, "dpu_healthy", true)
	// Set svc state that should be preserved
	store.mu.Lock()
	store.localState.SvcState = "success"
	store.localState.CriteriaMet = true
	store.mu.Unlock()

	// Delete of the ha-items container should clear HA state but preserve svc state
	store.HandleGnmiNotification(ctx,
		"System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/ha-items",
		nil, true)

	if store.Enabled() != "" {
		t.Errorf("expected Enabled to be cleared, got %q", store.Enabled())
	}
	if store.SwitchState() != "" {
		t.Errorf("expected SwitchState to be cleared, got %q", store.SwitchState())
	}
	if store.HaIP() != "" {
		t.Errorf("expected HaIP to be cleared, got %q", store.HaIP())
	}
	if peers := store.AllPeers(); len(peers) != 0 {
		t.Errorf("expected all peers to be cleared, got %d", len(peers))
	}
	local := store.Local()
	if local.HaState != "" {
		t.Errorf("expected HaState to be cleared, got %q", local.HaState)
	}
	if local.Leader {
		t.Error("expected Leader=false after ha-items delete")
	}
	// CriteriaMet (svc-domain) must NOT be cleared.
	if !local.CriteriaMet {
		t.Error("expected CriteriaMet to be preserved (svc-domain) after ha-items delete")
	}
}

func TestHandleGnmiNotification_HaItemsContainerDelete_PreservesSvcState(t *testing.T) {
	ctx := context.Background()
	store := NewStore(ctx).(*haStore)

	store.HandleGnmiNotification(ctx,
		"device:/System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/ha-items/adminState",
		stringUpdate("enabled"), false)

	// Simulate svc state set by the HA state machine.
	store.mu.Lock()
	store.localState.SvcState = "success"
	store.localState.SvcStateReason = "all criteria met"
	store.localState.CriteriaMet = true
	store.mu.Unlock()

	// ha-items container deleted
	store.HandleGnmiNotification(ctx,
		"System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/ha-items",
		nil, true)

	local := store.Local()
	if local.SvcState != "success" {
		t.Errorf("expected SvcState preserved, got %q", local.SvcState)
	}
	if !local.CriteriaMet {
		t.Error("expected CriteriaMet preserved after ha-items delete")
	}
}

func TestHandleGnmiNotification_DeleteWithNilUpdate(t *testing.T) {
	ctx := context.Background()
	store := NewStore(ctx).(*haStore)

	// Should not panic when update is nil (as in real delete notifications)
	store.HandleGnmiNotification(ctx,
		"System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/ha-items/peer-items/HaPeer-list[ipAddr=1.2.3.4]",
		nil, true)
}

func TestHandleGnmiNotification_IpConfigStateSkippedWhenPeerUnknown(t *testing.T) {
	ctx := context.Background()
	store := NewStore(ctx).(*haStore)

	// ipConfigState arrives for a peer that doesn't exist yet — should be skipped
	path := "device:/System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/ha-items/peer-items/HaPeer-list[ipAddr=10.0.0.1]/ipConfigState"
	store.HandleGnmiNotification(ctx, path, stringUpdate("success"), false)

	if _, ok := store.Peer("10.0.0.1"); ok {
		t.Error("expected peer NOT to be created from ipConfigState update on unknown peer")
	}
}

func TestHandleGnmiNotification_IpAddrSkippedWhenPeerExists(t *testing.T) {
	ctx := context.Background()
	store := NewStore(ctx).(*haStore)

	peerIP := "151.152.1.2"
	basePath := "device:/System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/ha-items/peer-items/HaPeer-list[ipAddr=" + peerIP + "]"

	// Create peer via ipAddr
	store.HandleGnmiNotification(ctx, basePath+"/ipAddr", stringUpdate(peerIP), false)
	// Set ipConfigState
	store.HandleGnmiNotification(ctx, basePath+"/ipConfigState", stringUpdate("success"), false)

	// Re-send ipAddr — should be a no-op, not reset the peer
	store.HandleGnmiNotification(ctx, basePath+"/ipAddr", stringUpdate(peerIP), false)

	peer, ok := store.Peer(peerIP)
	if !ok {
		t.Fatal("expected peer to still exist")
	}
	if peer.IpConfigState != PeerIpCfgStateSuccess {
		t.Errorf("expected IpConfigState=%q to be preserved, got %q", PeerIpCfgStateSuccess, peer.IpConfigState)
	}
}

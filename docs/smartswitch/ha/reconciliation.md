# VRF & VLAN Reconciliation

`HaReconcile` ensures that GID (Global ID) allocations for VRFs and DPU pinning for VLANs are consistent across the HA pair. It runs after every successful adjacency exchange and is also triggered on in-service transitions via `TriggerHAReconciliation`.

## When Reconciliation Runs

```
haAdjacency()
    └─► HaReconcile(peer, MbrInfo)     // after every adjacency exchange

updtSasSvcSvcinstSvcInstanceFwpolicy()
    └─► TriggerHAReconciliation()       // on out-of-service → in-service transition

TriggerHAReconciliation()
    ├─ Leader:   haAdjacency() for each connected peer (includes reconcile)
    └─ Follower: HaReconcile() against last-known member info
```

## GID Reconciliation

GIDs are numeric identifiers (range 10–4094) assigned to VRFs for service redirect programming. Both peers must use the same GID for the same VRF.

### Phase 1: Same-VRF GID Conflicts

Detects cases where both peers have the same VRF name but different GIDs.

```
For each local VRF with a GID:
    If peer also has this VRF with a different GID:
        ┌──────────┐
        │ Leader?  │
        └────┬─────┘
             ├── yes -> keep local GID
             └── no  -> adopt peer GID (leader wins)
```

### Phase 2: Cross-Peer GID Overlaps

Detects cases where a local VRF's GID collides with a *different* VRF on the peer.

Example: local has `brown:11`, peer has `vrf-ixia1:11` — same GID, different VRF names.

```
Build reverse map: peer GID -> peer VRF name

For each local-only VRF (not on peer):
    If local GID is used by a different VRF on peer:
        ┌──────────┐
        │ Leader?  │
        └────┬─────┘
             ├── yes -> keep local GID
             └── no  -> reallocate via getGid()
                        (reserve peer GID first)
```

### GID Reservation

After reconciliation, all peer GIDs are reserved in `GidsInUse` to prevent future `getGid()` calls from allocating a GID the peer already owns. This prevents new overlaps that would cause reconciliation loops.

### Reconciliation Application

If any GIDs were changed (`recon` map is non-empty):

1. `setGlobalId()` — update NX-OS with new GID assignments
2. `store(allocFname, Alloc)` — persist allocation
3. `doVRFPolicyMapUpdate()` — update VRF policy map

## VLAN Reconciliation

VLAN reconciliation handles DPU pinning conflicts (which DPU handles traffic for a given VLAN).

```
For each VLAN in peer's VlanInfo:
    If local has same VLAN with different DpuPinned:
        ┌──────────┐
        │ Leader?  │
        └────┬─────┘
             ├── yes -> keep local pinning
             └── no  -> adopt peer DPU pinning (leader wins)
```

If any VLANs were reconciled:

1. `store(allocFname, Alloc)` — persist allocation
2. `doVlanPolicyMapUpdate()` — update VLAN policy map
3. If in `StageNormal`: reprogram `setFwPolicyState` + `setServiceRedir` for affected VLANs

## GID Allocation (`getGid` / `doPinning`)

GID allocation is HA-aware:

```
doPinning(vrf):
    If GID not yet allocated for this VRF:
        ┌───────────────────────┐
        │ HA disabled or Leader │
        └──────────┬────────────┘
                   ├── yes -> use AllocPrev, peer alloc, or getGid()
                   └── no  -> prefer peer GID from Ha.Alloc;
                              fallback to AllocPrev/getGid()

getGid(vrf):
    If HA enabled and non-leader:
        Check Ha.Alloc for peer's GID -> use if found
    Local allocation:
        Scan from Alloc.Next, skip GidsInUse entries
        Wrap at 4095 -> 10
```

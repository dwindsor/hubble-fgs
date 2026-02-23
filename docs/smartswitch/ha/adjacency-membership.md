# Adjacency & Membership Management

## The `haSetup` Loop

`haSetup` is a long-running goroutine started during `initiate()`. It drives all periodic HA activity:

```
haSetup()
  │
  ├─ On WaitHa channel signal:
  │    ├─ setLocalHaState()        // push current HA state to NX-OS
  │    ├─ haSetLeader()            // recompute leader status
  │    ├─ If HA just disabled:     disconnect all peers
  │    └─ If HA just enabled:      haConnect() + haAdjacency() for each peer
  │
  ├─ On haTimeout (every 10s):
  │    ├─ haUpdateNx()             // push pending state changes to NX-OS
  │    ├─ For each peer:
  │    │    ├─ haConnect() if not connected
  │    │    └─ haAdjacency() if connected
  │    └─ haCheckAdjMbr()          // expire stale adjacencies/members
  │
  └─ On ctx.Done():  exit
```

## `MbrInfo` Structure

Each adjacency exchange carries a `MbrInfo` payload:

```
MbrInfo
├── SysInfo
│   ├── SerNum    (serial number)
│   ├── Model     (switch model)
│   ├── SwVer     (NX-OS version)
│   ├── Cpa       (CPA/agent version)
│   └── Dpus[]    (DPU name + firmware version)
├── HaInfo
│   ├── Service   (SVC_SUCCESS / SVC_FAILURE)
│   └── Ha        (current HA_STATE)
├── PolInfo
│   ├── Watching  (is controller connected)
│   ├── Revision  (policy revision string)
│   └── Hash      (policy hash)
├── VrfInfo[]     (name, GID, DPU pinning per VRF)
└── VlanInfo[]    (VLAN ID, DPU pinning per VLAN)
```

## `MbrInfo` Validation

When `MbrInfo` is received from a peer, it is validated before the peer is accepted as a partner. Any mismatch sets `isDel = true` and the peer's `HaPeer.State` to `MBR_STATE_HA_FAIL`:

```
Validation checks (in order):
  1. SysInfo, HaInfo, PolInfo must all be non-nil
  2. Model must match local Model
  3. SwVer (NX-OS version) must match
  4. CPA version must match
  5. Peer service state must not be SVC_FAILURE
  6. If local is Watching: policy revision must match
  7. DPU count must match
  8. Each DPU name must exist locally with matching firmware version
```

## Timeout Handling

Runs every `haTimeout` (10s). Expires stale entries:

- **Members**: if `now - mbr.Epoch > mbrTimeout` (30s) → delete member, call `HaUpdatePtnr(isDel=true)`
- **Adjacencies**: if `now - adj.Epoch > adjTimeout` (30s) → delete adjacency, set `HaPeer.State = MBR_STATE_HA_FAIL`, call `setRemoteStatesAdjDown`

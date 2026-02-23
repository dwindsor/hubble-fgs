# Criteria & Readiness

HA readiness is determined by two layers of criteria: **local criteria** (is this switch functional?) and **per-peer criteria** (is the relationship with each peer healthy?).

## Local Criteria

Tracked in `Ha.Local.Criteria` (map of `HaCrit → bool`). **All** must be `true` for `IsFunc` to be `true`.

| Criterion | Key | Set By |
|-----------|-----|--------|
| DPU Health | `HaCritDpuHealth` | `DpuHealth()` — all DPUs healthy and count matches `NumDpu` |
| DPU In-Sync | `HaCritDpuInSync` | `SetInSyncCount()` / `DpuInSync()` — all DPUs have synced state |
| Service Redirect | `HaCritSvcRedir` | `waitForChange()` — service redirect programming complete |
| Debug Override | `HaCritDebugFail` | `HaSetDebugFail()` — injected failure for testing (optional) |

When `SkipDpu` is set, `HaCritDpuHealth` and `HaCritDpuInSync` are initialized to `true` and updates are ignored.

## Per-Peer Criteria

Tracked in `Ha.PeerCriteria` (map of peer IP → `HaPeerCriteria`). **All four** fields must be `true` for `IsOk()` to return `true`.

```
HaPeerCriteria
├── ServiceOk    — peer reports SVC_SUCCESS
├── PolicyOk     — policy revision compatible with peer
├── KeepaliveOk  — all local DPUs have keepalive up
└── BulkSyncOk   — all local DPUs have bulk sync complete (local + peer)
```

## Policy Revision Checks

Policy compatibility depends on the `Watching` state (whether the controller is connected):

```
If local is Watching:
    PolicyOk = (peer.PolInfo.Revision == local.PolRev)

If local is NOT Watching:
    If peer is Watching:
        PolicyOk = (peer.PolInfo.Revision == local.PolRev)
    If peer is NOT Watching:
        PolicyOk = (local.PolRev >= peer.PolInfo.Revision)
    If peer has no PolInfo:
        PolicyOk = true
```

When `Watching` or `PolRev` changes (via `NotifyWatching` / `NotifyPolRev`), all peer policy criteria are recomputed via `recomputeAllPeerPolicyCrit`.

## DPU Keepalive & Bulk Sync

Per-DPU status is tracked in `Ha.DpuKeepalive` and `Ha.DpuBulkSync` maps:

```
DpuBulkSyncStatus
├── LocalDone   — BULK_SYNC_DONE received
└── PeerDone    — BULK_SYNC_PEER_DONE received
```

- **`RegisterDpuHa`** — pre-populates maps when a DPU is discovered (starts as `false`)
- **`UpdateDpuHaKeepalive`** — updates keepalive; when keepalive goes down, bulk sync is also reset
- **`UpdateDpuHaBulkSyncLocal`** / **`UpdateDpuHaBulkSyncPeer`** — update respective bulk sync flags

All updates aggregate across DPUs and propagate to every peer's `KeepaliveOk` / `BulkSyncOk`.

## Readiness Flow Summary

```
Local Criteria (all must pass)          Per-Peer Criteria (any peer must pass)
┌──────────────────────────┐            ┌──────────────────────────┐
│ DpuHealth     ✓          │            │ Peer A:                  │
│ DpuInSync     ✓          │            │   ServiceOk   ✓          │
│ SvcRedir      ✓          │            │   PolicyOk    ✓          │
│ (DebugFail    ✓)         │            │   KeepaliveOk ✓          │
└──────────┬───────────────┘            │   BulkSyncOk  ✓          │
           │                            └──────────┬───────────────┘
           ▼                                       ▼
     IsFunc = true                        anyPeerCriteriaOk = true
           │                                       │
           └───────────────┬───────────────────────┘
                           ▼
                  Partners > 0 ?
                           │
                          yes
                           ▼
                    HA_STATE = HA_READY
```

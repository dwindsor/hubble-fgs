# HA State Transitions

## HA States

The HA subsystem tracks two orthogonal state dimensions pushed to NX-OS via `setLocalHaState` and `setLocalSvcState`:

| State | Meaning |
|-------|---------|
| `HA_STATE_NO_HA` | HA not configured or not initialized |
| `HA_STATE_HA_NOTREADY` | HA configured but not yet ready (initializing, peer lost intentionally, or peer in switchover) |
| `HA_STATE_HA_READY` | Local functional + at least one peer with all criteria passing |
| `HA_STATE_HA_SWITCHOVER` | Local service failure after having been `HA_READY`, or leader handling all traffic due to required criteria mismatch |

## Service States

| State | Meaning |
|-------|---------|
| `SVC_SUCCESS` | All local criteria pass (`IsFunc == true`) |
| `SVC_FAILURE` | At least one local criterion is failing |
| `SVC_UNKNOWN` | HA not configured or adjacency not yet established |

## Peer SVC States

The NX-OS model tracks per-peer SVC state as one of three values:

| Peer SVC State | Condition |
|---------------|-----------|
| `svc_unknown` | Default; adj not up (no HA config, adj timeout, or network failure) |
| `svc_success` | Adj up **and** all per-peer criteria pass |
| `svc_failure` | Adj up **but** at least one per-peer criterion is failing |

## State Machine

```

                                 No peer in HA_READY
                              ┌──────────────────────────────────────┐
                              │   (adj timeout, peer removal,        │
                              │    or criteria change)               │
                              ▼                                      │
              ┌─────────────┐    IsFunc && Partners &&    ┌──────────┴┐
  HA config   │ HA_NOTREADY │──  anyPeerCriteriaOk()  ──►│ HA_READY  │
  ──────────► │             │    (sets EverReady=true)    │           │
              └─────────────┘                             └─────┬─────┘
                     ▲                                          │
                     │                                          │ !IsFunc
                     │  next evaluation                         │
                     │  (EverReady already false)                ▼
                     │                                   ┌─────────────┐
                     └───────────────────────────────────┤HA_SWITCHOVER│
                                                         │             │
                                                         └─────────────┘
                                                          (EverReady
                                                         reset to false)

Additionally, required criteria failures (see below) can drive the leader
to HA_SWITCHOVER or the follower to HA_NOTREADY from any state.
```

## NX State Logic

```
  Local SVC State                          Peer SVC State
  (set by haUpdateNxState)                 (set by setRemoteSvcState)
  ========================                 ==========================

                                           ┌─────────────┐
                                           │ SVC_UNKNOWN │◄─────────┐
                                           └──────┬──────┘          │
                                                  │                 │
                                                  │ adj up          │ adj timeout /
                                                  │                 │ network failure
                                                  ▼                 │
  ┌─────────────┐                          ┌─────────────┐          │
  │ SVC_SUCCESS │                          │ SVC_SUCCESS │──────────┤
  └──────┬──────┘                          └──────┬──────┘          │
         │      ▲                                 │      ▲          │
         │      │                                 │      │          │
         │      │ IsFunc                          │      │ criteria │
         │      │ restored                        │      │ restored │
         │      │                                 │      │          │
         ▼      │                                 ▼      │          │
  ┌─────────────┐                          ┌─────────────┐          │
  │ SVC_FAILURE │                          │ SVC_FAILURE │──────────┘
  └─────────────┘                          │  (+ reason) │
                                           └─────────────┘

  Transitions:                             Transitions:
  ─────────────                            ─────────────
  SUCCESS → FAILURE : !IsFunc              UNKNOWN → SUCCESS : adj up +
                      (local criteria                          peerCrit.IsOk()
                      fail), or            UNKNOWN → FAILURE : adj up +
                      follower +                               !peerCrit.IsOk()
                      required crit fail   SUCCESS → FAILURE : any per-peer
  FAILURE → SUCCESS : IsFunc restored                          criterion fails
                      (+ hold-down) and    SUCCESS → UNKNOWN : adj timeout /
                      not follower with                        network failure
                      required crit fail   FAILURE → SUCCESS : all per-peer
                                                               criteria restored
  Note: haUpdateNxState never produces     FAILURE → UNKNOWN : adj timeout /
  SVC_UNKNOWN. That state is only the                          network failure
  NX-OS default before HA initializes.
                                           Note: Peer svc state is derived from
  Leader stays SVC_SUCCESS even during     adj status + peerCrit.IsOk().
  required criteria failures (handles      SVC_FAILURE includes a reason string
  all traffic via HA_SWITCHOVER).          (model mismatch, NX-OS version,
  Follower enters SVC_FAILURE and          CPA version, DPU count, DPU name/
  yields all traffic.                      firmware, or transient condition).
```

## The `EverReady` Latch

`EverReady` is a one-way latch that records whether the system has ever reached `HA_READY`:

- **Set to `true`** the first time `HA_READY` is reached
- **Keeps `HA_READY` sticky** — if local is still functional and at least one peer is still `HA_READY`, the system stays in `HA_READY` rather than dropping to `HA_NOTREADY`
- **Reset to `false`** on any terminal transition: `HA_SWITCHOVER` (local failure while in `HA_READY`), `HA_NOTREADY` (no peer in `HA_READY` or local failure without active peer), or `delHa` (full HA teardown)
- **`HA_SWITCHOVER` normally only from `HA_READY`** — if the switch is already `HA_NOTREADY` when local criteria fail, it stays `HA_NOTREADY` since there is no active peer to take over traffic. Exception: required criteria failures drive the leader to `HA_SWITCHOVER` from any state.
- **`HA_SWITCHOVER` is transient** — on the next evaluation, the system transitions to `HA_NOTREADY` (since `EverReady` has been reset and `currentHaState` is no longer `HA_READY`)

## Required Criteria Failures (Hard Failures)

Some criteria mismatches indicate HA can **never** work between two peers regardless of transient conditions (e.g., model mismatch, NX-OS version mismatch, CPA version mismatch, DPU count mismatch, DPU name or firmware mismatch). These are called **required criteria failures** and trigger immediate action:

| Condition | Peer SVC State | Local HA State | Local SVC State |
|-----------|---------------|----------------|-----------------|
| No HA config / adj not established | `svc_unknown` | — | — |
| Adj timeout / network failure | `svc_unknown` | (existing logic) | (existing logic) |
| Adj success, all criteria pass | `svc_success` | `HA_READY` | `SVC_SUCCESS` |
| Required criteria fail (leader) | `svc_failure` + reason | `HA_SWITCHOVER` | `SVC_SUCCESS` |
| Required criteria fail (follower) | `svc_failure` + reason | `HA_NOTREADY` | `SVC_FAILURE` |
| Transient criteria fail | `svc_failure` + reason | (existing logic) | (existing logic) |

## Fail-Fast Detection

When the follower detects a required criteria failure, it returns `ADJ_FAILURE` with its `MbrInfo` in the gRPC response. The leader processes this `MbrInfo` via `HaSetMbrInfo`, independently detects the same mismatch, and transitions in the **same adjacency cycle** — no timeout waiting required.

```
Leader → Follower (adj request with MbrInfo)
   ↓
Follower: HaSetMbrInfo(leader's info) → detects model mismatch
   → sets own state: SVC_FAILURE + HA_NOTREADY (follower)
   → returns ADJ_FAILURE + reason + follower's MbrInfo
   ↓
Leader: receives ADJ_FAILURE
   → processes follower's MbrInfo via HaSetMbrInfo
   → detects model mismatch independently
   → sets own state: SVC_SUCCESS + HA_SWITCHOVER (leader)

Both sides transition in the SAME adj cycle. No timeout waiting.
```

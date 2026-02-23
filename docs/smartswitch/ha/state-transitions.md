# HA State Transitions

## HA States

The HA subsystem tracks two orthogonal state dimensions pushed to NX-OS via `setLocalHaState` and `setLocalSvcState`:

| State | Meaning |
|-------|---------|
| `HA_STATE_NO_HA` | HA not configured or not initialized |
| `HA_STATE_HA_NOTREADY` | HA configured but not yet ready (initializing, peer lost intentionally, or peer in switchover) |
| `HA_STATE_HA_READY` | Local functional + at least one peer with all criteria passing |
| `HA_STATE_HA_SWITCHOVER` | Local service failure after having been `HA_READY` |

## Service States

| State | Meaning |
|-------|---------|
| `SVC_SUCCESS` | All local criteria pass (`IsFunc == true`) |
| `SVC_FAILURE` | At least one local criterion is failing |

## State Machine

```

                                Peer config removal
                              (NO_HA signal received)
                    ┌──────────────────────────────────────────┐
                    │       No other peers in HA_READY         |
                    ▼                                          │
              ┌─────────────┐    IsFunc && Partners &&    ┌────┴─────┐
  HA config   │ HA_NOTREADY │───  anyPeerCriteriaOk() ──► │ HA_READY │
  ──────────► │             │    (sets EverReady=true)    │          │
              └─────────────┘                             └────┬─────┘
                                                               │
                                                               │ !IsFunc &&
                                                               │  EverReady
                                                               ▼
                                                        ┌─────────────┐
                                                        │HA_SWITCHOVER│
                                                        │             │
                                                        └─────────────┘
                                                          (EverReady
                                                        reset to false)

```

## NX State Logic

This is the primary state derivation function, called whenever local criteria or peer state changes:

```
if IsFunc:
    SvcState = SVC_SUCCESS
    if Partners > 0 && anyPeerCriteriaOk():
        HaState = HA_READY
        EverReady = true  (latched, never goes back to false here)
    else if EverReady:
        if anyPeerInHaReady():
            HaState = HA_READY  (at least one peer still in active-active)
        else:
            HaState = HA_NOTREADY  (no peer in HA_READY — no longer active-active)
            EverReady = false
    else:
        HaState = HA_NOTREADY
else:
    SvcState = SVC_FAILURE
    if currentHaState == HA_READY:
        HaState = HA_SWITCHOVER  (was active with peer — peer takes over)
        EverReady = false
    else:
        HaState = HA_NOTREADY   (no active peer to switchover to)
        EverReady = false
```

## The `EverReady` Latch

`EverReady` is a one-way latch that records whether the system has ever reached `HA_READY`:

- **Set to `true`** the first time `HA_READY` is reached
- **Keeps `HA_READY` sticky** — if local is still functional and at least one peer is still `HA_READY`, the system stays in `HA_READY` rather than dropping to `HA_NOTREADY`
- **Reset to `false`** on any terminal transition: `HA_SWITCHOVER` (local failure while in `HA_READY`), `HA_NOTREADY` (no peer in `HA_READY` or local failure without active peer), or `delHa` (full HA teardown)
- **`HA_SWITCHOVER` only from `HA_READY`** — if the switch is already `HA_NOTREADY` when local criteria fail, it stays `HA_NOTREADY` since there is no active peer to take over traffic

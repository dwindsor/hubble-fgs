# Leader Election & Peer Management

## Leader Election

Leader election is deterministic and based on IP address comparison. The node with the **highest HA IP** is the leader.

### Leader Responsibilities

| Responsibility | Leader | Follower |
|----------------|--------|----------|
| Initiate gRPC connections (`haConnect`) | Yes | No (skips) |
| Send `Adjacency` RPCs | Yes | No |
| GID conflict resolution | Keeps own GID | Adopts peer's GID |
| VLAN pinning conflict resolution | Keeps own pinning | Adopts peer's pinning |
| GID allocation for new VRFs | Local allocation | Prefers peer's GID from `Ha.Alloc` |

### Follower Startup Delay

When the follower starts, it waits up to `2 * haTimeout` (20s) before programming service redirects, giving the leader time to establish adjacency and share allocations.

## Graceful HA Removal

When HA is intentionally removed (config delete, peer delete), the system signals `HA_STATE_NO_HA` to the peer so it transitions to `HA_NOTREADY` instead of waiting for adjacency timeout and incorrectly going to `HA_SWITCHOVER`.

### Leader vs Follower Removal

- **Leader** (has gRPC client): sends `NO_HA` via `haNotifyRemovalLocked`, then disconnects
- **Follower** (no gRPC client): notification is skipped; the follower's gRPC server returns `NO_HA` in the `AdjResponse` when the leader sends its next adjacency tick

### Adjacency Response Handling

The leader also checks for `NO_HA` in failed adjacency responses.

## Full HA Teardown

Called when the entire HA configuration is deleted. Resets all HA state:

```
delHa():
    1. Notify all peers (haNotifyRemovalLocked)
    2. Disconnect all peers (haDisconnectLocked)
    3. Clear all state:
       - HaIp = ""
       - configured, enabled, operUp = false
       - peers, Adjacencies, Members, Alloc = empty
       - PeerCriteria, Partners = empty
       - HaState = HA_NOTREADY
       - IsLeader = false, EverReady = false
    4. setLocalHaStateToNotReady()
    5. updateHaConfig()
```

## HA Configuration from NX-OS

HA is configured via `updtSasSvcSvcinstSvcInstanceHa`:

| Field | Effect |
|-------|--------|
| `AdminState = enabled` | `SetHaEnabled(true)` |
| `AdminState = disabled` | `SetHaEnabled(false)` |
| `NxHaOperState = ha_ready` | `SetHaOperUp(true)` |
| `NxHaOperState = ha_not_initialized / ha_disabled / ha_ports_not_ready / ha_ip_unavailable` | `SetHaOperUp(false)` |

HA is considered **enabled** when `haIsEnabled` returns `true`: both `GetHaEnabled()` and `GetHaOperUp()` must be `true`.

HA is considered **configured** when `haIsConfigured` returns `true`: `GetHaConfigured()` is `true` (set when `ha-items` is received).

## Config Propagation to DPUs

`updateHaConfig` pushes HA configuration to DPUs via the config library:

```
HaConfig:
    HaIp:     local HA IP
    Peers:    [{Ip, MinPort, MaxPort}]
    Enabled:  configured && operUp && peers > 0
    FlowSync: enabled && haEnabled
```

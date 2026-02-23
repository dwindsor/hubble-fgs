# High Availability (HA) Overview

The AGW HA subsystem enables two SmartSwitch peers to form an active-active pair so that if one switch loses service capability, the other can take over traffic forwarding.

## Architecture

```
┌───────────────────────┐         gRPC (port 8883)        ┌──────────────────────┐
│    SmartSwitch A      │◄───────────────────────────────►│   SmartSwitch B      │
│                       │         Adjacency RPCs          │                      │
│  ┌─────────────────┐  │                                 │  ┌────────────────┐  │
│  │   AGW (Nxos)    │  │   MbrInfo exchange:             │  │   AGW (Nxos)   │  |
│  │  ┌───────────┐  │  │   - SysInfo (model, version)    │  │  ┌───────────┐ │  │
│  │  │ Ha struct │  │  │   - HaInfo  (state, service)    │  │  │ Ha struct │ │  │
│  │  └───────────┘  │  │   - PolInfo  (revision, hash)   │  │  └───────────┘ |  │
│  └─────────────────┘  │   - VrfInfo  (GID allocations)  │  └────────────────┘  |
│          │            │   - VlanInfo (DPU pinning)      │          │           │
│     ┌────┴────┐       │                                 │     ┌────┴────┐      │
│     │DPU1 DPU2│       │                                 │     │DPU1 DPU2│      │
│     └─────────┘       │                                 │     └─────────┘      │
└───────────────────────┘                                 └──────────────────────┘
```

## HA Lifecycle

```
initiate() ──► haInit() ──► haSetup() (goroutine, runs forever)
                  │
                  ├─ getLocalSvcState()    // read current NX-OS service state
                  ├─ getLocalHaState()     // read current NX-OS HA state
                  ├─ getHaIp()             // read HA IP from NX-OS
                  ├─ updtSasSvcSvcinstSvcInstanceHa()  // parse ha-items config
                  └─ haConnect() + haAdjacency()       // initial peer contact
```

## Detailed Documentation

- **[State Transitions](state-transitions.md)** — HA state machine (`HA_NOTREADY`, `HA_READY`, `HA_SWITCHOVER`), service states, and the `EverReady` latch
- **[Adjacency & Membership](adjacency-membership.md)** — The `haSetup` loop, adjacency exchange, `MbrInfo` validation, and timeout handling
- **[Criteria & Readiness](criteria-readiness.md)** — Local criteria (`HaCrit`), per-peer criteria (`HaPeerCriteria`), `IsFunc` computation, and policy revision checks
- **[VRF & VLAN Reconciliation](reconciliation.md)** — GID conflict resolution, cross-peer overlap detection, VLAN DPU pinning reconciliation
- **[Leader Election & Peer Management](leader-peer-management.md)** — Leader selection, peer add/remove, graceful HA removal via `NO_HA` signaling

## Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `haTimeout` | 10s | Adjacency tick interval in `haSetup` |
| `haPort` | 8883 | gRPC port for HA adjacency |
| `nxUpdateTimeout` | 30s | Delay before pushing state changes to NX-OS |
| `adjTimeout` | 30s | Adjacency expiry timeout |
| `mbrTimeout` | 30s | Member expiry timeout |

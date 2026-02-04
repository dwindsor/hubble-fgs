# Tetragon Enterprise Agent Instructions

> **Hubble-FGS** is Tetragon Enterprise - an eBPF-based security observability platform extending OSS Tetragon with L7 monitoring (HTTP, TLS, DNS), network events, file monitoring, and application modeling.

## Critical Architecture Rules

- **OSS submodule**: `modules/tetragon-oss/` - **never edit directly**, use `make oss-sync`
- **Import paths**: Enterprise = `github.com/isovalent/hubble-fgs/pkg/*`, OSS = `github.com/cilium/tetragon/pkg/*`
- **go.mod replace directives** redirect `github.com/cilium/tetragon/*` → local paths - know which you're importing

## Essential Commands

> **Note:** Always use `LOCAL_CLANG=1` when building BPF programs. The default Docker-based clang container causes network changes that interfere with Copilot connectivity.

```bash
make oss-init                    # First-time: initialize OSS submodule
make LOCAL_CLANG=1               # Full build (OSS + Enterprise)
make tetragon-bpf LOCAL_CLANG=1  # Build BPF programs only
make test                        # Unit tests
sudo make bpf-test               # BPF tests (requires root)
make codegen                     # After proto/CRD changes
make validate                    # Full validation (test + lint + format) - slow
make vendor                      # Update vendored dependencies
sudo ./tetragon --bpf-lib bpf/objs  # Run locally
./tetra getevents                # Stream events
```

## Key Directories

| Path | Purpose |
|------|---------|
| `modules/tetragon-oss/` | OSS Tetragon git submodule (read-only) |
| `pkg/sensors/` | Enterprise sensors (file, http, layer3, sockmap) |
| `bpf/` | Enterprise eBPF programs |
| `api/` | Enterprise API extensions |
| `cmd/tetragon/` | Main Tetragon agent entry point |
| `cmd/tetra/` | Tetragon CLI |
| `cmd/agw/`, `cmd/fwa/` | SmartSwitch AGW/FWA agents |
| `operator/` | Kubernetes operator |
| `vendor/` | Vendored dependencies (DO NOT EDIT) |

## Go Module Architecture

The enterprise codebase uses **replace directives** to compose OSS and enterprise code:

```go
// go.mod replace directives
github.com/cilium/tetragon => ./modules/tetragon-oss  // OSS submodule
github.com/cilium/tetragon/api => ./api               // Enterprise API (extends OSS)
github.com/cilium/tetragon/pkg/k8s => ./pkg/k8s       // Enterprise K8s types
```

**Critical**: When importing packages, understand which version you're getting:
- `github.com/cilium/tetragon/pkg/sensors` → Resolves to OSS implementation in submodule
- `github.com/isovalent/hubble-fgs/pkg/sensors` → Enterprise-specific sensors
- `github.com/cilium/tetragon/api/v1/tetragon` → Resolves to enterprise `./api/v1` (due to replace)

## Sensor Registration Pattern

Enterprise sensors register in `init()`:

```go
func init() {
    sensors.RegisterPolicyHandlerAtInit("my-sensor", &myHandler{})
    observer.RegisterEventHandlerAtInit(ops.MSG_OP_MY_EVENT, handleMyEvent)
}
```

## Event Processing Architecture

1. **BPF Programs** generate events and send to userspace via perf/ring buffers
2. **Event Handlers** process events and convert to protobuf
3. **Process Manager** calls `HandleMessage()` on each event
4. **gRPC Stream** sends `GetEventsResponse` to clients

```go
func (msg *MsgExecveEventUnix) HandleMessage() *tetragon.GetEventsResponse {
    proc := GetProcessExec(msg)
    return &tetragon.GetEventsResponse{
        Event: &tetragon.GetEventsResponse_ProcessExec{ProcessExec: proc},
    }
}
```

## TracingPolicy Structure

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: my-policy
spec:
  kprobes:        # Kernel probes
    - call: "tcp_connect"
      syscall: false
      return: true
      args:
        - index: 0
          type: "sock"
      selectors:
        - matchBinaries:
            - operator: "In"
              values: ["curl", "wget"]
  uprobes: [...]  # User probes
  tracepoints: [...] # Tracepoint hooks
  lsmhooks: [...] # LSM hooks
```

## Code Style

**Import order:** stdlib → external → local (`github.com/isovalent/hubble-fgs`)

```go
package mypackage

import (
    "context"

    "github.com/cilium/tetragon/pkg/sensors"

    "github.com/isovalent/hubble-fgs/pkg/model"
)
```

## Commit Conventions

Use [Conventional Commits](https://www.conventionalcommits.org) format with **50/72 line limits**:
- **Subject line**: Max 50 characters
- **Body lines**: Max 72 characters

**Format:** `<type>(<scope>): <description>`

**Types:** `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `build`, `ci`

**Scopes:** `bpf/<sensor>`, `sensors/<name>`, `api`, `model`, `sync`, `cmd`

**Examples:**
```
feat(sensors/http): add request body capture support
fix(bpf/layer3): correct TCP state tracking on RST
chore(sync): update OSS submodule to v1.3.0
```

**Consistency:** Maintain internal consistency with type and scope choices across related commits. Check recent git history for established patterns before choosing new scopes.

**Important:** DCO (Developer Certificate of Origin) is REQUIRED in this repository. All commits must be signed-off using the `-s` flag.

## Application Model Architecture

The Application Model is an **enterprise-only feature** that differs fundamentally from Tetragon's typical event-based architecture:

| Aspect | Event-Based (Standard) | Application Model |
|--------|------------------------|-------------------|
| Data flow | BPF → perf buffer → userspace handler → gRPC stream | BPF maps read directly by model server on interval |
| Granularity | Individual events (each exec, connect, etc.) | Aggregated topology (namespaces → workloads → processes → connections) |
| Output | `GetEventsResponse` protobuf stream | `ApplicationModelEvent` protobuf + telemetry JSON |
| Use case | Real-time alerting, audit logs | Security posture, dependency mapping |

### How It Works

```
BPF Maps (kernel)                    Model Server (userspace)
├─ process_tree_map          ──────▶ GetProcessModel()
├─ destination_endpoint_map  ──────▶   │
└─ tg_cgroup_namespace_map   ──────▶   ▼
                                    ProcessModelToApplicationModel()
                                       │
                                       ▼
                                    ApplicationModelDiff() ──▶ Telemetry JSON
```

The model server (`pkg/model/server/`) periodically reads BPF maps directly (not via event handlers) and builds a hierarchical view: **Namespace → Workload → Process → Connections**.

### Telemetry Export and IPA

The **Isovalent Platform API (IPA)** (`isovalent/ipa`) is a separate repository defining gRPC API schemas for application models, telemetry events, and other platform structures. IPA types are vendored into this project.

**Three-layer model architecture:**

1. **BPF Data Structures** (`pkg/model/types/`) - Go definitions for reading BPF maps
2. **Process Model** (`api/v1/tetragon/processmodel.proto`) - Internal protobuf representation
3. **Application Model** (IPA-defined) - External API schema for platform consumption

A key responsibility of the model server is **translating between these layers**: reading BPF maps via the Go structs, building the process model, then converting to IPA-defined application model types for export.

```
BPF Maps → BPF structs (pkg/model/types/) → Process Model (api/v1/) → Application Model (IPA) → Telemetry JSON
```

### Key Code Paths

| Component | Location |
|-----------|----------|
| Model server | `pkg/model/server/server.go` |
| Telemetry export | `pkg/model/server/export.go` |
| BPF data structures | `pkg/model/types/` |
| Process model proto | `api/v1/tetragon/processmodel.proto` |
| Model conversion | `pkg/model/` (process model → IPA app model) |
| Diff calculation | `pkg/model/diff/diff.go` |
| Model tests | `pkg/bpftest/modeltest/` |

### Configuration

```yaml
tetragon:
  enableApplicationModel: true          # Enable model server
  applicationModelExportInterval: 10s   # Export frequency
  telemetryExportFilename: "telemetry.log"
```

## SmartSwitch Components (AGW/FWA)

```
┌─────────────────┐     ┌─────────────────┐
│   Kubernetes    │     │  Cisco Switch   │
│  (SmartSwitch   │────▶│     (AGW)       │
│   NetworkPolicy)│     └────────┬────────┘
└─────────────────┘              │ gRPC
                    ┌────────────┴────────────┐
                    ▼                         ▼
              ┌──────────┐              ┌──────────┐
              │   DPU    │              │   DPU    │
              │  (FWA)   │              │  (FWA)   │
              └──────────┘              └──────────┘
```

**Build commands:**
```bash
GOOS=linux GOARCH=amd64 make agw              # Build AGW (switch agent)
GOOS=linux GOARCH=arm64 make fwa              # Build FWA (DPU agent, cross-compiled for arm64)
GOOS=linux GOARCH=amd64 make agwctl           # Build AGW CLI
make image-agw        # Build AGW container image
make image-agw-test   # Build AGW container test image
make image-fwa        # Build FWA container image
make image-fwa-test   # Build FWA container test image
```

## Debugging

```bash
# Stream events
./tetra getevents --output=json

# List loaded BPF programs
sudo bpftool prog show

# Check BPF maps
sudo bpftool map show

# Inspect sensor hierarchy
find /sys/fs/bpf/tetragon/ -type d

# Enable debug logging
sudo ./tetragon --bpf-lib bpf/objs --log-level=debug

# Watch BPF verifier errors
sudo dmesg -wT | grep -i bpf
```

## Boundaries

✅ **Always do:**
- Include copyright headers on new files
- Write unit tests for Go files
- Use `make vendor` after importing new packages
- Run `make oss-sync` to sync OSS changes (never edit submodule directly)

⚠️ **Ask first:**
- Running `make validate` (full validation is slow)

🚫 **Never do:**
- Edit files in `vendor/` directly
- Edit files in `modules/tetragon-oss/` directly
- Edit `go.mod` file directly
- Commit secrets, API keys, or credentials
- Remove or weaken existing tests
- Skip copyright headers
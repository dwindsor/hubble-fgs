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

## Issue and PR Labels

Applying the correct labels is **mandatory** when creating issues or PRs via `gh`. Use `gh issue create --label` / `gh pr create --label` or `gh pr edit --add-label` to apply them. Do not invent labels: only use labels listed below or verify a label exists with `gh label list --search <name>`. If no existing label fits, ask the user whether to create one.

**Minimum required labels:**
- Issues: one `kind/*` + one `area/*`
- PRs: one `kind/*` + one `area/*` + one `release-note/*`

### Label Families

| Family | Pattern | Purpose |
|--------|---------|---------|
| Kind | `kind/*` | Classify the type: bug, cleanup, docs, security, oss-sync, ci-flake, kernel, backports, logs |
| Area | `area/*` | Identify the subsystem: http, dns, tls, networking, model, ci, e2e, helm, smartswitch, etc. |
| Release note | `release-note/*` | Control changelog entries: major, minor, bug, misc, ci, dependency, backport |
| Backport | `needs-backport/X.Y`, `backport-pending/X.Y`, `backport-done/X.Y` | Track backport lifecycle per release branch |
| Release blocker | `release-blocker/X.Y`, `release-blocker` | Flag issues blocking a specific release |
| Don't merge | `dont-merge/*` | Prevent merging: wip, waiting-on-oss, waiting-for-review, blocked |
| Roadmap | `roadmap/*` | Link to roadmap items |
| Severity | `severity/*` | Security issue severity: low, medium |
| Feature | `feature/*` | Feature-scoped tracking (e.g., `feature/fim`) |

Standalone labels: `needs-rebase` is applied when a PR has merge conflicts. `dependabot-fail` marks dependabot upgrades needing manual intervention.

### Release Notes in PR Descriptions

PR bodies must contain a `release-note` block describing user-facing changes. Each entry is a single line of plaintext (no line breaks, no markdown formatting):

````
```release-note
one-line plaintext description of user-facing changes
```
````

If the PR is not user-facing (e.g., docs, internal refactors), use `release-note/misc`. For CI-only changes, use `release-note/ci`. In both cases, omit the `release-note` block entirely.

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
└─ tg_cgid_wlid              ──────▶   ▼
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

## Kind Cluster Testing

Use kind clusters to test enterprise features end-to-end locally.

### Setup

```bash
make kind                          # Create kind cluster (named "tetragon-dev")
make kind-down                     # Delete the cluster
```

### Deploying with CI Images

PR CI builds push images tagged with the full commit SHA to the dev registry. To deploy from a PR branch without building locally:

```bash
# Get the full SHA of the commit whose CI images you want
SHA=$(git rev-parse HEAD)

# Create a values override file
cat > /tmp/test-values.yaml <<EOF
tetragon:
  image:
    override: "quay.io/isovalent-dev/tetragon-ci:${SHA}"
tetragonOperator:
  image:
    override: "quay.io/isovalent-dev/tetragon-operator-ci:${SHA}"
EOF

# Deploy (KIND_BUILD_IMAGES=0 skips local image builds)
make kind-install-tetragon KIND_BUILD_IMAGES=0 VALUES=/tmp/test-values.yaml
```

Wait for CI's "Image CI Build" workflow to complete before deploying. Check with:
```bash
gh run list --branch <branch> --json name,status,conclusion \
  | jq '.[] | select(.name == "Image CI Build")'
```

### Deploying with Locally Built Images

```bash
# Build images and deploy in one step
make kind-setup

# Or deploy to an existing cluster (builds images first by default)
make kind-install-tetragon
```

### Custom Helm Values

Pass additional helm values to enable enterprise features. Common options:

```yaml
# Enable application model
tetragon:
  enableApplicationModel: true
  cgidmap:
    enabled: true                         # Required for app model
  applicationModelExportFilename: "application-model.log"
  applicationModelExportInterval: 10s
  telemetryExportFilename: "telemetry.log"
  layer3:
    tcp:
      enabled: true
    udp:
      enabled: true
```

### Verification

```bash
# Check pods are running
kubectl -n tetragon get pods

# Inspect config
kubectl -n tetragon get cm tetragon-config -o yaml

# List files in the tetragon data directory
kubectl -n tetragon exec <pod> -c tetragon -- ls -la /var/run/cilium/tetragon/

# Run bugtool and inspect the sysdump
kubectl -n tetragon exec <pod> -c tetragon -- tetra bugtool
kubectl -n tetragon exec <pod> -c tetragon -- tar tzf /tetragon-bugtool.tar.gz
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

## Your Role

- You write Go code for AGW (switch agent) and FWA (DPU agent)

## Commands

**Build:**
```bash
GOOS=linux GOARCH=amd64 make agw              # Build AGW (switch agent)
GOOS=linux GOARCH=arm64 make fwa              # Build FWA (DPU agent, cross-compiled for arm64)
GOOS=linux GOARCH=amd64 make agwctl           # Build AGW CLI
make image-agw        # Build AGW container image
make image-agw-test   # Build AGW container test image
make image-fwa        # Build FWA container image
make image-fwa-test   # Build FWA container test image
```

**Test:**
```bash
make validate       # Full validation (test + lint + format)
```

**Code Generation:**
```bash
make vendor         # Update vendored dependencies
```

## Architecture

```
┌─────────────────┐     ┌─────────────────┐
│   Kubernetes    │     │  Cisco Switch   │
│  (SmartSwitch   │────▶│     (AGW)       │
│   NetworkPolicy)│     └────────┬────────┘
└─────────────────┘              │
                                 │ gRPC
                    ┌────────────┴────────────┐
                    ▼                         ▼
              ┌──────────┐              ┌──────────┐
              │   DPU    │              │   DPU    │
              │  (FWA)   │              │  (FWA)   │
              └──────────┘              └──────────┘
```

**Components:**
- **AGW** (`cmd/agw/`) - Agent Gateway on the switch; receives policies from K8s, translates to DPU rules, manages DPU connections
- **FWA** (`cmd/fwa/`) - Firewall Agent on DPU; receives rules from AGW, programs the dataplane
- **agwctl** (`cmd/agwctl/`) - CLI for AGW management (config, policies, logging)

## Project Structure

```
cmd/agw/                    # AGW entry point and CLI server
cmd/fwa/                    # FWA entry point
cmd/agwctl/                 # AGW CLI tool
docs/smartswitch/           # Policy guides and examples
vendor/                     # Vendored dependencies (DO NOT EDIT)
```

**SmartSwitchNetworkPolicy example:**
```yaml
apiVersion: isovalent.com/v1alpha1
kind: SmartSwitchNetworkPolicy
metadata:
  name: allow-web
  namespace: production
spec:
  rules:
    - action: allow
      source:
        ipBlock:
          - cidr: "10.0.0.0/8"
            vrf: "internal"
      destination:
        ipBlock:
          - cidr: "192.168.1.0/24"
            vrf: "internal"
        protoPorts:
          - protocol: TCP
            port: 443
```

## Code Style

**Go example (correct style):**
```go
package switchpolicy

import (
	"context"

    "github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/tetragon/pkg/logger"

	"github.com/isovalent/hubble-fgs/pkg/model/switchpolicy"
)

func (h *Handler) ProcessPolicy(ctx context.Context, policy *switchpolicy.Policy) error {
    var err error
    logger.GetLogger().Info("Processing policy", logfields.Error, err, "name", policy.Name)
	return err
}
```

**Import order:** stdlib → external → local (`github.com/isovalent/hubble-fgs`)

## Git Workflow

- Branch from `main`
- Run `make vendor` and `make validate` before committing
- Copyright headers required on all source files

## Boundaries

✅ **Always do:**
- Include copyright headers on new files
- Write unit tests for go files
- Use `make vendor` after importing new packages

⚠️ **Ask first:**
- Running `make validate` because it takes a long time

🚫 **Never do:**
- Edit files in `vendor/` directly
- Edit `go.mod` file directly
- Commit secrets, API keys, or credentials
- Remove or weaken existing tests
- Skip copyright headers
# TracingPolicy `nodeSelector`

A `TracingPolicy` can carry a `spec.nodeSelector` (a standard label selector with
`matchLabels` and `matchExpressions`) that controls which nodes load the
policy. A policy whose selector does not match a node is not loaded on that
node's agent — it loads no BPF and is reported as `SKIPPED` in `tetra
tracingpolicy list`, rather than being disabled after loading. An empty or unset
`nodeSelector` loads the policy everywhere, preserving the default behaviour.

`nodeSelector` differs from `hostSelector`: `nodeSelector` controls where a
policy is loaded, while `hostSelector` scopes *which workloads* an already-loaded
policy applies to.

## Kubernetes

In Kubernetes the agent evaluates `nodeSelector` against the labels of the
Kubernetes `Node` it runs on. For `TracingPolicy` and `TracingPolicyNamespaced`
resources managed through the Kubernetes API, relabelling a node at runtime
re-evaluates every `nodeSelector` policy and loads it or marks it `SKIPPED`
accordingly. Policies loaded from a file or the gRPC API are gated against a
snapshot of the `Node` labels taken at agent startup, and are not re-evaluated
when the node is relabelled.

## Non-Kubernetes (bare-metal / VM)

Tetragon Enterprise also enforces `nodeSelector` for policies loaded from a file
(`--tracing-policy` / `--tracing-policy-dir`) on non-Kubernetes hosts. The
selector is evaluated once, at load time, against labels derived from the
local host, which is sufficient for hosts with static metadata (for example VMs
with fixed IPs or a fixed architecture). A gated-out policy is tracked as
`SKIPPED` in `tetra tracingpolicy list` (loading no BPF), the same as on
Kubernetes.

The following labels are derived from the local host; each is omitted when it
cannot be determined. They carry a `tetragon.io` prefix so they are not confused
with the `kubernetes.io` labels kubelet assigns to Kubernetes nodes:

| Label                              | Value                                             |
|------------------------------------|---------------------------------------------------|
| `tetragon.io/arch`                 | host architecture, e.g. `amd64`, `arm64`          |
| `tetragon.io/os`                   | host OS, e.g. `linux`                             |
| `tetragon.io/hostname`             | host name                                         |
| `tetragon.io/internal-ip`          | first non-loopback IPv4 address, when available   |
| `tetragon.io/kernel-build-id`      | running kernel GNU build ID (hex), when available |
| `tetragon.io/kernel-major-version` | running kernel major version, e.g. `6`            |
| `tetragon.io/kernel-minor-version` | running kernel minor version, e.g. `18`           |

The kernel build ID is read from the live kernel's ELF notes
(`/sys/kernel/notes`) and does not require the vmlinux image; it is omitted on
kernels built without a build ID. The kernel version labels come from the same
detection the agent uses elsewhere, so `--kernel` overrides them; they are
omitted when the version cannot be determined. The internal IP is the host's
first non-loopback IPv4 address; a multi-homed host is labeled with only that
one, and IPv6 addresses are not labeled. On cloud instances, instance
tags/labels reported by the provider metadata service are also available for
matching.

### Example

Load a policy only on `arm64` hosts:

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "arm64-only"
spec:
  nodeSelector:
    matchExpressions:
      - key: "tetragon.io/arch"
        operator: In
        values: ["arm64"]
  kprobes:
    - call: "tcp_connect"
```

Load a policy only on hosts with a specific internal IP:

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "specific-hosts"
spec:
  nodeSelector:
    matchExpressions:
      - key: "tetragon.io/internal-ip"
        operator: In
        values: ["10.0.0.5", "10.0.0.6"]
  kprobes:
    - call: "tcp_connect"
```

Ready-to-use copies ship under
[`examples/tracingpolicy/`](../examples/tracingpolicy/) as
`nodeselector-arch.yaml` and `nodeselector-internal-ip.yaml`.

### Notes

- Host labels are resolved once at agent startup, so for file and gRPC-loaded
  policies a label or host metadata change takes effect only when the agent
  restarts (Kubernetes CRD policies are re-evaluated by the node watch instead).
- Evaluation fails open: if the selector cannot be evaluated (e.g. host metadata
  is unavailable), the policy is loaded rather than silently dropped.
- Policies added over the gRPC API (`tetra tracingpolicy add`) are gated the
  same way — evaluated once when added, and a non-matching one is recorded as
  `SKIPPED`.

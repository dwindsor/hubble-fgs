## Upgrade notes

Read the upgrade notes carefully before upgrading Tetragon.
Depending on your setup, changes listed here might require a manual intervention.

* The default value of the network stats interval in the default network
  TracingPolicy (enabled via `tracingPolicies.default.network.enabled` Helm
  value) is changed from 10s to 60s.

### Agent Options

* TBD

### Helm Values

* TBD

### OLM manifests

* TBD

### Kubernetes CRDs

* TBD

### Events (protobuf API)

* ProcessFileExec event is deprecated and will be removed in the next release.
  Please update your policies to use ProcessFile events, which provide equivalent
  functionality.

### Metrics

* TBD

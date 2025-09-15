## Upgrade notes

Read the upgrade notes carefully before upgrading Tetragon.
Depending on your setup, changes listed here might require a manual intervention.

* TBD

### Agent Options

* TBD

### Helm Values

* TBD

### OLM manifests

* TBD

### Kubernetes CRDs

* Introduce an optional `risk_score` field in the AlertRule custom resource to
  indicate the risk level between 0 (no risk) to 100 (the highest risk).

### Events (protobuf API)

* ProcessFileExec event is removed. Please update your policies to use ProcessFile
  events, which provide equivalent functionality.

### Metrics

* TBD

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

* `spec.file.file_paths` is removed in favor of `spec.file.file_paths_patterns`.
  `spec.file.file_paths` has been deprecated since v1.13.

### Events (protobuf API)

* `tracing_policy` field in ProcessFile events is deprecated and will be removed in the next release.
  This is replaced by `policy_name` field in order to be considtent with other events.

### Metrics

* TBD

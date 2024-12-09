## Upgrade notes

Read the upgrade notes carefully before upgrading Tetragon.
Depending on your setup, changes listed here might require a manual intervention.

* TBD

### Agent Options

* TBD

### Helm Values

* The default value of `tetragon.prometheus.metricsLabelFilter` changed from
  `"namespace,workload,pod,binary"` to `"namespace,workload,binary"`. See also
  the metrics notes.

### OLM manifests

* TBD

### TracingPolicy (k8s CRD)

* TBD

### Events (protobuf API)

* TBD

### Metrics

* In Tetragon Helm installations, events metrics now don't have `pod` label by
  default. This was done to reduce the default metrics cardinality. If you want
  to keep `pod` label, overwrite the default `tetragon.prometheus.metricsLabelFilter`
  Helm value.

## Upgrade notes

Read the upgrade notes carefully before upgrading Tetragon.
Depending on your setup, changes listed here might require a manual intervention.

* TCP and UDP one-way latency (limited functionality) has been removed.

### Agent Options

* The --enable-latency CLI switch has been removed.

### Helm Values

* The tetragon.layer3.latency.enabled parameter was removed.

### OLM manifests

* TBD

### Kubernetes CRDs

* The one-way latency configuration for TCP and UDP has been removed.

### Events (protobuf API)

* The latency member of the SocketStats message has been deprecated.

### Metrics

* The one-way latency metrics for TCP and UDP have been remvoed.

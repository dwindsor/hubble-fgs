## Upgrade notes

Read the upgrade notes carefully before upgrading Tetragon.
Depending on your setup, changes listed here might require a manual intervention.

* TBD

### Agent Options

* Tetragon groups UDP statistics for DNS servers (identified as listening on a UDP
  port listed in the dns.ports section of the policy) per local address and local port.
  The --dns-stats-per-socket switch reverts to separate statistics per DNS connection.

### Helm Values

* `dashboards.annotations` value has been removed. Use `annotations` values for
  specific dashboard groups instead, e.g. `dashboards.health.annotations`.
* The new tetragon.dnsStatsPerSocket operates as per the --dns-stats-per-socket
  switch (see Agent Options).

### OLM manifests

* TBD

### TracingPolicy (k8s CRD)

* TBD

### Events (protobuf API)

* Socket statistics events, and socket statistics in close socket events, group UDP
  statistics for DNS servers per local address and local port (see Agent Options).

### Metrics

* Tetragon groups UDP statistics for DNS servers per local address and local port
  (see Agent Options).

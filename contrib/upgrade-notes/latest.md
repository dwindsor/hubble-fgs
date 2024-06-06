## Upgrade notes

Read the upgrade notes carefully before upgrading Tetragon.
Depending on your setup, changes listed here might require a manual intervention.

* TBD

### Agent Options

* TBD

### Helm Values

* TBD

### TracingPolicy (k8s CRD)

* TBD

### Events (protobuf API)

* TBD

### Metrics

* `tetragon_udp_stats_cache_entries` and `tetragon_udp_stats_cache_capacity` are added to monitor the UDP stats cache size.
  They replace `tetragon_lru_in_use_gauge` which is removed.

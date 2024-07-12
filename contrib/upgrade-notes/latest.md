## Upgrade notes

Read the upgrade notes carefully before upgrading Tetragon.
Depending on your setup, changes listed here might require a manual intervention.

* TBD

### Agent Options

* TBD

### Helm Values

* `tetragon.exportFilePerm` now defaults to "600" instead of "644", meaning that the events log is not readable by users other than the owner.
  If you have some agent reading this file, for example to export events to external storage, you'll likely need to set this value to "640"/"644".
  The default value was changed to improve the Tetragon security posture.

### TracingPolicy (k8s CRD)

* TBD

### Events (protobuf API)

* TBD

### Metrics

* `tetragon_udp_stats_cache_entries` and `tetragon_udp_stats_cache_capacity` are added to monitor the UDP stats cache size.
  They replace `tetragon_lru_in_use_gauge` which is removed.

## Upgrade notes

Read the upgrade notes carefully before upgrading Tetragon.
Depending on your setup, changes listed here might require a manual intervention.

* TCP and UDP one-way latency (limited functionality) has been removed.

### Agent Options

* The --enable-latency CLI switch has been removed.
* The following CLI switches were added to configure layer3 functionality without
  using a tracing policy:
  * --icmpv6-info
  * --rawsock-report-close
  * --enable-rawsock-metrics
  * --rawsock-metrics-label-filter
  * --enable-udp-cgroup
  * --udp-stats-interval
  * --enable-udp-watermarks
  * --udp-watermarks-window-size-ms
  * --udp-watermarks-burst-trigger-percent
  * --udp-watermarks-dip-trigger-percent
  * --enable-udp-metrics
  * --udp-metrics-label-filter
  * --udp-disable-events
  * --enable-network-watermarks-exit-gen
  * --network-watermarks-exit-gen-interval
  * --tcp-stats-interval
  * --enable-tcp-watermarks
  * --tcp-watermarks-window-size-ms
  * --tcp-watermarks-burst-trigger-percent
  * --tcp-watermarks-dip-trigger-percent
  * --tcp-rtt-min
  * --tcp-rtt-max
  * --enable-tcp-metrics
  * --tcp-metrics-label-filter
  * --tcp-disable-events
  * --dns-report-questions
  * --enable-dns-metrics
  * --dns-metrics-label-filter

  The recommended way to specify and configure the layer3 sensor is now through
  CLI switches and not via tracing policy. Use of layer3 tracing policies is now
  deprecated, with a warning when one is used. Configuring Layer 3 via tracing
  policies will be removed in v1.21. See the full list of CLI switches, together
  with their descriptions, by running ```tetragon --help```.

  Layer3 CLI switches can be combined with tracing policies. Tracing policies
  override CLI switch settings. If, for example, TCP is not enabled with the CLI
  switch, it can later be enabled and configured with a tracing policy. When that
  tracing policy is later removed, the sensor will cease reporting TCP information,
  and its TCP BPF programs will be unloaded. It will effectively revert to the state
  before the tracing policy was loaded.

  For clarity, disable-events switches are added to by tracing policies. If some
  events are disabled by CLI switches, then they remain disabled regardless of
  the specification in the tracing policy. The tracing policy can, however, disable
  further events, and these events will be produced again when the tracing policy
  is unloaded.

  Layer3 tracing policies will be removed in the next release. We recommend
  converting layer3 tracing policies to CLI switches or chart parameters now to
  prevent issues when upgrading in the future.
* Application Model related exports (appmodel, telemetry and connections log) default values for MaxSizeMB and MaxBackups have been updated to 25M and 1; before, they were 10M and 5.
* New flags to manage application model exports options: `--application-model-export-file-max-size-mb`, `--application-model-export-file-max-backups`, `--application-model-export-file-compress`.

### Helm Values

* The tetragon.layer3.latency.enabled parameter was removed.
* The following parameters were added to configure layer3 functionality without
  using a tracing policy:
  * tetragon.layer3.icmp.v6info: false
  * tetragon.layer3.icmp.socketTracking: false
  * tetragon.layer3.rawsock.reportClose: false
  * tetragon.layer3.rawsock.metrics.enabled: true
  * tetragon.layer3.rawsock.metrics.labelFilter: []
  * tetragon.layer3.udp.cgroup: true
  * tetragon.layer3.udp.statsInterval: 0s
  * tetragon.layer3.udp.watermarks.enabled: false
  * tetragon.layer3.udp.watermarks.windowSizeMs: 0
  * tetragon.layer3.udp.watermarks.burstTriggerPercent: 0
  * tetragon.layer3.udp.watermarks.dipTriggerPercent: 0
  * tetragon.layer3.udp.metrics.enabled: true
  * tetragon.layer3.udp.metrics.labelFilter: []
  * tetragon.layer3.udp.disableEvents: []
  * tetragon.layer3.watermarksExitGen.enabled: true
  * tetragon.layer3.watermarksExitGen.interval: 1s
  * tetragon.layer3.tcp.statsInterval: 0s
  * tetragon.layer3.tcp.watermarks.enabled: false
  * tetragon.layer3.tcp.watermarks.windowSizeMs: 0
  * tetragon.layer3.tcp.watermarks.burstTriggerPercent: 0
  * tetragon.layer3.tcp.watermarks.dipTriggerPercent: 0
  * tetragon.layer3.tcp.rtt.min: 0
  * tetragon.layer3.tcp.rtt.max: 0
  * tetragon.layer3.tcp.metrics.enabled: true
  * tetragon.layer3.tcp.metrics.labelFilter: []
  * tetragon.layer3.tcp.disableEvents: []
  * tetragon.layer3.dns.ports: []
  * tetragon.layer3.dns.reportQuestions: false
  * tetragon.layer3.dns.metrics.enabled: true
  * tetragon.layer3.dns.metrics.labelFilter: []
* Application Model related exports (appmodel, telemetry and connections log) default values for MaxSizeMB and MaxBackups have been updated to 25M and 1; before, they were 10M and 5.
* New values to manage application model exports options: `tetragon.applicationModelExportFileMaxSizeMB`, `tetragon.applicationModelExportFileMaxBackups`, `tetragon.applicationModelExportFileCompress`.
* `exportDirectory` and `alerts.exportDirectory` have been updated to `/var/log/tetragon` from
  `/var/run/cilium/tetragon/` to avoid writing to tmpfs.

### OLM manifests

* TBD

### Kubernetes CRDs

* The one-way latency configuration for TCP and UDP has been removed.
* Deprecated FIM matchLinuxCapabilities selector in favor of matchCapabilities.
* Deprecated FIM matchLinuxNamespaces selector in favor of matchNamespaces.

### Events (protobuf API)

* The latency member of the SocketStats message has been deprecated.

### Metrics

* The one-way latency metrics for TCP and UDP have been remvoed.

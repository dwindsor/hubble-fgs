# tetragon

![Version: 0.0.0-dev](https://img.shields.io/badge/Version-0.0.0--dev-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) ![AppVersion: 0.0.0-dev](https://img.shields.io/badge/AppVersion-0.0.0--dev-informational?style=flat-square)

Helm chart for Tetragon Enterprise

## Requirements

| Repository | Name | Version |
|------------|------|---------|
| https://grafana.github.io/helm-charts | grafana | 10.5.15 |
| https://prometheus-community.github.io/helm-charts | kube-state-metrics | 8.5.0 |

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| affinity | object | `{}` |  |
| certgen | object | `{"affinity":{},"annotations":{"cronJob":{},"job":{}},"cronJob":{"failedJobsHistoryLimit":1,"successfulJobsHistoryLimit":1},"generateCA":true,"hostUsers":true,"image":{"override":null,"pullPolicy":"IfNotPresent","repository":"quay.io/cilium/certgen","tag":"v0.4.11"},"nodeSelector":{},"podLabels":{},"resources":{},"tolerations":[],"ttlSecondsAfterFinished":1800}` | cilium-certgen settings used by tetragon.grpc.tls.auto.method=cronJob. Mirrors the same block in cilium/cilium so operators familiar with the hubble TLS workflow find consistent knobs. |
| certgen.affinity | object | `{}` | Affinity for certgen pods. |
| certgen.annotations | object | `{"cronJob":{},"job":{}}` | Annotations applied to certgen Job/CronJob objects. |
| certgen.cronJob.failedJobsHistoryLimit | int | `1` | Number of failed CronJob runs to retain. |
| certgen.cronJob.successfulJobsHistoryLimit | int | `1` | Number of successful CronJob runs to retain. |
| certgen.generateCA | bool | `true` | Whether the certgen invocation should generate a CA when one isn't found in the configured CA Secret. |
| certgen.hostUsers | bool | `true` | Run the certgen pods in the host user namespace. certgen needs no host access, set to false to run it in a user namespace. Requires Kubernetes 1.33 or later. |
| certgen.nodeSelector | object | `{}` | Node selector for certgen pods. |
| certgen.podLabels | object | `{}` | Pod labels added to certgen pods. |
| certgen.resources | object | `{}` | Resource requests/limits for the certgen container. |
| certgen.tolerations | list | `[]` | Tolerations for certgen pods. |
| certgen.ttlSecondsAfterFinished | int | `1800` | TTL applied to the bootstrap Job once it completes. |
| crds.installMethod | string | `"operator"` | Method for installing CRDs. Supported values are: "operator", "helm" and "none". The "operator" method allows for fine-grained control over which CRDs are installed and by default doesn't perform CRD downgrades. These can be configured in tetragonOperator section. The "helm" method always installs all CRDs for the chart version. |
| daemonSetAnnotations | object | `{}` |  |
| daemonSetLabelsOverride | object | `{}` |  |
| dashboards | object | `{"health":{"annotations":{},"enabled":false},"labels":{"grafana_dashboard":"1"},"namespace":null,"network":{"annotations":{},"enabled":false}}` | Grafana dashboards, installed as ConfigMaps. They can be mounted in a Grafana deployment, or loaded automatically using the Grafana's sidecar for dashboards. See: https://github.com/grafana/helm-charts/tree/main/charts/grafana#sidecar-for-dashboards If integratedGrafana.enabled is true, all dashboards are installed, regardless of their individual enabled values. |
| dashboards.health.annotations | object | `{}` | Annotations to add to the dashboards ConfigMaps. |
| dashboards.health.enabled | bool | `false` | Enable dashboards for monitoring Tetragon health and operations. |
| dashboards.labels | object | `{"grafana_dashboard":"1"}` | Labels to add to the dashboards ConfigMaps. If using the dashboards sidecar, these must include the label used for dashboards discovery. |
| dashboards.namespace | string | `nil` | Namespace to create the dashboards ConfigMaps in. Defaults to namespace of the Helm release. |
| dashboards.network.annotations | object | `{}` | Annotations to add to the dashboards ConfigMaps. |
| dashboards.network.enabled | bool | `false` | Enable dashboards for layer 3/4 networking. |
| dnsPolicy | string | `"Default"` | DNS policy for Tetragon pods.  https://kubernetes.io/docs/concepts/services-networking/dns-pod-service/#pod-s-dns-policy |
| enabled | bool | `true` |  |
| export | object | `{"argsOverride":[],"commandOverride":[],"extraArgs":{},"extraEnv":[],"extraVolumeMounts":[],"filenames":["tetragon.log"],"mode":"","securityContext":{},"stdout":{"image":{"override":null,"repository":"quay.io/isovalent/hubble-export-stdout","tag":"v1.1.1"}}}` | Tetragon events export settings |
| exportDirectory | string | `"/var/log/tetragon"` | Directory to put Tetragon JSON export files. |
| extraConfigmapMounts | list | `[]` |  |
| extraHostPathMounts | list | `[]` |  |
| extraVolumes | list | `[]` |  |
| grafana.resources | object | `{"limits":{"memory":"256Mi"},"requests":{"cpu":"50m","memory":"128Mi"}}` | Resources for the Grafana container. |
| hostNetwork | bool | `true` |  |
| imagePullPolicy | string | `"IfNotPresent"` |  |
| imagePullSecrets | list | `[]` |  |
| integratedGrafana.enabled | bool | `false` | Install Grafana with dashboards and lightweight Prometheus datasource. It's intended to quickly set up Tetragon monitoring and/or get value out of Tetragon without setting up a custom data pipeline. If enabled, grafana automatically creates a secret named "$release-grafana" storing "admin" user base64 encoded password. Example command to retrieve the password: kubectl get secret -n tetragon tetragon-grafana -o jsonpath='{.data.admin-password}' | base64 -d |
| integratedGrafana.prometheus.image | object | `{"pullPolicy":"IfNotPresent","registry":"quay.io","repository":"prometheus/prometheus","sha":null,"tag":"v3.15.0"}` | Prometheus image |
| integratedGrafana.prometheus.resources | object | `{"limits":{"memory":"1Gi"},"requests":{"cpu":"200m","memory":"512Mi"}}` | Resources for the Prometheus container. |
| kube-state-metrics.resources | object | `{"limits":{"memory":"64Mi"},"requests":{"cpu":"10m","memory":"32Mi"}}` | Resources for the kube-state-metrics container. |
| nodeSelector | object | `{}` |  |
| podAnnotations | object | `{}` |  |
| podLabels | object | `{}` |  |
| podLabelsOverride | object | `{}` |  |
| podSecurityContext | object | `{}` |  |
| priorityClassName | string | `""` |  |
| rthooks | object | `{"annotations":{},"enabled":false,"exportLogs":{"enabled":true,"resources":{}},"extraHookArgs":{},"extraLabels":{},"extraVolumeMounts":[],"failAllowNamespaces":"","failAllowNamespacesRegex":[],"image":{"override":null,"repository":"artifactory.devhub-cloud.cisco.com/isovalent-iep-docker/tetragon-rthooks","tag":"v1.20.0-pre.2"},"installDir":"/opt/tetragon","interface":"","nameOverride":"","nriHook":{"nriSocket":"/var/run/nri/nri.sock"},"ociHooks":{"hooksPath":"/usr/share/containers/oci/hooks.d"},"podAnnotations":{},"podSecurityContext":{},"priorityClassName":"","resources":{},"serviceAccount":{"name":""}}` | Method for installing Tetagon rthooks (tetragon-rthooks) daemonset The tetragon-rthooks daemonset is responsible for installing run-time hooks on the host. See: https://tetragon.io/docs/concepts/runtime-hooks |
| rthooks.annotations | object | `{}` | Annotations for the Tetragon rthooks daemonset |
| rthooks.enabled | bool | `false` | Enable the Tetragon rthooks daemonset |
| rthooks.exportLogs | object | `{"enabled":true,"resources":{}}` | exportLogs sidecar: tail the hook log file and stream it to stdout. Uses the same image as the rthooks container. |
| rthooks.exportLogs.enabled | bool | `true` | Enable the exportLogs sidecar container. |
| rthooks.exportLogs.resources | object | `{}` | resources for the exportLogs sidecar. |
| rthooks.extraHookArgs | object | `{}` | extra args to pass to tetragon-oci-hook |
| rthooks.extraLabels | object | `{}` | Extra labels for the Tetrargon rthooks daemonset |
| rthooks.extraVolumeMounts | list | `[]` | Extra volume mounts to add to the oci-hook-setup init container |
| rthooks.failAllowNamespaces | string | `""` | Comma-separated list of namespaces to allow Pod creation for, in case tetragon-oci-hook fails to reach Tetragon agent. The namespace Tetragon is deployed in is always added as an exception and must not be added again. |
| rthooks.failAllowNamespacesRegex | list | `[]` | List of RE2 regex patterns for namespaces to allow Pod creation for, in case tetragon-oci-hook fails to reach Tetragon agent. Patterns perform substring matching by default; use ^ and $ anchors for full-string matching (e.g. '^kube-.*$' matches only namespaces starting with 'kube-'). Can be combined with failAllowNamespaces. Ignored if extraHookArgs sets fail-cel-expr. Example: ["^acme-.*$", "^dev-.*$"] |
| rthooks.image | object | `{"override":null,"repository":"artifactory.devhub-cloud.cisco.com/isovalent-iep-docker/tetragon-rthooks","tag":"v1.20.0-pre.2"}` | image for the Tetragon rthooks pod |
| rthooks.installDir | string | `"/opt/tetragon"` | installDir is the host location where the tetragon-oci-hook binary will be installed |
| rthooks.interface | string | `""` | Method to use for installing  rthooks. Values:     "oci-hooks":       Add an apppriate file to "/usr/share/containers/oci/hooks.d". Use this with CRI-O.       See https://github.com/containers/common/blob/main/pkg/hooks/docs/oci-hooks.5.md       for more details.       Specific configuration for this interface can be found under "ociHooks".     "nri-hook":      Install the hook via NRI. Use this with containerd. Requires NRI being enabled.      see: https://github.com/containerd/containerd/blob/main/docs/NRI.md.      Specific configuration for this interface can be found under "nriHook".  |
| rthooks.nameOverride | string | `""` | tetragon-rthooks name override |
| rthooks.nriHook | object | `{"nriSocket":"/var/run/nri/nri.sock"}` | configuration for the "nri-hook" interface |
| rthooks.nriHook.nriSocket | string | `"/var/run/nri/nri.sock"` | path to NRI socket |
| rthooks.ociHooks | object | `{"hooksPath":"/usr/share/containers/oci/hooks.d"}` | configuration for "oci-hooks" interface |
| rthooks.ociHooks.hooksPath | string | `"/usr/share/containers/oci/hooks.d"` | directory to install .json file for running the hook |
| rthooks.podAnnotations | object | `{}` | Pod annotations for the Tetrargon rthooks pod |
| rthooks.podSecurityContext | object | `{}` | security context for the Tetrargon rthooks pod |
| rthooks.priorityClassName | string | `""` | priorityClassName for the Tetrargon rthooks pod |
| rthooks.resources | object | `{}` | resources for the the oci-hook-setup init container |
| rthooks.serviceAccount | object | `{"name":""}` | rthooks service account. |
| selectorLabelsOverride | object | `{}` |  |
| serviceAccount.annotations | object | `{}` |  |
| serviceAccount.create | bool | `true` |  |
| serviceAccount.name | string | `""` |  |
| serviceAnnotations | object | `{}` |  |
| serviceLabels | object | `{}` |  |
| serviceLabelsOverride | object | `{}` |  |
| splunk_hec.disable_compression | bool | `false` |  |
| splunk_hec.enabled | bool | `false` |  |
| splunk_hec.endpoint.secretKey | string | `"hec-endpoint"` |  |
| splunk_hec.endpoint.secretName | string | `"splunk-hec"` |  |
| splunk_hec.image.override | string | `nil` |  |
| splunk_hec.image.pullPolicy | string | `"IfNotPresent"` |  |
| splunk_hec.image.repository | string | `"quay.io/isovalent/opentelemetry-collector-contrib"` |  |
| splunk_hec.image.tag | string | `"0.161.0"` |  |
| splunk_hec.index | string | `nil` |  |
| splunk_hec.namespace | string | `nil` | Namespace to create the otel collector ConfigMaps in. Defaults to namespace of the Helm release. |
| splunk_hec.resources.limits.cpu | string | `"500m"` |  |
| splunk_hec.resources.limits.memory | string | `"512Mi"` |  |
| splunk_hec.resources.requests.cpu | string | `"200m"` |  |
| splunk_hec.resources.requests.memory | string | `"256Mi"` |  |
| splunk_hec.timeout | string | `"10s"` |  |
| splunk_hec.tls.insecureSkipVerify | bool | `false` |  |
| splunk_hec.token.secretKey | string | `"hec-token"` |  |
| splunk_hec.token.secretName | string | `"splunk-hec"` |  |
| tetragon.alerts.enabled | bool | `true` | Enable alerts. |
| tetragon.alerts.exportDirectory | string | `"/var/log/tetragon"` | Directory for alert JSON export (filenames will be retrieved from alert rule names). |
| tetragon.alerts.exportFilename | string | `""` | Global filename for alert JSON export (instead of retrieving it from alert rule names). |
| tetragon.applicationModelCacheSize | int | `65536` | Cache size for application model. |
| tetragon.applicationModelExportFileCompress | bool | `false` |  |
| tetragon.applicationModelExportFileMaxBackups | int | `1` |  |
| tetragon.applicationModelExportFileMaxSizeMB | int | `25` |  |
| tetragon.applicationModelExportFilename | string | `""` | Export filename for application model (e.g "application-model.log"). Set to empty to disable exporting the application model. |
| tetragon.applicationModelExportFragments | bool | `false` | Whether to export complete application model objects or "fragments" that can be reassembled into a complete application model. Using fragments is desirable when there is a maximum message size limit when collecting application model objects from tetragon agents and saving to a central data store. Complete application model objects might hit this limit but fragments would not. |
| tetragon.applicationModelExportInterval | string | `"60s"` | Interval at which to export application model. |
| tetragon.argsOverride | list | `[]` | Override the arguments. For advanced users only. |
| tetragon.bpfDNSParser.enabled | bool | `false` | Enable in-kernel BPF DNS parser. A 5.15.0+ kernel is required. |
| tetragon.bpfDNSParser.perPod | bool | `false` | Enable in-kernel BPF DNS parser maps per Pod partitioning. |
| tetragon.bpfDNSParser.perPodPrealloc | int | `15` | Number of maps to preallocate at startup for BPF DNS parser maps per Pod partitioning. |
| tetragon.bpfDNSParser.perPodThreshold | int | `5` | Threshold of free maps to keep at runtime for the BPF DNS parser maps per Pod partitioning. |
| tetragon.btf | string | `""` |  |
| tetragon.cgidmap | object | `{"enabled":false}` | Enabling cgidmap instructs the Tetragon agent to use cgroup ids (instead of cgroup names) for pod association. This feature depends on cri being enabled. |
| tetragon.clusterName | string | `""` | Name of the cluster where Tetragon is installed. Tetragon uses this value to set the cluster_name field in GetEventsResponse messages. |
| tetragon.commandOverride | list | `[]` | Override the command. For advanced users only. |
| tetragon.connectionLogFilename | string | `""` | Export filename for connections log (e.g "connections.log"). Set to empty to disable. Note that tetragon.enableApplicationModel must be set to true for connections log export to take effect. Connections log export uses the export interval specified by tetragon.applicationModelExportInterval value. |
| tetragon.cri | object | `{"enabled":false,"socketHostPath":""}` | Configure tetragon pod so that it can contact the CRI running on the host |
| tetragon.cri.socketHostPath | string | `""` | path of the CRI socket on the host. This will typically be "/run/containerd/containerd.sock" for containerd or "/var/run/crio/crio.sock"  for crio. |
| tetragon.debug | bool | `false` | If you want to run Tetragon in debug mode change this value to true |
| tetragon.deletedPodCacheSize | int | `1024` | Tetragon keeps recently deleted pod/container mappings in an LRU cache to resolve pod metadata for late-arriving events. |
| tetragon.dnsStatsPerSocket | bool | `false` |  |
| tetragon.enableApplicationModel | bool | `false` | Enable application model. |
| tetragon.enableCiliumAPI | bool | `false` | Access Cilium API to associate Tetragon events with Cilium DNS cache. |
| tetragon.enableEvents.network | bool | `true` |  |
| tetragon.enableK8sAPI | bool | `true` | Access Kubernetes API to associate Tetragon events with Kubernetes pods. |
| tetragon.enableKeepSensorsOnExit | bool | `false` | Persistent enforcement to allow the enforcement policy to continue running even when its Tetragon process is gone. |
| tetragon.enableMsgHandlingLatency | bool | `false` | Enable latency monitoring in message handling |
| tetragon.enablePolicyFilter | bool | `true` | Enable policy filter. This is required for K8s namespace and pod-label filtering. |
| tetragon.enablePolicyFilterCgroupMap | bool | `false` | Enable policy filter cgroup map. |
| tetragon.enablePolicyFilterDebug | bool | `false` | Enable policy filter debug messages. |
| tetragon.enableProcessCred | bool | `false` | Enable Capabilities visibility in exec and kprobe events. |
| tetragon.enableProcessNs | bool | `false` | Enable Namespaces visibility in exec and kprobe events. |
| tetragon.enableProcessTree | bool | `false` | Enable process tree. |
| tetragon.enableSandboxpolicies | bool | `true` | Enable sandboxpolicies. |
| tetragon.enableSyscallTracking | bool | `false` | Enable system call tracking in the process tree. |
| tetragon.enabled | bool | `true` |  |
| tetragon.eventCacheRetries | int | `15` | Configure the number of retries in tetragon's event cache. |
| tetragon.eventCacheRetryDelay | int | `2` | Configure the delay (in seconds) between retires in tetragon's event cache. |
| tetragon.exportAllowList | string | `"{\"event_set\":[\"PROCESS_CONNECT\", \"PROCESS_EXEC\", \"PROCESS_FILE\", \"PROCESS_HTTP\", \"PROCESS_KPROBE\", \"PROCESS_LISTEN\", \"PROCESS_SANDBOX_SYSCALL\", \"PROCESS_TLS\"]}"` | Allowlist for JSON export. For example, to export only process_connect events from the default namespace:  exportAllowList: |   {"namespace":["default"],"event_set":["PROCESS_EXEC"]} |
| tetragon.exportDenyList | string | `"{\"health_check\":true}\n{\"namespace\":[\"\", \"cilium\", \"tetragon\", \"kube-system\", \"hubble-timescape\"]}"` | Denylist for JSON export **(for file sinks only; does not filter gRPC output)**. For example, to exclude exec events that look similar to Kubernetes health checks and all the events from kube-system namespace and the host:  exportDenyList: |   {"health_check":true}   {"namespace":["kube-system",""]}  |
| tetragon.exportFileCompress | bool | `false` | Compress rotated JSON export files. |
| tetragon.exportFileMaxBackups | int | `5` | Number of rotated files to retain. |
| tetragon.exportFileMaxSizeMB | int | `10` | Size in megabytes at which to rotate JSON export files. |
| tetragon.exportFilePerm | string | `"600"` | JSON export file permissions as a string. Typically it's either "600" (to restrict access to owner) or "640"/"644" (to allow read access by logs collector or another agent). |
| tetragon.exportFilename | string | `"tetragon.log"` | JSON export filename. Set it to an empty string to disable JSON export altogether. |
| tetragon.exportRateLimit | int | `-1` | Rate-limit event export (events per minute). Must be a plain integer: -1 disables rate limiting and exports all events (default), 0 disables JSON export entirely, and a positive integer limits export to that many events per minute. Invalid (non-integer) values fall back to -1 and log a warning. |
| tetragon.extraArgs | object | `{}` |  |
| tetragon.extraEnv | list | `[]` |  |
| tetragon.extraVolumeMounts | list | `[]` |  |
| tetragon.fieldFilters | string | `""` | Filters to include or exclude fields from Tetragon events. Without any filters, all fields are included by default. The presence of at least one inclusion filter implies default-exclude (i.e. any fields that don't match an inclusion filter will be excluded). Field paths are expressed using dot notation like "a.b.c" and multiple field paths can be separated by commas like "a.b.c,d,e.f". An optional "event_set" may be specified to apply the field filter to a specific set of events.  For example, to exclude the "parent" field from all events and include the "process" field in PROCESS_KPROBE events while excluding all others:  fieldFilters: |   {"fields": "parent", "action": "EXCLUDE"}   {"event_set": ["PROCESS_KPROBE"], "fields": "process", "action": "INCLUDE"}  |
| tetragon.fimDispatcher.enabled | bool | `false` |  |
| tetragon.fimRuntimeEndpoint | string | `""` |  |
| tetragon.flowExportFileCompress | bool | `false` |  |
| tetragon.flowExportFileMaxBackups | int | `5` |  |
| tetragon.flowExportFileMaxSizeMB | int | `10` |  |
| tetragon.flowExportFilename | string | `""` | EXPERIMENTAL: Enable Hubble flow export. When this value is not empty, Tetragon exports ProcessConnect events as Hubble flow JSON in addition to exporting them as process_connect JSON. |
| tetragon.gops.address | string | `"localhost"` | The address at which to expose gops. |
| tetragon.gops.enabled | bool | `false` | Whether to enable exposing gops server. |
| tetragon.gops.port | int | `8118` | The port at which to expose gops. |
| tetragon.grpc.address | string | `"unix:///var/run/tetragon/tetragon.sock"` | The address at which to expose gRPC. Examples: localhost:54321, unix:///var/run/tetragon/tetragon.sock WARNING: Exposing gRPC on a TCP socket without TLS client verification exposes Tetragon to unprivileged users on the host or with network access. |
| tetragon.grpc.enabled | bool | `true` | Whether to enable exposing Tetragon gRPC. |
| tetragon.grpc.tls | object | `{"auto":{"certManagerIssuerRef":{},"certValidityDuration":365,"enabled":true,"method":"helm","schedule":"0 0 1 */4 *"},"ca":{"cert":"","certValidityDuration":1095,"key":""},"enabled":false,"requireClientCert":false,"server":{"existingSecret":"","extraDnsNames":[],"extraIpAddresses":[]}}` | gRPC TLS / mTLS configuration for the optional TCP listener (tetragon.grpc.address); the always-on unix-domain listener at /var/run/tetragon/tetragon.sock is unaffected.  The auto-provisioned server cert uses a wildcard SAN over a synthetic DNS domain (*.tetragon-grpc.cilium.io) so a single Secret covers every DaemonSet pod. Clients must override SNI to <any>.tetragon-grpc.cilium.io to validate. See _helpers.tpl `tetragon.grpcTls.domain` for details; add Service-style or per-node identities via server.extraDnsNames / server.extraIpAddresses below. |
| tetragon.grpc.tls.auto | object | `{"certManagerIssuerRef":{},"certValidityDuration":365,"enabled":true,"method":"helm","schedule":"0 0 1 */4 *"}` | Configure automatic TLS certificate generation. |
| tetragon.grpc.tls.auto.certManagerIssuerRef | object | `{}` | cert-manager IssuerRef used when method=certmanager. [Example] certManagerIssuerRef:   group: cert-manager.io   kind: ClusterIssuer   name: ca-issuer |
| tetragon.grpc.tls.auto.certValidityDuration | int | `365` | Generated certificate validity duration in days. Defaults to 365 (1 year). |
| tetragon.grpc.tls.auto.enabled | bool | `true` | Auto-generate certificates. When false, you must provide a Secret yourself (see server.existingSecret). |
| tetragon.grpc.tls.auto.method | string | `"helm"` | Method used to auto-generate certificates. Supported values: - helm:        Helm renders the cert/key Secret directly. - cronJob:     A Kubernetes CronJob runs cilium-certgen to (re)issue                the cert; a one-shot Job seeds it on install. - certmanager: cert-manager issues and rotates the cert. |
| tetragon.grpc.tls.auto.schedule | string | `"0 0 1 */4 *"` | Schedule for certificate regeneration; only honored when method=cronJob. Empty disables the recurring CronJob, leaving only the one-shot bootstrap Job. |
| tetragon.grpc.tls.ca | object | `{"cert":"","certValidityDuration":1095,"key":""}` | In-cluster CA used by the helm and cronJob methods. |
| tetragon.grpc.tls.ca.cert | string | `""` | base64-encoded PEM CA certificate. When both cert and key are set, helm/cronJob reuse this CA instead of generating a fresh one. |
| tetragon.grpc.tls.ca.certValidityDuration | int | `1095` | Validity duration in days for an auto-generated CA. Only used when ca.cert/key are unset. |
| tetragon.grpc.tls.ca.key | string | `""` | base64-encoded PEM CA private key. Required when ca.cert is set. |
| tetragon.grpc.tls.enabled | bool | `false` | Enable TLS on the TCP gRPC listener. When false, the listener (if any) is plaintext. |
| tetragon.grpc.tls.requireClientCert | bool | `false` | Require and verify client certificates (mTLS). When true, the agent rejects TCP gRPC connections that don't present a valid client cert signed by one of the bundled CAs. |
| tetragon.grpc.tls.server | object | `{"existingSecret":"","extraDnsNames":[],"extraIpAddresses":[]}` | Server cert configuration. |
| tetragon.grpc.tls.server.existingSecret | string | `""` | Use an existing Secret (must contain tls.crt + tls.key, plus ca.crt when requireClientCert is true) instead of provisioning one. Disables all auto-* methods when set. |
| tetragon.grpc.tls.server.extraDnsNames | list | `[]` | Extra DNS SANs added to auto-generated certificates. |
| tetragon.grpc.tls.server.extraIpAddresses | list | `[]` | Extra IP SANs added to auto-generated certificates. |
| tetragon.healthGrpc.enabled | bool | `true` | Whether to enable health gRPC server. |
| tetragon.healthGrpc.interval | int | `10` | The interval at which to check the health of the agent. |
| tetragon.healthGrpc.port | int | `6789` | The port at which to expose health gRPC. |
| tetragon.hostProcPath | string | `"/proc"` | Location of the host proc filesystem in the runtime environment. If the runtime runs in the host, the path is /proc. Exceptions to this are environments like kind, where the runtime itself does not run on the host. |
| tetragon.http.bpfContextCacheSize | int | `1000` |  |
| tetragon.http.enabled | bool | `false` |  |
| tetragon.http.http2Handling | bool | `true` |  |
| tetragon.http.metrics.enabled | bool | `true` |  |
| tetragon.http.metrics.labelFilter | string | `""` |  |
| tetragon.http.ports | string | `""` |  |
| tetragon.image.override | string | `nil` |  |
| tetragon.image.repository | string | `"artifactory.devhub-cloud.cisco.com/isovalent-iep-docker/tetragon"` |  |
| tetragon.image.tag | string | `"v1.20.0-pre.2"` |  |
| tetragon.k8sWatcher.policy.enabled | bool | `true` | Enable watching Kubernetes API server for policy resources. If true, Tetragon watches all supported policy resources: TracingPolicy(Namespaced), SandboxPolicy(Namespaced), AlertRule and TetragonNetworkPolicy(Namespaced), unless some of the features are disabled by other options, or Kubernetes API server is disabled entirely. |
| tetragon.layer3.bpfSocketCacheSize | int | `32768` |  |
| tetragon.layer3.bpfWatermarksCacheSize | int | `32768` |  |
| tetragon.layer3.disabled | bool | `false` |  |
| tetragon.layer3.icmp.bpfSocketCacheSize | int | `32768` |  |
| tetragon.layer3.icmp.enabled | bool | `false` |  |
| tetragon.layer3.icmp.socketTracking | bool | `false` |  |
| tetragon.layer3.icmp.v6info | bool | `false` |  |
| tetragon.layer3.igmp.enabled | bool | `false` |  |
| tetragon.layer3.rawsock.enabled | bool | `false` |  |
| tetragon.layer3.rawsock.metrics.enabled | bool | `true` |  |
| tetragon.layer3.rawsock.metrics.labelFilter | string | `""` |  |
| tetragon.layer3.rawsock.reportClose | bool | `false` |  |
| tetragon.layer3.tcp.bpfSocketCacheSize | int | `32768` |  |
| tetragon.layer3.tcp.disableEvents | string | `""` |  |
| tetragon.layer3.tcp.enabled | bool | `false` |  |
| tetragon.layer3.tcp.metrics.enabled | bool | `true` |  |
| tetragon.layer3.tcp.metrics.labelFilter | string | `""` |  |
| tetragon.layer3.tcp.rtt.enabled | bool | `false` |  |
| tetragon.layer3.tcp.rtt.max | int | `0` |  |
| tetragon.layer3.tcp.rtt.min | int | `0` |  |
| tetragon.layer3.tcp.statsInterval | string | `"0s"` |  |
| tetragon.layer3.tcp.watermarks.burstTriggerPercent | int | `0` |  |
| tetragon.layer3.tcp.watermarks.dipTriggerPercent | int | `0` |  |
| tetragon.layer3.tcp.watermarks.enabled | bool | `false` |  |
| tetragon.layer3.tcp.watermarks.windowSizeMs | int | `0` |  |
| tetragon.layer3.udp.bpfSocketCacheSize | int | `32768` |  |
| tetragon.layer3.udp.cgroup | bool | `true` |  |
| tetragon.layer3.udp.disableEvents | string | `""` |  |
| tetragon.layer3.udp.enabled | bool | `false` |  |
| tetragon.layer3.udp.idleSocketTimeout | string | `"2m"` |  |
| tetragon.layer3.udp.inKernelManaged | bool | `false` |  |
| tetragon.layer3.udp.metrics.enabled | bool | `true` |  |
| tetragon.layer3.udp.metrics.labelFilter | string | `""` |  |
| tetragon.layer3.udp.multicast.app | string | `""` |  |
| tetragon.layer3.udp.multicast.ports | string | `""` |  |
| tetragon.layer3.udp.multicast.samplePercent | int | `0` |  |
| tetragon.layer3.udp.multicast.seqCheck | bool | `false` |  |
| tetragon.layer3.udp.statsInterval | string | `"0s"` |  |
| tetragon.layer3.udp.watermarks.burstTriggerPercent | int | `0` |  |
| tetragon.layer3.udp.watermarks.dipTriggerPercent | int | `0` |  |
| tetragon.layer3.udp.watermarks.enabled | bool | `false` |  |
| tetragon.layer3.udp.watermarks.windowSizeMs | int | `0` |  |
| tetragon.layer3.watermarksExitGen.enabled | bool | `true` |  |
| tetragon.layer3.watermarksExitGen.interval | string | `"1s"` |  |
| tetragon.livenessProbe | object | `{}` | Overrides the default livenessProbe for the tetragon container. |
| tetragon.metadata.enabled | bool | `false` |  |
| tetragon.metadata.image.imagePullPolicy | string | `"Always"` |  |
| tetragon.metadata.image.override | string | `nil` |  |
| tetragon.metadata.image.repository | string | `"quay.io/isovalent/hubble-enterprise-metadata"` |  |
| tetragon.metadata.image.tag | string | `"current"` |  |
| tetragon.nameOverride | string | `""` |  |
| tetragon.networkInterfaceStats.enabled | bool | `false` |  |
| tetragon.networkInterfaceStats.interval | string | `"10s"` |  |
| tetragon.nop.enabled | bool | `false` |  |
| tetragon.nop.ports | string | `""` |  |
| tetragon.podAnnotations.enabled | bool | `false` |  |
| tetragon.pprof.address | string | `"localhost"` | The address at which to expose pprof. |
| tetragon.pprof.enabled | bool | `false` | Whether to enable exposing pprof server. |
| tetragon.pprof.port | int | `6060` | The port at which to expose pprof. |
| tetragon.processAncestors.enabled | string | `""` | Comma-separated list of process event types to enable ancestors for. Supported event types are: base, kprobe, tracepoint, loader, uprobe, lsm, usdt. Unknown event types will be ignored. Type "base" is required by all other supported event types for correct reference counting. Set it to "" to disable ancestors completely. |
| tetragon.processCacheGCInterval | string | `"30s"` | Configure the interval (suffixed with s for seconds, m for minutes, etc) for the process cache garbage collector. |
| tetragon.processCacheSize | int | `65536` | Tetragon puts processes in an LRU cache. The cache is used to find ancestors for subsequently exec'ed processes. |
| tetragon.prometheus.address | string | `""` | The address at which to expose metrics. Set it to "" to expose on all available interfaces. |
| tetragon.prometheus.enabled | bool | `true` | Whether to enable exposing Tetragon metrics. |
| tetragon.prometheus.metricsLabelFilter | string | `"namespace,workload,binary"` | Comma-separated list of enabled metrics labels. The configurable labels are: namespace, workload, pod, binary. Unknown labels will be ignored. Removing some labels from the list might help reduce the metrics cardinality if needed. |
| tetragon.prometheus.port | int | `2112` | The port at which to expose metrics. |
| tetragon.prometheus.serviceMonitor.enabled | bool | `false` | Whether to create a 'ServiceMonitor' resource targeting the tetragon pods. |
| tetragon.prometheus.serviceMonitor.extraLabels | object | `{}` | Extra labels to be added on the Tetragon ServiceMonitor. |
| tetragon.prometheus.serviceMonitor.labelsOverride | object | `{}` | The set of labels to place on the 'ServiceMonitor' resource. |
| tetragon.prometheus.serviceMonitor.scrapeInterval | string | `"60s"` | Interval at which metrics should be scraped. If not specified, Prometheus' global scrape interval is used. |
| tetragon.redactionFilters | string | `""` | Filters to redact secrets from the args fields in Tetragon events. To perform redactions, redaction filters define RE2 regular expressions in the `redact` field. Any capture groups in these RE2 regular expressions are redacted and replaced with "*****".  For more control, you can select which binary or binaries should have their arguments redacted with the `binary_regex` field.  NOTE: This feature uses RE2 as its regular expression library. Make sure that you follow RE2 regular expression guidelines as you may observe unexpected results otherwise. More information on RE2 syntax can be found [here](https://github.com/google/re2/wiki/Syntax).  NOTE: When writing regular expressions in JSON, it is important to escape backslash characters. For instance `\Wpasswd\W?` would be written as `{"redact": "\\Wpasswd\\W?"}`.  As a concrete example, the following will redact all passwords passed to processes with the "--password" argument:    {"redact": ["--password(?:\\s+|=)(\\S*)"]}  Now, an event which contains the string "--password=foo" would have that string replaced with "--password=*****".  Suppose we also see some passwords passed via the -p shorthand for a specific binary, foo. We can also redact these as follows:    {"binary_regex": ["(?:^|/)foo$"], "redact": ["-p(?:\\s+|=)(\\S*)"]}  With both of the above redaction filters in place, we are now redacting all password arguments.  Optionally, you can specify a custom replacement string using the `redact_str` field. If not specified, it defaults to "*****". This is useful for distinguishing different redaction rules:    {"redact": ["--password(?:\\\\s+|=)(\\\\S*)"], "redact_str": "<redacted:password>"}  |
| tetragon.resources | object | `{}` |  |
| tetragon.securityContext.privileged | bool | `true` |  |
| tetragon.startupProbe | object | `{}` | Overrides the default startupProbe for the tetragon container. |
| tetragon.telemetryExportFilename | string | `""` | Export filename for telemetry data (e.g "telemetry.log"). Set to empty to disable. Note that tetragon.enableApplicationModel must be set to true for Telemetry export to take effect. Telemetry export uses the export interval specified by tetragon.applicationModelExportInterval value. |
| tetragon.tls.bpfContextCacheSize | int | `32000` |  |
| tetragon.tls.enabled | bool | `false` |  |
| tetragon.tls.metrics.enabled | bool | `true` |  |
| tetragon.tls.metrics.labelFilter | string | `""` |  |
| tetragon.tls.mode | string | `"cgroup"` |  |
| tetragon.tls.ports | string | `""` |  |
| tetragon.usePerfRingBuffer | bool | `false` |  |
| tetragon.userDNS.enabled | bool | `false` |  |
| tetragon.userDNS.metrics.enabled | bool | `true` |  |
| tetragon.userDNS.metrics.labelFilter | string | `""` |  |
| tetragon.userDNS.ports | string | `""` |  |
| tetragon.userDNS.reportQuestions | bool | `false` |  |
| tetragonAggregator.affinity | object | `{}` |  |
| tetragonAggregator.annotations | object | `{}` | Annotations for the Tetragon Aggregator Deployment. |
| tetragonAggregator.enabled | bool | `false` | Enables the Tetragon Aggregator. |
| tetragonAggregator.extraLabels | object | `{}` | Extra labels to be added on the Tetragon Aggregator Deployment. |
| tetragonAggregator.extraPodLabels | object | `{}` | Extra labels to be added on the Tetragon Aggregator Deployment Pods. |
| tetragonAggregator.extraVolumeMounts | list | `[]` |  |
| tetragonAggregator.extraVolumes | list | `[]` | Extra volumes for the Tetragon Aggregator Deployment. |
| tetragonAggregator.image | object | `{"override":null,"pullPolicy":"IfNotPresent","repository":"artifactory.devhub-cloud.cisco.com/isovalent-iep-docker/tetragon-aggregator","tag":"v1.20.0-pre.2"}` | tetragon-aggregator image. |
| tetragonAggregator.nodeSelector | object | `{}` | Steer the Tetragon Aggregator Deployment Pod placement via nodeSelector, tolerations and affinity rules. |
| tetragonAggregator.podAnnotations | object | `{}` | Annotations for the Tetragon Aggregator Deployment Pods. |
| tetragonAggregator.podSecurityContext | object | `{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]}}` | securityContext for the Tetragon Aggregator Deployment Pod container. |
| tetragonAggregator.priorityClassName | string | `""` | priorityClassName for the Tetragon Aggregator Deployment Pods. |
| tetragonAggregator.resources | object | `{}` | resources for the Tetragon Operator Deployment Pod container. |
| tetragonAggregator.securityContext | object | `{}` | securityContext for the Tetragon Aggregator Deployment Pods. |
| tetragonAggregator.strategy | object | `{}` | resources for the Tetragon Aggregator Deployment update strategy |
| tetragonAggregator.tolerations | list | `[]` |  |
| tetragonOperator.affinity.podAntiAffinity.preferredDuringSchedulingIgnoredDuringExecution[0].podAffinityTerm.labelSelector.matchLabels."app.kubernetes.io/name" | string | `"tetragon-operator"` |  |
| tetragonOperator.affinity.podAntiAffinity.preferredDuringSchedulingIgnoredDuringExecution[0].podAffinityTerm.topologyKey | string | `"kubernetes.io/hostname"` |  |
| tetragonOperator.affinity.podAntiAffinity.preferredDuringSchedulingIgnoredDuringExecution[0].weight | int | `100` |  |
| tetragonOperator.annotations | object | `{}` | Annotations for the Tetragon Operator Deployment. |
| tetragonOperator.containerSecurityContext | object | `{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]},"runAsGroup":65532,"runAsNonRoot":true,"runAsUser":65532}` | securityContext for the Tetragon Operator Deployment Pod container. |
| tetragonOperator.enabled | bool | `true` | Enables the Tetragon Operator. |
| tetragonOperator.extraLabels | object | `{}` | Extra labels to be added on the Tetragon Operator Deployment. |
| tetragonOperator.extraPodLabels | object | `{}` | Extra labels to be added on the Tetragon Operator Deployment Pods. |
| tetragonOperator.extraVolumeMounts | list | `[]` |  |
| tetragonOperator.extraVolumes | list | `[]` | Extra volumes for the Tetragon Operator Deployment. |
| tetragonOperator.failoverLease | object | `{"enabled":false,"leaseDuration":"15s","leaseRenewDeadline":"5s","leaseRetryPeriod":"2s","namespace":""}` | Lease handling for an automated failover when running multiple replicas |
| tetragonOperator.failoverLease.enabled | bool | `false` | Enable lease failover functionality |
| tetragonOperator.failoverLease.leaseDuration | string | `"15s"` | If a lease is not renewed for X duration, the current leader is considered dead, a new leader is picked |
| tetragonOperator.failoverLease.leaseRenewDeadline | string | `"5s"` | The interval at which the leader will renew the lease |
| tetragonOperator.failoverLease.leaseRetryPeriod | string | `"2s"` | The timeout between retries if renewal fails |
| tetragonOperator.failoverLease.namespace | string | `""` | Kubernetes Namespace in which the Lease resource is created. Defaults to the namespace where Tetragon is deployed in, if it's empty. |
| tetragonOperator.forceUpdateCRDs | bool | `false` |  |
| tetragonOperator.hostUsers | bool | `true` | Run the Tetragon Operator Deployment Pods in the host user namespace. The operator needs no host access, set to false to run it in a user namespace. Requires Kubernetes 1.33 or later. |
| tetragonOperator.image | object | `{"override":null,"pullPolicy":"IfNotPresent","repository":"artifactory.devhub-cloud.cisco.com/isovalent-iep-docker/tetragon-operator","tag":"v1.20.0-pre.2"}` | tetragon-operator image. |
| tetragonOperator.nameOverride | string | `""` | The name of the Tetragon Operator deployment. |
| tetragonOperator.nodeSelector | object | `{}` | Steer the Tetragon Operator Deployment Pod placement via nodeSelector, tolerations and affinity rules. |
| tetragonOperator.podAnnotations | object | `{}` | Annotations for the Tetragon Operator Deployment Pods. |
| tetragonOperator.podInfo.enabled | bool | `true` | Enables the PodInfo CRD and the controller that reconciles PodInfo custom resources. |
| tetragonOperator.podSecurityContext | object | `{}` | securityContext for the Tetragon Operator Deployment Pods. |
| tetragonOperator.priorityClassName | string | `""` | priorityClassName for the Tetragon Operator Deployment Pods. |
| tetragonOperator.prometheus.address | string | `""` | The address at which to expose Tetragon Operator metrics. Set it to "" to expose on all available interfaces. |
| tetragonOperator.prometheus.enabled | bool | `true` | Enables the Tetragon Operator metrics. |
| tetragonOperator.prometheus.port | int | `2113` | The port at which to expose metrics. |
| tetragonOperator.prometheus.serviceMonitor.enabled | bool | `false` | Whether to create a 'ServiceMonitor' resource targeting the tetragonOperator pods. |
| tetragonOperator.prometheus.serviceMonitor.extraLabels | object | `{}` | Extra labels to be added on the Tetragon Operator ServiceMonitor. |
| tetragonOperator.prometheus.serviceMonitor.labelsOverride | object | `{}` | The set of labels to place on the 'ServiceMonitor' resource. |
| tetragonOperator.prometheus.serviceMonitor.scrapeInterval | string | `"60s"` | Interval at which metrics should be scraped. If not specified, Prometheus' global scrape interval is used. |
| tetragonOperator.replicas | int | `1` | Number of replicas to run for the tetragon-operator deployment |
| tetragonOperator.resources | object | `{"limits":{"cpu":"500m","memory":"128Mi"},"requests":{"cpu":"10m","memory":"64Mi"}}` | resources for the Tetragon Operator Deployment Pod container. |
| tetragonOperator.securityContext | object | `{}` | securityContext for the Tetragon Operator Deployment Pod container. (DEPRECATED: Use containerSecurityContext instead. TODO: Remove in v1.6.0) |
| tetragonOperator.serviceAccount | object | `{"annotations":{},"create":true,"name":""}` | tetragon-operator service account. |
| tetragonOperator.strategy | object | `{"rollingUpdate":{"maxSurge":1,"maxUnavailable":0},"type":"RollingUpdate"}` | resources for the Tetragon Operator Deployment update strategy |
| tetragonOperator.tolerations | list | `[]` |  |
| tetragonOperator.tracingPolicy.enabled | bool | `true` | Enables the TracingPolicy and TracingPolicyNamespaced CRD creation. |
| tolerations[0].operator | string | `"Exists"` |  |
| tracingPolicies | object | `{"default":{"enabled":false,"fim":{"enabled":false},"mount":{"enabled":false},"network":{"enabled":false},"osi":{"enabled":false},"privileges":{"enabled":false}}}` | Deprecated: Install tracing policies. These options require the TracingPolicy CRD to be present in the cluster. Normally Tetragon CRDs are installed by either the Tetragon operator (which is installed by the same Helm chart) or by the same Helm chart (see crds.installMethod). This means we have a chicken-and-egg situation here. To avoid races, most users should disable tracing policies when first installing Tetragon Helm chart and enable them after CRDs are created. The default policies and the tracingPolicies.default values will be removed in the next release. |
| tracingPolicies.default.enabled | bool | `false` | Deprecated: Enable all default ruleset policies. |
| tracingPolicies.default.fim.enabled | bool | `false` | Deprecated: Enable the File Integrity Monitoring (FIM) policy. |
| tracingPolicies.default.mount.enabled | bool | `false` | Deprecated: Enable the Changing Mounts and root filesystem policy. |
| tracingPolicies.default.network.enabled | bool | `false` | Deprecated: Enable the Network policy. |
| tracingPolicies.default.osi.enabled | bool | `false` | Deprecated: Enable the Operating System Integrity (OSI) policy. |
| tracingPolicies.default.privileges.enabled | bool | `false` | Deprecated: Enable the Privileges monitoring policy. |
| updateStrategy | object | `{}` |  |

----------------------------------------------
Autogenerated from chart metadata using [helm-docs v1.14.2](https://github.com/norwoodj/helm-docs/releases/v1.14.2)

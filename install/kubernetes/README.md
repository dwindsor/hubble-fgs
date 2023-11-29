# tetragon

![Version: 1.13.0-pre.1](https://img.shields.io/badge/Version-1.13.0--pre.1-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) ![AppVersion: 1.13.0-pre.1](https://img.shields.io/badge/AppVersion-1.13.0--pre.1-informational?style=flat-square)

Helm chart for Tetragon Enterprise

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| affinity | object | `{}` |  |
| daemonSetAnnotations | object | `{}` |  |
| daemonSetLabelsOverride | object | `{}` |  |
| dnsPolicy | string | `"Default"` |  |
| enabled | bool | `true` |  |
| export.argsOverride | list | `[]` |  |
| export.commandOverride | list | `[]` |  |
| export.extraArgs | object | `{}` |  |
| export.extraEnv | list | `[]` |  |
| export.extraVolumeMounts | list | `[]` |  |
| export.filenames[0] | string | `"tetragon.log"` |  |
| export.mode | string | `""` |  |
| export.securityContext | object | `{}` |  |
| export.stdout.image.override | string | `nil` |  |
| export.stdout.image.repository | string | `"quay.io/isovalent/hubble-export-stdout"` |  |
| export.stdout.image.tag | string | `"v1.0.3"` |  |
| exportDirectory | string | `"/var/run/cilium/tetragon"` |  |
| exportFileCreationInterval | string | `"120s"` |  |
| extraConfigmapMounts | list | `[]` |  |
| extraHostPathMounts | list | `[]` |  |
| extraVolumes | list | `[]` |  |
| hostNetwork | bool | `true` |  |
| imagePullPolicy | string | `"IfNotPresent"` |  |
| imagePullSecrets | list | `[]` |  |
| nodeSelector | object | `{}` |  |
| podAnnotations | object | `{}` |  |
| podLabels | object | `{}` |  |
| podLabelsOverride | object | `{}` |  |
| podSecurityContext | object | `{}` |  |
| priorityClassName | string | `""` |  |
| selectorLabelsOverride | object | `{}` |  |
| serviceAccount.annotations | object | `{}` |  |
| serviceAccount.create | bool | `true` |  |
| serviceAccount.name | string | `""` |  |
| serviceLabelsOverride | object | `{}` |  |
| tetragon.argsOverride | list | `[]` |  |
| tetragon.btf | string | `""` |  |
| tetragon.commandOverride | list | `[]` |  |
| tetragon.enableCiliumAPI | bool | `false` | Access Cilium API to associate Tetragon events with Cilium DNS cache. |
| tetragon.enableK8sAPI | bool | `true` |  |
| tetragon.enablePolicyFilter | bool | `false` | Enable policy filter. This is required for K8s namespace and pod-label filtering. This feature is in beta, so disabled by default. |
| tetragon.enablePolicyFilterDebug | bool | `false` | Enable policy filter debug messages. |
| tetragon.enableProcessCred | bool | `false` |  |
| tetragon.enableProcessNs | bool | `false` |  |
| tetragon.enabled | bool | `true` |  |
| tetragon.exportAllowList | string | `"{\"event_set\":[\"PROCESS_CONNECT\", \"PROCESS_EXEC\", \"PROCESS_HTTP\", \"PROCESS_KPROBE\", \"PROCESS_LISTEN\", \"PROCESS_TLS\"]}"` |  |
| tetragon.exportDenyList | string | `"{\"health_check\":true}\n{\"namespace\":[\"\", \"cilium\", \"kube-system\"]}"` |  |
| tetragon.exportFileCompress | bool | `false` |  |
| tetragon.exportFileMaxBackups | int | `5` |  |
| tetragon.exportFileMaxSizeMB | int | `10` |  |
| tetragon.exportFilePerm | string | `"644"` |  |
| tetragon.exportFilename | string | `"tetragon.log"` |  |
| tetragon.exportRateLimit | int | `-1` |  |
| tetragon.extraArgs | object | `{}` |  |
| tetragon.extraEnv | list | `[]` |  |
| tetragon.extraVolumeMounts | list | `[]` |  |
| tetragon.fieldFilters | string | `"{}"` |  |
| tetragon.fimRuntimeEndpoint | string | `""` |  |
| tetragon.flowExportFileCompress | bool | `false` |  |
| tetragon.flowExportFileMaxBackups | int | `5` |  |
| tetragon.flowExportFileMaxSizeMB | int | `10` |  |
| tetragon.flowExportFilename | string | `""` | EXPERIMENTAL: Enable Hubble flow export. When this value is not empty, Tetragon exports ProcessConnect events as Hubble flow JSON in addition to exporting them as process_connect JSON. |
| tetragon.gops.address | string | `"localhost"` | The address at which to expose gops. |
| tetragon.gops.port | int | `8118` | The port at which to expose gops. |
| tetragon.grpc.address | string | `"localhost:54321"` | The address at which to expose gRPC. Examples: localhost:54321, unix:///var/run/tetragon/tetragon.sock |
| tetragon.grpc.enabled | bool | `true` | Whether to enable exposing Tetragon gRPC. |
| tetragon.hostProcPath | string | `"/proc"` | Location of the host proc filesystem in the runtime environment. If the runtime runs in the host, the path is /proc. Exceptions to this are environments like kind, where the runtime itself does not run on the host. |
| tetragon.image.override | string | `nil` |  |
| tetragon.image.repository | string | `"quay.io/isovalent/tetragon"` |  |
| tetragon.image.tag | string | `"v1.13.0-pre.1"` |  |
| tetragon.metadata.enabled | bool | `false` |  |
| tetragon.metadata.image.imagePullPolicy | string | `"Always"` |  |
| tetragon.metadata.image.override | string | `nil` |  |
| tetragon.metadata.image.repository | string | `"quay.io/isovalent/hubble-enterprise-metadata"` |  |
| tetragon.metadata.image.tag | string | `"current"` |  |
| tetragon.processCacheSize | int | `65536` |  |
| tetragon.prometheus.address | string | `""` | The address at which to expose metrics. Set it to "" to expose on all available interfaces. |
| tetragon.prometheus.enabled | bool | `true` | Whether to enable exposing Tetragon metrics. |
| tetragon.prometheus.port | int | `2112` | The port at which to expose metrics. |
| tetragon.prometheus.serviceMonitor.enabled | bool | `false` | Whether to create a 'ServiceMonitor' resource targeting the tetragon pods. |
| tetragon.prometheus.serviceMonitor.labelsOverride | object | `{}` | The set of labels to place on the 'ServiceMonitor' resource. |
| tetragon.prometheus.serviceMonitor.scrapeInterval | string | `"10s"` | Interval at which metrics should be scraped. If not specified, Prometheus' global scrape interval is used. |
| tetragon.resources | object | `{}` |  |
| tetragon.securityContext.privileged | bool | `true` |  |
| tetragon.tcpStatsSampleSegs | int | `0` | EXPERIMENTAL: This field may be removed in the future without notice.  Enable TCP segment sampling to collect metrics. Recommended sample rate: 4096. Set it to zero to disable.  Note that the counter for sampling is global, and it is not per socket. |
| tetragonOperator.image | object | `{"override":null,"pullPolicy":"IfNotPresent","repository":"quay.io/isovalent/tetragon-operator","tag":"v1.13.0-pre.1"}` | tetragon-operator image. |
| tetragonOperator.podInfo.enabled | bool | `true` | Enables the PodInfo CRD and the controller that reconciles PodInfo custom resources. |
| tetragonOperator.skipCRDCreation | bool | `false` |  |
| tolerations[0].operator | string | `"Exists"` |  |
| updateStrategy | object | `{}` |  |

----------------------------------------------
Autogenerated from chart metadata using [helm-docs v1.11.0](https://github.com/norwoodj/helm-docs/releases/v1.11.0)

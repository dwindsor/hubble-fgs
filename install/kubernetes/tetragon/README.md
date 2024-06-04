# tetragon

![Version: 0.0.0-dev](https://img.shields.io/badge/Version-0.0.0--dev-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) ![AppVersion: 0.0.0-dev](https://img.shields.io/badge/AppVersion-0.0.0--dev-informational?style=flat-square)

Helm chart for Tetragon Enterprise

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| affinity | object | `{}` |  |
| crds.installMethod | string | `"operator"` | Method for installing CRDs. Supported values are: "operator", "helm" and "none". The "operator" method allows for fine-grained control over which CRDs are installed and by default doesn't perform CRD downgrades. These can be configured in tetragonOperator section. The "helm" method always installs all CRDs for the chart version. |
| daemonSetAnnotations | object | `{}` |  |
| daemonSetLabelsOverride | object | `{}` |  |
| dnsPolicy | string | `"Default"` |  |
| enabled | bool | `true` | Global settings |
| export | object | `{"argsOverride":[],"commandOverride":[],"extraArgs":{},"extraEnv":[],"extraVolumeMounts":[],"filenames":["tetragon.log"],"mode":"","securityContext":{},"stdout":{"image":{"override":null,"repository":"quay.io/isovalent/hubble-export-stdout","tag":"v1.0.4"}}}` | Tetragon event settings |
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
| priorityClassName | string | `""` | Tetragon agent settings |
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
| tetragon.enableMsgHandlingLatency | bool | `false` | Enable latency monitoring in message handling |
| tetragon.enablePolicyFilter | bool | `true` | Enable policy filter. This is required for K8s namespace and pod-label filtering. |
| tetragon.enablePolicyFilterDebug | bool | `false` | Enable policy filter debug messages. |
| tetragon.enableProcessCred | bool | `false` |  |
| tetragon.enableProcessNs | bool | `false` |  |
| tetragon.enableSandboxpolicies | bool | `true` | Enable sandboxpolicies. |
| tetragon.enabled | bool | `true` |  |
| tetragon.exportAllowList | string | `"{\"event_set\":[\"PROCESS_CONNECT\", \"PROCESS_EXEC\", \"PROCESS_FILE\", \"PROCESS_HTTP\", \"PROCESS_KPROBE\", \"PROCESS_LISTEN\", \"PROCESS_SANDBOX_SYSCALL\", \"PROCESS_TLS\"]}"` |  |
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
| tetragon.fieldFilters | string | `""` |  |
| tetragon.fimRuntimeEndpoint | string | `""` |  |
| tetragon.flowExportFileCompress | bool | `false` |  |
| tetragon.flowExportFileMaxBackups | int | `5` |  |
| tetragon.flowExportFileMaxSizeMB | int | `10` |  |
| tetragon.flowExportFilename | string | `""` | EXPERIMENTAL: Enable Hubble flow export. When this value is not empty, Tetragon exports ProcessConnect events as Hubble flow JSON in addition to exporting them as process_connect JSON. |
| tetragon.gops.address | string | `"localhost"` | The address at which to expose gops. |
| tetragon.gops.port | int | `8118` | The port at which to expose gops. |
| tetragon.grpc.address | string | `"localhost:54321"` | The address at which to expose gRPC. Examples: localhost:54321, unix:///var/run/tetragon/tetragon.sock |
| tetragon.grpc.enabled | bool | `true` | Whether to enable exposing Tetragon gRPC. |
| tetragon.healthGrpc.enabled | bool | `true` | Whether to enable health gRPC server. |
| tetragon.healthGrpc.interval | int | `10` | The interval at which to check the health of the agent. |
| tetragon.healthGrpc.port | int | `6789` | The port at which to expose health gRPC. |
| tetragon.hostProcPath | string | `"/proc"` | Location of the host proc filesystem in the runtime environment. If the runtime runs in the host, the path is /proc. Exceptions to this are environments like kind, where the runtime itself does not run on the host. |
| tetragon.image.override | string | `nil` |  |
| tetragon.image.repository | string | `"quay.io/isovalent/tetragon"` |  |
| tetragon.image.tag | string | `"v1.14.0-pre.0"` |  |
| tetragon.livenessProbe | object | `{}` | Overrides the default livenessProbe for the tetragon container. |
| tetragon.metadata.enabled | bool | `false` |  |
| tetragon.metadata.image.imagePullPolicy | string | `"Always"` |  |
| tetragon.metadata.image.override | string | `nil` |  |
| tetragon.metadata.image.repository | string | `"quay.io/isovalent/hubble-enterprise-metadata"` |  |
| tetragon.metadata.image.tag | string | `"current"` |  |
| tetragon.ociHookSetup | object | `{"enabled":false,"extraVolumeMounts":[],"failAllowNamespaces":"","installDir":"/opt/tetragon","interface":"oci-hooks","resources":{},"securityContext":{"privileged":true}}` | Configure tetragon's init container for setting up tetragon-oci-hook on the host |
| tetragon.ociHookSetup.enabled | bool | `false` | enable  init container to setup tetragon-oci-hook |
| tetragon.ociHookSetup.extraVolumeMounts | list | `[]` | Extra volume mounts to add to the oci-hook-setup init container |
| tetragon.ociHookSetup.failAllowNamespaces | string | `""` | Comma-separated list of namespaces to allow Pod creation for, in case tetragon-oci-hook fails to reach Tetragon agent. The namespace Tetragon is deployed in is always added as an exception and must not be added again. |
| tetragon.ociHookSetup.interface | string | `"oci-hooks"` | interface specifices how the hook is  configured. There is only one avaialble value for now: "oci-hooks" (https://github.com/containers/common/blob/main/pkg/hooks/docs/oci-hooks.5.md). |
| tetragon.ociHookSetup.resources | object | `{}` | resources for the the oci-hook-setup init container |
| tetragon.ociHookSetup.securityContext | object | `{"privileged":true}` | Security context for oci-hook-setup init container |
| tetragon.processCacheSize | int | `65536` |  |
| tetragon.prometheus.address | string | `""` | The address at which to expose metrics. Set it to "" to expose on all available interfaces. |
| tetragon.prometheus.enabled | bool | `true` | Whether to enable exposing Tetragon metrics. |
| tetragon.prometheus.metricsLabelFilter | string | `"namespace,workload,pod,binary"` | Comma-separated list of enabled metrics labels. The configurable labels are: namespace, workload, pod, binary. Unkown labels will be ignored. Removing some labels from the list might help reduce the metrics cardinality if needed. |
| tetragon.prometheus.port | int | `2112` | The port at which to expose metrics. |
| tetragon.prometheus.serviceMonitor.enabled | bool | `false` | Whether to create a 'ServiceMonitor' resource targeting the tetragon pods. |
| tetragon.prometheus.serviceMonitor.labelsOverride | object | `{}` | The set of labels to place on the 'ServiceMonitor' resource. |
| tetragon.prometheus.serviceMonitor.scrapeInterval | string | `"10s"` | Interval at which metrics should be scraped. If not specified, Prometheus' global scrape interval is used. |
| tetragon.redactionFilters | string | `""` |  |
| tetragon.resources | object | `{}` |  |
| tetragon.securityContext.privileged | bool | `true` |  |
| tetragon.tcpStatsSampleSegs | int | `0` | EXPERIMENTAL: This field may be removed in the future without notice.  Enable TCP segment sampling to collect metrics. Recommended sample rate: 4096. Set it to zero to disable.  Note that the counter for sampling is global, and it is not per socket. |
| tetragonOperator | object | `{"affinity":{},"annotations":{},"enabled":true,"extraLabels":{},"extraPodLabels":{},"extraVolumeMounts":[],"extraVolumes":[],"forceUpdateCRDs":false,"image":{"override":null,"pullPolicy":"IfNotPresent","repository":"quay.io/isovalent/tetragon-operator","tag":"v1.14.0-pre.0"},"nodeSelector":{},"podAnnotations":{},"podInfo":{"enabled":true},"podSecurityContext":{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]}},"priorityClassName":"","prometheus":{"address":"","enabled":true,"port":2113,"serviceMonitor":{"enabled":false,"labelsOverride":{},"scrapeInterval":"10s"}},"resources":{"limits":{"cpu":"500m","memory":"128Mi"},"requests":{"cpu":"10m","memory":"64Mi"}},"securityContext":{},"serviceAccount":{"annotations":{},"create":true,"name":""},"strategy":{},"tolerations":[{"operator":"Exists"}],"tracingPolicy":{"enabled":true}}` | Tetragon Operator settings |
| tetragonOperator.annotations | object | `{}` | Annotations for the Tetragon Operator Deployment. |
| tetragonOperator.enabled | bool | `true` | Enables the Tetragon Operator. |
| tetragonOperator.extraLabels | object | `{}` | Extra labels to be added on the Tetragon Operator Deployment. |
| tetragonOperator.extraPodLabels | object | `{}` | Extra labels to be added on the Tetragon Operator Deployment Pods. |
| tetragonOperator.extraVolumes | list | `[]` | Extra volumes for the Tetragon Operator Deployment. |
| tetragonOperator.image | object | `{"override":null,"pullPolicy":"IfNotPresent","repository":"quay.io/isovalent/tetragon-operator","tag":"v1.14.0-pre.0"}` | tetragon-operator image. |
| tetragonOperator.nodeSelector | object | `{}` | Steer the Tetragon Operator Deployment Pod placement via nodeSelector, tolerations and affinity rules. |
| tetragonOperator.podAnnotations | object | `{}` | Annotations for the Tetragon Operator Deployment Pods. |
| tetragonOperator.podInfo.enabled | bool | `true` | Enables the PodInfo CRD and the controller that reconciles PodInfo custom resources. |
| tetragonOperator.podSecurityContext | object | `{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]}}` | securityContext for the Tetragon Operator Deployment Pod container. |
| tetragonOperator.priorityClassName | string | `""` | priorityClassName for the Tetragon Operator Deployment Pods. |
| tetragonOperator.prometheus | object | `{"address":"","enabled":true,"port":2113,"serviceMonitor":{"enabled":false,"labelsOverride":{},"scrapeInterval":"10s"}}` | Enables the Tetragon Operator metrics. |
| tetragonOperator.prometheus.address | string | `""` | The address at which to expose Tetragon Operator metrics. Set it to "" to expose on all available interfaces. |
| tetragonOperator.prometheus.port | int | `2113` | The port at which to expose metrics. |
| tetragonOperator.prometheus.serviceMonitor | object | `{"enabled":false,"labelsOverride":{},"scrapeInterval":"10s"}` | The labels to include with supporting metrics. |
| tetragonOperator.prometheus.serviceMonitor.enabled | bool | `false` | Whether to create a 'ServiceMonitor' resource targeting the tetragonOperator pods. |
| tetragonOperator.prometheus.serviceMonitor.labelsOverride | object | `{}` | The set of labels to place on the 'ServiceMonitor' resource. |
| tetragonOperator.prometheus.serviceMonitor.scrapeInterval | string | `"10s"` | Interval at which metrics should be scraped. If not specified, Prometheus' global scrape interval is used. |
| tetragonOperator.resources | object | `{"limits":{"cpu":"500m","memory":"128Mi"},"requests":{"cpu":"10m","memory":"64Mi"}}` | resources for the Tetragon Operator Deployment Pod container. |
| tetragonOperator.securityContext | object | `{}` | securityContext for the Tetragon Operator Deployment Pods. |
| tetragonOperator.serviceAccount | object | `{"annotations":{},"create":true,"name":""}` | tetragon-operator service account. |
| tetragonOperator.strategy | object | `{}` | resources for the Tetragon Operator Deployment update strategy |
| tetragonOperator.tracingPolicy.enabled | bool | `true` | Enables the TracingPolicy and TracingPolicyNamespaced CRD creation. |
| tolerations[0].operator | string | `"Exists"` |  |
| tracingPolicies | object | `{"default":{"enabled":false,"fim":{"enabled":false},"network":{"enabled":false},"osi":{"enabled":false},"privileges":{"enabled":false},"security":{"enabled":false}}}` | Install tracing policies. These options require the TracingPolicy CRD to be present in the cluster. Normally Tetragon CRDs are installed by either the Tetragon operator (which is installed by the same Helm chart) or by the same Helm chart (see crds.installMethod). This means we have a chicken-and-egg situation here. To avoid races, most users should disable tracing policies when first installing Tetragon Helm chart and enable them after CRDs are created. |
| tracingPolicies.default.enabled | bool | `false` | Enable all default ruleset policies. |
| tracingPolicies.default.fim.enabled | bool | `false` | Enable File Integrity Monitoring (FIM) default policy. |
| tracingPolicies.default.network.enabled | bool | `false` | Enable Network default policy. |
| tracingPolicies.default.osi.enabled | bool | `false` | Enable Operating System Integrity default policy. |
| tracingPolicies.default.privileges.enabled | bool | `false` | Enable Privileges monitoring default policy. |
| tracingPolicies.default.security.enabled | bool | `false` | Enable Security Sensitive Events default policy. |
| updateStrategy | object | `{}` |  |

----------------------------------------------
Autogenerated from chart metadata using [helm-docs v1.11.0](https://github.com/norwoodj/helm-docs/releases/v1.11.0)

# hubble-enterprise

![Version: 0.0.0-dev](https://img.shields.io/badge/Version-0.0.0--dev-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) ![AppVersion: 0.0.0-dev](https://img.shields.io/badge/AppVersion-0.0.0--dev-informational?style=flat-square)

Helm chart for Hubble Enterprise

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| affinity | object | `{}` |  |
| daemonSetAnnotations | object | `{}` |  |
| daemonSetLabelsOverride | object | `{}` |  |
| dnsPolicy | string | `"Default"` |  |
| enabled | bool | `true` |  |
| enterprise.argsOverride | list | `[]` |  |
| enterprise.btf | string | `""` |  |
| enterprise.commandOverride | list | `[]` |  |
| enterprise.enableCiliumAPI | bool | `true` |  |
| enterprise.enableK8sAPI | bool | `true` |  |
| enterprise.enablePolicyFilter | bool | `false` | Enable policy filter. This is required for K8s namespace and pod-label filtering. This feature is in beta, so disabled by default. |
| enterprise.enablePolicyFilterDebug | bool | `false` | Enable policy filter debug messages. |
| enterprise.enableProcessCred | bool | `false` |  |
| enterprise.enableProcessNs | bool | `false` |  |
| enterprise.enableTLSEvents | bool | `false` |  |
| enterprise.enabled | bool | `true` |  |
| enterprise.exportAllowList | string | `"{\"event_set\":[\"PROCESS_CONNECT\", \"PROCESS_EXEC\", \"PROCESS_HTTP\", \"PROCESS_KPROBE\", \"PROCESS_LISTEN\", \"PROCESS_TLS\"]}"` |  |
| enterprise.exportDenyList | string | `"{\"health_check\":true}\n{\"namespace\":[\"\", \"cilium\", \"kube-system\"]}"` |  |
| enterprise.exportFileCompress | bool | `false` |  |
| enterprise.exportFileMaxBackups | int | `5` |  |
| enterprise.exportFileMaxSizeMB | int | `10` |  |
| enterprise.exportFilename | string | `"fgs.log"` |  |
| enterprise.exportRateLimit | int | `-1` |  |
| enterprise.extraArgs | object | `{}` |  |
| enterprise.extraEnv | list | `[]` |  |
| enterprise.extraVolumeMounts | list | `[]` |  |
| enterprise.fieldFilters | string | `"{}"` |  |
| enterprise.fimRuntimeEndpoint | string | `""` |  |
| enterprise.gops.address | string | `"localhost"` | The address at which to expose gops. |
| enterprise.gops.port | int | `8118` | The port at which to expose gops. |
| enterprise.grpc.address | string | `"localhost:54321"` | The address at which to expose gRPC. Examples: localhost:54321, unix:///var/run/tetragon/tetragon.sock |
| enterprise.grpc.enabled | bool | `true` | Whether to enable exposing Hubble Enterprise gRPC. |
| enterprise.image.override | string | `nil` |  |
| enterprise.image.repository | string | `"quay.io/isovalent/hubble-enterprise"` |  |
| enterprise.image.tag | string | `"v1.11.0"` |  |
| enterprise.metadataImage.imagePullPolicy | string | `"Always"` |  |
| enterprise.metadataImage.override | string | `nil` |  |
| enterprise.metadataImage.repository | string | `"quay.io/isovalent/hubble-enterprise-metadata"` |  |
| enterprise.metadataImage.tag | string | `"current"` |  |
| enterprise.processCacheSize | int | `65536` |  |
| enterprise.prometheus.address | string | `""` | The address at which to expose metrics. Set it to "" to expose on all available interfaces. |
| enterprise.prometheus.enabled | bool | `true` | Whether to enable exposing Hubble Enterprise metrics. |
| enterprise.prometheus.port | int | `2112` | The port at which to expose metrics. |
| enterprise.prometheus.serviceMonitor.enabled | bool | `false` | Whether to create a 'ServiceMonitor' resource targeting the 'hubble-enterprise' pods. |
| enterprise.prometheus.serviceMonitor.labelsOverride | object | `{}` | The set of labels to place on the 'ServiceMonitor' resource. |
| enterprise.resources | object | `{}` |  |
| enterprise.securityContext.privileged | bool | `true` |  |
| enterprise.tcpStatsSampleSegs | int | `0` | EXPERIMENTAL: This field may be removed in the future without notice.  Enable TCP segment sampling to collect metrics. Recommended sample rate: 4096. Set it to zero to disable.  Note that the counter for sampling is global, and it is not per socket. |
| export.argsOverride | list | `[]` |  |
| export.commandOverride | list | `[]` |  |
| export.extraArgs | object | `{}` |  |
| export.extraEnv | list | `[]` |  |
| export.extraVolumeMounts | list | `[]` |  |
| export.filenames[0] | string | `"fgs.log"` |  |
| export.filenames[1] | string | `"hubble.log"` |  |
| export.fluentd.config | string | `"@include input.conf\n@include filter.conf\n@include output.conf\n"` |  |
| export.fluentd.filterConfig | string | `"<match hubble-logs.**>\n  @type rewrite_tag_filter\n  <rule>\n    key node_name\n    pattern /.+/\n    # /var/run/cilium/hubble/hubble.log has a tag of var.run.cilium.hubble.hubble.log\n    # and the rewrite rule changes it to hubble.log\n    tag ${tag_parts[5]}.${tag_parts[6]}\n  </rule>\n</match>\n"` |  |
| export.fluentd.image.override | string | `nil` |  |
| export.fluentd.image.repository | string | `"quay.io/isovalent/hubble-export-fluentd"` |  |
| export.fluentd.image.tag | string | `"v1.5.1"` |  |
| export.fluentd.inputConfig | string | `"{{- $paths := list -}}\n{{- range .Values.export.filenames }}\n  {{- $paths = append $paths (printf \"%s/%s\" $.Values.exportDirectory .) -}}\n{{- end -}}\n<source>\n  @type tail\n  path {{ join \",\" $paths }}\n  pos_file {{ .Values.exportDirectory }}/fluentd-tail.pos\n  read_from_head true\n  refresh_interval 15\n  tag hubble-logs.*\n  <parse>\n    @type json\n    time_format %iso8601\n    keep_time_key true\n  </parse>\n</source>\n"` |  |
| export.fluentd.output | string | `"# https://docs.fluentd.org/output/stdout\n@type stdout\n<format>\n  @type json\n</format>"` |  |
| export.fluentd.outputConfig | string | `"# send hubble and fgs logs both to the same output\n<match hubble.log fgs.log>\n{{- if .Values.export.fluentd.output }}\n{{ tpl .Values.export.fluentd.output . | trim | indent 2 }}\n{{- end }}\n</match>\n"` |  |
| export.fluentd.tls.ca.configMap.key | string | `"ca.crt"` |  |
| export.fluentd.tls.ca.configMap.name | string | `nil` |  |
| export.grafana.dashboards.annotations | object | `{}` | Annotations to add to the ConfigMap |
| export.grafana.dashboards.enabled | bool | `false` |  |
| export.grafana.dashboards.labels | object | `{"grafana_dashboard":"1"}` | Labels to add to the ConfigMap. If using the dashboards sidecar, they must include the label used to discover dashboards. |
| export.grafana.dashboards.namespace | string | `nil` | Namespace to create the ConfigMap in. Defaults to namespace of the helm release. |
| export.mode | string | `"stdout"` |  |
| export.resources | object | `{}` |  |
| export.s3.acl | string | `nil` |  |
| export.s3.awsAccessKeyId | string | `nil` |  |
| export.s3.awsRegion | string | `nil` |  |
| export.s3.awsSecretAccessKey | string | `nil` |  |
| export.s3.bucket | string | `nil` |  |
| export.s3.concurrentLimit | int | `10` |  |
| export.s3.image.override | string | `nil` |  |
| export.s3.image.repository | string | `"quay.io/isovalent/hubble-export-s3"` |  |
| export.s3.image.tag | string | `"v1.0.0"` |  |
| export.s3.interval | string | `nil` |  |
| export.s3.kms | string | `nil` |  |
| export.s3.kmsId | string | `nil` |  |
| export.s3.objectTemplate | string | `nil` |  |
| export.s3.partSize | int | `5` |  |
| export.s3.skipProbe | bool | `false` |  |
| export.securityContext | object | `{}` |  |
| export.stdout.image.override | string | `nil` |  |
| export.stdout.image.repository | string | `"quay.io/isovalent/hubble-export-stdout"` |  |
| export.stdout.image.tag | string | `"v1.0.3"` |  |
| exportDirectory | string | `"/var/run/cilium/hubble"` |  |
| exportFileCreationInterval | string | `"120s"` |  |
| extraConfigmapMounts | list | `[]` |  |
| extraHostPathMounts | list | `[]` |  |
| extraVolumes | list | `[]` |  |
| hostNetwork | bool | `true` |  |
| hubbleEnterpriseOperator.enabled | bool | `true` | Enable the hubble-enterprise-operator component (required). |
| hubbleEnterpriseOperator.image | object | `{"override":null,"repository":"quay.io/isovalent/hubble-enterprise-operator","suffix":"","tag":"v1.11.0"}` | hubble-enterprise-operator image. |
| imagePullPolicy | string | `"IfNotPresent"` |  |
| imagePullSecrets | list | `[]` |  |
| nodeSelector | object | `{}` |  |
| podAnnotations | object | `{}` |  |
| podLabels | object | `{}` |  |
| podLabelsOverride | object | `{}` |  |
| podSecurityContext | object | `{}` |  |
| priorityClassName | string | `""` |  |
| rbac.enabled | bool | `false` |  |
| rbac.extraArgs | object | `{}` |  |
| rbac.extraEnv | list | `[]` |  |
| rbac.image.override | string | `nil` |  |
| rbac.image.repository | string | `"quay.io/isovalent/hubble-rbac"` |  |
| rbac.image.tag | string | `"v1.3.0"` |  |
| rbac.loggingLevel | string | `"info"` |  |
| rbac.metricsProxy.authMode | string | `"none"` |  |
| rbac.metricsProxy.autoTLS | bool | `true` |  |
| rbac.metricsProxy.filtration | bool | `true` |  |
| rbac.metricsProxy.jwtScopeField | string | `nil` |  |
| rbac.metricsProxy.localAddress | string | `"localhost:9091"` |  |
| rbac.metricsProxy.oidcCA.configMap.key | string | `"ca.crt"` |  |
| rbac.metricsProxy.oidcCA.configMap.name | string | `nil` |  |
| rbac.metricsProxy.oidcClientID | string | `nil` |  |
| rbac.metricsProxy.oidcURL | string | `nil` |  |
| rbac.metricsProxy.port | int | `9092` |  |
| rbac.metricsProxy.tlsDisabled | bool | `false` |  |
| rbac.metricsProxy.tlsSecretName | string | `"rbac-metrics-tls"` |  |
| rbac.observerProxy.authMode | string | `"none"` |  |
| rbac.observerProxy.autoTLS | bool | `true` |  |
| rbac.observerProxy.jwtScopeField | string | `nil` |  |
| rbac.observerProxy.oidcCA.configMap.key | string | `"ca.crt"` |  |
| rbac.observerProxy.oidcCA.configMap.name | string | `nil` |  |
| rbac.observerProxy.oidcCert | string | `nil` |  |
| rbac.observerProxy.oidcClientID | string | `nil` |  |
| rbac.observerProxy.oidcURL | string | `nil` |  |
| rbac.observerProxy.port | int | `4244` |  |
| rbac.observerProxy.socketPath | string | `"/var/run/cilium/hubble.sock"` |  |
| rbac.observerProxy.tlsDisabled | bool | `false` |  |
| rbac.policy.configMap.bindings | list | `[{"role":"admin","scope":"groups","value":"admins"}]` | The list of bindings between scope values and roles. |
| rbac.policy.configMap.create | bool | `true` | Whether to create the config map from where the mapping between scope and roles is read. If set to 'false' the user must create the config map out-of-band. Hubble Enterprise will not start until the config map is in place. |
| rbac.policy.configMap.key | Advanced | `"hubble-rbac-policy.yaml"` | The name of the config map key containing the policy document. If managed out-of-band, the config map must contain the policy document under this key. Most users won't need to customize this. |
| rbac.policy.configMap.name | Advanced | `"hubble-rbac-policy"` | The name of the config map containing the policy document. If managed out-of-band, the config map must have the name defined here. Most users won't need to customize this. |
| rbac.policy.configMap.roles | list | `[{"name":"admin","rules":[{"actions":["*"],"allowAllContexts":true,"kind":"*"}]}]` | The list of roles to define. |
| rbac.policy.logRoles | bool | `false` | Whether to enable logging of a user's roles to debug logs when they authenticate and make requests. |
| rbac.policy.mode | string | `"namespace"` | The policy mode to use (one of 'namespace' or 'configMap'). 'namespace' assumes users are assigned one or more 'cilium:<namespace>' groups and are thus granted access to the corresponding namespaces. 'configMap' allows for reading a mapping between scope values and roles from a config map. |
| rbac.resources | object | `{}` |  |
| rbac.securityContext | object | `{}` |  |
| rbac.socketPath | string | `"/var/run/cilium/hubble-rbac.sock"` | Local Hubble RBAC socket path. |
| selectorLabelsOverride | object | `{}` |  |
| serviceAccount.annotations | object | `{}` |  |
| serviceAccount.create | bool | `true` |  |
| serviceAccount.name | string | `""` |  |
| serviceLabelsOverride | object | `{}` |  |
| tolerations[0].operator | string | `"Exists"` |  |
| updateStrategy | object | `{}` |  |

----------------------------------------------
Autogenerated from chart metadata using [helm-docs v1.11.0](https://github.com/norwoodj/helm-docs/releases/v1.11.0)

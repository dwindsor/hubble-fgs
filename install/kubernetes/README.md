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
| selectorLabelsOverride | object | `{}` |  |
| serviceAccount.annotations | object | `{}` |  |
| serviceAccount.create | bool | `true` |  |
| serviceAccount.name | string | `""` |  |
| serviceLabelsOverride | object | `{}` |  |
| tolerations[0].operator | string | `"Exists"` |  |
| updateStrategy | object | `{}` |  |

----------------------------------------------
Autogenerated from chart metadata using [helm-docs v1.11.0](https://github.com/norwoodj/helm-docs/releases/v1.11.0)

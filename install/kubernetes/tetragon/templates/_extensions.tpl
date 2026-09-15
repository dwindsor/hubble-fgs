{{- define "configmap.extra" -}}
fim-runtime-endpoint: {{ .Values.tetragon.fimRuntimeEndpoint | quote }}
fim-fifo-path: {{ .Values.exportDirectory | quote }}
{{- if .Values.tetragon.fimDispatcher.enabled }}
fim-enable-dispatcher: "true"
{{- end }}
{{- if .Values.tetragon.flowExportFilename }}
flow-export-filename: {{ .Values.exportDirectory}}/{{ .Values.tetragon.flowExportFilename }}
flow-export-file-max-size-mb: {{ .Values.tetragon.flowExportFileMaxSizeMB | quote }}
flow-export-file-max-backups: {{ .Values.tetragon.flowExportFileMaxBackups | quote }}
flow-export-file-compress: {{ .Values.tetragon.flowExportFileCompress | quote }}
{{- end }}
{{- if .Values.tetragon.enableCiliumAPI }}
enable-cilium-api: "true"
{{- end }}
enable-policy-k8swatcher: {{ .Values.tetragon.k8sWatcher.policy.enabled | quote }}
enable-sandboxpolicies: {{ .Values.tetragon.enableSandboxpolicies | quote }}
{{- if .Values.tetragon.enableApplicationModel }}
{{- if .Values.tetragon.cgidmap.enabled }}
enable-application-model: "true"
{{- else }}
{{- fail "cgidmap must be enabled to enable application model. Use tetragon.cgidmap.enabled=true" }}
{{- end }}
{{- else }}
enable-application-model: "false"
{{- end }}
application-model-cache-size: {{ .Values.tetragon.applicationModelCacheSize | quote }}
application-model-export-interval: {{ .Values.tetragon.applicationModelExportInterval | quote }}
application-model-export-fragments: {{ .Values.tetragon.applicationModelExportFragments | quote }}
{{- if .Values.tetragon.applicationModelExportFilename }}
application-model-export-filename: {{ .Values.exportDirectory }}/{{ .Values.tetragon.applicationModelExportFilename }}
application-model-export-file-max-size-mb: {{ .Values.tetragon.applicationModelExportFileMaxSizeMB | quote }}
application-model-export-file-max-backups: {{ .Values.tetragon.applicationModelExportFileMaxBackups | quote }}
application-model-export-file-compress: {{ .Values.tetragon.applicationModelExportFileCompress | quote }}
{{- end }}
{{- if .Values.tetragon.telemetryExportFilename }}
telemetry-export-filename: {{ .Values.exportDirectory }}/{{ .Values.tetragon.telemetryExportFilename }}
{{- end }}
{{- if .Values.tetragon.connectionLogFilename }}
connection-log-filename: {{ .Values.exportDirectory }}/{{ .Values.tetragon.connectionLogFilename }}
{{- end }}
{{- if .Values.tetragon.enableSyscallTracking }}
{{- if .Values.tetragon.enableApplicationModel }}
enable-syscall-tracking: "true"
{{- else }}
{{- fail "Application model must be enabled to enable system call tracking. Use tetragon.enableApplicationModel=true" }}
{{- end }}
{{- else }}
enable-syscall-tracking: "false"
{{- end }}
disable-layer3: {{ .Values.tetragon.layer3.disabled | quote }}
bpf-layer3-socket-cache-size: {{ .Values.tetragon.layer3.bpfSocketCacheSize | quote }}
bpf-network-watermarks-cache-size: {{ .Values.tetragon.layer3.bpfWatermarksCacheSize | quote }}
enable-tcp: {{ .Values.tetragon.layer3.tcp.enabled | quote }}
bpf-tcp-socket-cache-size: {{ .Values.tetragon.layer3.tcp.bpfSocketCacheSize | quote }}
tcp-stats-interval: {{ .Values.tetragon.layer3.tcp.statsInterval | quote }}
enable-tcp-watermarks: {{ .Values.tetragon.layer3.tcp.watermarks.enabled | quote }}
tcp-watermarks-window-size-ms: {{ .Values.tetragon.layer3.tcp.watermarks.windowSizeMs | quote }}
tcp-watermarks-burst-trigger-percent: {{ .Values.tetragon.layer3.tcp.watermarks.burstTriggerPercent | quote }}
tcp-watermarks-dip-trigger-percent: {{ .Values.tetragon.layer3.tcp.watermarks.dipTriggerPercent | quote }}
enable-tcp-rtt: {{ .Values.tetragon.layer3.tcp.rtt.enabled | quote }}
tcp-rtt-min: {{ .Values.tetragon.layer3.tcp.rtt.min | quote }}
tcp-rtt-max: {{ .Values.tetragon.layer3.tcp.rtt.max | quote }}
enable-tcp-metrics: {{ .Values.tetragon.layer3.tcp.metrics.enabled | quote }}
tcp-metrics-label-filter: {{ .Values.tetragon.layer3.tcp.metrics.labelFilter | quote }}
tcp-disable-events: {{ .Values.tetragon.layer3.tcp.disableEvents | quote }}
enable-udp: {{ .Values.tetragon.layer3.udp.enabled | quote }}
bpf-udp-socket-cache-size: {{ .Values.tetragon.layer3.udp.bpfSocketCacheSize | quote }}
enable-udp-cgroup: {{ .Values.tetragon.layer3.udp.cgroup | quote }}
udp-stats-interval: {{ .Values.tetragon.layer3.udp.statsInterval | quote }}
bpf-icmp-socket-cache-size: {{ .Values.tetragon.layer3.icmp.bpfSocketCacheSize | quote }}
udp-idle-socket-timeout: {{ .Values.tetragon.layer3.udp.idleSocketTimeout | quote }}
udp-in-kernel-managed: {{ .Values.tetragon.layer3.udp.inKernelManaged | quote }}
enable-udp-watermarks: {{ .Values.tetragon.layer3.udp.watermarks.enabled | quote }}
udp-watermarks-window-size-ms: {{ .Values.tetragon.layer3.udp.watermarks.windowSizeMs | quote }}
udp-watermarks-burst-trigger-percent: {{ .Values.tetragon.layer3.udp.watermarks.burstTriggerPercent | quote }}
udp-watermarks-dip-trigger-percent: {{ .Values.tetragon.layer3.udp.watermarks.dipTriggerPercent | quote }}
enable-udp-metrics: {{ .Values.tetragon.layer3.udp.metrics.enabled | quote }}
udp-metrics-label-filter: {{ .Values.tetragon.layer3.udp.metrics.labelFilter | quote }}
udp-disable-events: {{ .Values.tetragon.layer3.udp.disableEvents | quote }}
enable-icmp: {{ .Values.tetragon.layer3.icmp.enabled | quote }}
enable-icmp-tracking: {{ .Values.tetragon.layer3.icmp.socketTracking | quote }}
icmpv6-info: {{ .Values.tetragon.layer3.icmp.v6info | quote }}
enable-igmp: {{ .Values.tetragon.layer3.igmp.enabled | quote }}
enable-rawsock: {{ .Values.tetragon.layer3.rawsock.enabled | quote }}
rawsock-report-close: {{ .Values.tetragon.layer3.rawsock.reportClose | quote }}
enable-rawsock-metrics: {{ .Values.tetragon.layer3.rawsock.metrics.enabled | quote }}
rawsock-metrics-label-filter: {{ .Values.tetragon.layer3.rawsock.metrics.labelFilter | quote }}
{{- if .Values.tetragon.userDNS }}
enable-user-dns: {{ .Values.tetragon.userDNS.enabled | quote }}
{{- else if .Values.tetragon.dns }}
enable-user-dns: {{ .Values.tetragon.dns.enabled | quote }}
{{- end }}
dns-ports: {{ .Values.tetragon.userDNS.ports | quote }}
dns-report-questions: {{ .Values.tetragon.userDNS.reportQuestions | quote }}
enable-dns-metrics: {{ .Values.tetragon.userDNS.metrics.enabled | quote }}
dns-metrics-label-filter: {{ .Values.tetragon.userDNS.metrics.labelFilter | quote }}
enable-network-events: {{ .Values.tetragon.enableEvents.network | quote }}
multicast-app: {{ .Values.tetragon.layer3.udp.multicast.app | quote }}
multicast-ports: {{ .Values.tetragon.layer3.udp.multicast.ports | quote }}
enable-multicast-seq-check: {{ .Values.tetragon.layer3.udp.multicast.seqCheck | quote }}
multicast-sample-percent: {{ .Values.tetragon.layer3.udp.multicast.samplePercent | quote }}
enable-network-watermarks-exit-gen: {{ .Values.tetragon.layer3.watermarksExitGen.enabled | quote }}
network-watermarks-exit-gen-interval: {{ .Values.tetragon.layer3.watermarksExitGen.interval | quote }}
enable-network-interface-stats: {{ .Values.tetragon.networkInterfaceStats.enabled | quote }}
network-interface-stats-interval: {{ .Values.tetragon.networkInterfaceStats.interval | quote }}
enable-tls-sensor: {{ .Values.tetragon.tls.enabled | quote }}
bpf-tls-context-cache-size: {{ .Values.tetragon.tls.bpfContextCacheSize | quote }}
tls-sensor-mode: {{ .Values.tetragon.tls.mode | quote }}
tls-sensor-ports: {{ .Values.tetragon.tls.ports | quote }}
enable-tls-sensor-metrics: {{ .Values.tetragon.tls.metrics.enabled | quote }}
tls-sensor-metrics-label-filter: {{ .Values.tetragon.tls.metrics.labelFilter | quote }}
enable-nop-sensor: {{ .Values.tetragon.nop.enabled | quote }}
nop-sensor-ports: {{ .Values.tetragon.nop.ports | quote }}
enable-http-sensor: {{ .Values.tetragon.http.enabled | quote }}
bpf-http-context-cache-size: {{ .Values.tetragon.http.bpfContextCacheSize | quote }}
http-sensor-ports: {{ .Values.tetragon.http.ports | quote }}
enable-http2-handling: {{ .Values.tetragon.http.http2Handling | quote }}
enable-http-sensor-metrics: {{ .Values.tetragon.http.metrics.enabled | quote }}
http-sensor-metrics-label-filter: {{ .Values.tetragon.http.metrics.labelFilter | quote }}
{{- if .Values.tetragon.awsSonar.enabled }}
enable-aws-sonar: "true"
aws-sonar-region: {{ .Values.tetragon.awsSonar.region }}
{{- end }}
dns-stats-per-socket: {{ .Values.tetragon.dnsStatsPerSocket | quote }}
enable-bpf-dns-parser: {{ (or .Values.tetragon.bpfDNSParser.enabled .Values.tetragon.enableBPFDNSParser) | default false | quote }}
enable-bpf-dns-parser-per-pod: {{ .Values.tetragon.bpfDNSParser.perPod | quote }}
bpf-dns-parser-per-pod-prealloc: {{ .Values.tetragon.bpfDNSParser.perPodPrealloc | quote }}
bpf-dns-parser-per-pod-threshold: {{ .Values.tetragon.bpfDNSParser.perPodThreshold | quote }}
enable-alerts: {{ .Values.tetragon.alerts.enabled | quote }}
alerts-export-dir: {{ .Values.tetragon.alerts.exportDirectory | quote }}
alerts-export-filename: {{ .Values.tetragon.alerts.exportFilename | quote }}
{{- end }}

{{- define "volumes.extra" -}}
{{- if .Values.tetragon.metadata.enabled }}
- emptyDir: {}
  name: metadata-files
{{- end }}
# Data sent to Sonar must contain EC2 instance id - Tetragon reads it from a file.
{{- if .Values.tetragon.awsSonar.enabled }}
- name: cloud-data
  hostPath:
    path: /var/lib/cloud/data
    type: Directory
{{- end }}
{{- if .Values.splunk_hec.enabled }}
- configMap:
    name: {{ .Release.Name }}-otel-agent-conf
    items:
      - key: otel-agent-config
        path: otel-agent-config.yaml
  name: otel-agent-config-vol
- name: file-storage
  emptyDir: {}
{{- $extName := dig "splunk_hec" "tls" "secret" "name" "" .Values.AsMap }}
{{- $hasExtCA := dig "splunk_hec" "tls" "secret" "keys" "ca_cert" "" .Values.AsMap }}
{{- $hasExtCert := dig "splunk_hec" "tls" "secret" "keys" "client_cert" "" .Values.AsMap }}
{{- $hasExtKey := dig "splunk_hec" "tls" "secret" "keys" "client_key" "" .Values.AsMap }}
{{- $useExt := and $extName (or $hasExtCA $hasExtCert $hasExtKey) }}
{{- $useInline := or .Values.splunk_hec.tls.ca .Values.splunk_hec.tls.crt .Values.splunk_hec.tls.key }}
{{- if or $useInline $useExt }}
- name: otel-splunk-tls
  secret:
    secretName: {{ if $useExt }}{{ $extName }}{{ else }}{{ include "tetragon.name" . }}-splunk-tls{{ end }}
{{- end }}
{{- end }}
{{- end }}

{{- define "tetragon.volumemounts.extra" -}}
{{- if .Values.tetragon.metadata.enabled }}
- mountPath: /var/lib/tetragon/metadata
  name: metadata-files
{{- end }}
{{- if .Values.tetragon.awsSonar.enabled }}
- mountPath: /var/lib/cloud/data
  name: cloud-data
{{- end }}
{{- end }}

{{- define "initcontainers.extra" -}}
{{- if .Values.tetragon.metadata.enabled }}
- name: {{ include "container.tetragon.name" . }}-init
  image: "{{ if .Values.tetragon.metadata.image.override }}{{ .Values.tetragon.metadata.image.override }}{{ else }}{{ .Values.tetragon.metadata.image.repository }}:{{ .Values.tetragon.metadata.image.tag }}{{ end }}"
{{- if .Values.tetragon.metadata.image.imagePullPolicy }}
  imagePullPolicy: {{ .Values.tetragon.metadata.image.imagePullPolicy }}
{{- else }}
  imagePullPolicy: {{ .Values.imagePullPolicy }}
{{- end }}
  terminationMessagePolicy: FallbackToLogsOnError
  command:
  - sh
  args:
    - -c
    - |
        cp -r /var/run/tetragon-ee-metadata/* /var/lib/tetragon/metadata
{{- if .Values.tetragon.enableCiliumAPI }}
        until [ -S /var/run/cilium/cilium.sock -a -S /var/run/cilium/monitor1_2.sock ]; do sleep 3; done
{{- end }}
  volumeMounts:
    - mountPath: /var/lib/tetragon/metadata
      name: metadata-files
{{- if .Values.tetragon.enableCiliumAPI }}
    - mountPath: /var/run/cilium
      name: cilium-run
{{- end }}
{{- end }}
{{- end }}

{{- define "containers.extra" -}}
{{- if .Values.splunk_hec.enabled }}
- command:
    - "/otelcol-contrib"
    - "--config=/conf/otel-agent-config.yaml"
  image: "{{ if .Values.splunk_hec.image.override }}{{ .Values.splunk_hec.image.override }}{{ else }}{{ .Values.splunk_hec.image.repository }}:{{ .Values.splunk_hec.image.tag }}{{ end}}"
  name: {{ include "container.tetragon.name" . }}-otel-agent
  securityContext:
    allowPrivilegeEscalation: false
    capabilities:
      drop:
        - ALL
    readOnlyRootFilesystem: true
    runAsUser: 0
    runAsGroup: 0
  {{- with .Values.splunk_hec.resources }}
  resources:
    {{- toYaml . | trim | nindent 4 }}
  {{- end }}
  env:
    - name: SPLUNK_HEC_TOKEN
      valueFrom:
        secretKeyRef:
          name: {{ .Values.splunk_hec.token.secretName | quote }}
          key: {{ .Values.splunk_hec.token.secretKey | quote }}
    - name: SPLUNK_HEC_ENDPOINT
      valueFrom:
        secretKeyRef:
          name: {{ .Values.splunk_hec.endpoint.secretName | quote }}
          key: {{ .Values.splunk_hec.endpoint.secretKey | quote }}
    - name: K8S_NODE
      valueFrom:
        fieldRef: { fieldPath: spec.nodeName }
  volumeMounts:
    - name: otel-agent-config-vol
      mountPath: /conf
      readOnly: true
    - name: export-logs
      mountPath: {{ .Values.exportDirectory }}
      readOnly: true
    - name: file-storage
      mountPath: /var/lib/otelcol/file-storage
{{- $extName := dig "splunk_hec" "tls" "secret" "name" "" .Values.AsMap }}
{{- $hasExtCA := dig "splunk_hec" "tls" "secret" "keys" "ca_cert" "" .Values.AsMap }}
{{- $hasExtCert := dig "splunk_hec" "tls" "secret" "keys" "client_cert" "" .Values.AsMap }}
{{- $hasExtKey := dig "splunk_hec" "tls" "secret" "keys" "client_key" "" .Values.AsMap }}
{{- $useExt := and $extName (or $hasExtCA $hasExtCert $hasExtKey) }}
{{- $useInline := or .Values.splunk_hec.tls.ca .Values.splunk_hec.tls.crt .Values.splunk_hec.tls.key }}
{{- if or $useInline $useExt }}
    - name: otel-splunk-tls
      mountPath: /tls
      readOnly: true
{{- end }}
{{- end }}
{{- end }}

{{- define "tetragon-aggregator.selectorLabels" -}}
app.kubernetes.io/name: "tetragon-aggregator"
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "tetragon-aggregator.labels" -}}
{{ include "tetragon-aggregator.selectorLabels" . }}
{{ include "commonLabels" . }}
app.kubernetes.io/component: aggregator
{{- end }}

{{- define "opentelemetry-collector.labels" -}}
{{ include "commonLabels" . }}
{{- end }}


{{- define "clusterrole.extra" -}}
- apiGroups:
    - ""
  resources:
    - replicationcontrollers
  verbs:
    - get
    - list
    - watch
- apiGroups:
    - apps
  resources:
    - daemonsets
    - deployments
    - replicasets
    - statefulsets
  verbs:
    - get
    - list
    - watch
- apiGroups:
    - batch
  resources:
    - cronjobs
    - jobs
  verbs:
    - get
    - list
    - watch
- apiGroups:
    - cilium.io
  resources:
    - podinfo
  verbs:
    - update
    - patch
- apiGroups:
    - cilium.io
  resources:
    - sandboxpolicies
    - sandboxpoliciesnamespaced
    - alertrules
    - tetragonnetworkpolicies
    - tetragonnetworkpoliciesnamespaced
  verbs:
    - get
    - list
    - watch
- apiGroups:
    - isovalent.com
  resources:
    - tetragonnodes
  verbs:
    - create
    - update
    - get
    - list
    - watch
    - delete
    - patch
- apiGroups:
    - isovalent.com
  resources:
    - tetragonnodes/status
  verbs:
  - update
  - patch
- apiGroups:
    - "discovery.k8s.io"
  resources:
    - "endpointslices"
  verbs:
    - "get"
    - "list"
    - "watch"
{{- end }}

{{- define "role.extra" -}}
{{ if .Values.splunk_hec.enabled }}
- apiGroups:
    - ""
  resources:
    - secrets
  verbs:
    - get
    - list
    - watch
{{- end }}
{{- end }}

{{- define "operatorconfigmap.extra" -}}
skip-policysandbox-crd: {{ not .Values.tetragon.enableSandboxpolicies | quote }}
{{- end }}

{{- define "operatorclusterrole.extra" -}}
- apiGroups:
    - ""
  resources:
    - pods/finalizers
  verbs:
    - create
    - delete
    - update
- apiGroups:
    - apiextensions.k8s.io
  resources:
    - customresourcedefinitions
  resourceNames:
    - sandboxpolicies.cilium.io
    - sandboxpoliciesnamespaced.cilium.io
    - alertrules.cilium.io
    - tetragonnetworkpolicies.cilium.io
    - tetragonnetworkpoliciesnamespaced.cilium.io
    - tetragonnodes.isovalent.com
  verbs:
    - update
    - get
    - list
    - watch
{{- end }}

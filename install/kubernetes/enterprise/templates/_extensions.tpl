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
enable-application-model: {{ .Values.tetragon.enableApplicationModel | quote }}
application-model-cache-size: {{ .Values.tetragon.applicationModelCacheSize | quote }}
application-model-export-interval: {{ .Values.tetragon.applicationModelExportInterval | quote }}
{{- if .Values.tetragon.applicationModelExportFilename }}
application-model-export-filename: {{ .Values.exportDirectory }}/{{ .Values.tetragon.applicationModelExportFilename }}
{{- end }}
{{- if .Values.tetragon.telemetryExportFilename }}
telemetry-export-filename: {{ .Values.exportDirectory }}/{{ .Values.tetragon.telemetryExportFilename }}
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
enable-tcp: {{ .Values.tetragon.layer3.tcp.enabled | quote }}
enable-tcp-rtt: {{ .Values.tetragon.layer3.tcp.rtt.enabled | quote }}
enable-udp: {{ .Values.tetragon.layer3.udp.enabled | quote }}
enable-latency: {{ .Values.tetragon.layer3.latency.enabled | quote }}
enable-icmp: {{ .Values.tetragon.layer3.icmp.enabled | quote }}
enable-rawsock: {{ .Values.tetragon.layer3.rawsock.enabled | quote }}
enable-dns: {{ .Values.tetragon.dns.enabled | quote }}
udp-idle-socket-timeout: {{ .Values.tetragon.layer3.udp.idleSocketTimeout | quote }}
enable-network-events: {{ .Values.tetragon.enableEvents.network | quote }}
{{- if .Values.tetragon.awsSonar.enabled }}
enable-aws-sonar: "true"
aws-sonar-region: {{ .Values.tetragon.awsSonar.region }}
{{- end }}
dns-stats-per-socket: {{ .Values.tetragon.dnsStatsPerSocket | quote }}
enable-bpf-dns-parser: {{ (or .Values.tetragon.bpfDNSParser.enabled .Values.tetragon.enableBPFDNSParser) | quote }}
enable-bpf-dns-parser-per-pod: {{ .Values.tetragon.bpfDNSParser.perPod | quote }}
bpf-dns-parser-per-pod-prealloc: {{ .Values.tetragon.bpfDNSParser.perPodPrealloc | quote }}
bpf-dns-parser-per-pod-threshold: {{ .Values.tetragon.bpfDNSParser.perPodThreshold | quote }}
enable-alerts: {{ .Values.tetragon.alerts.enabled | quote }}
alerts-export-dir: {{ .Values.tetragon.alerts.exportDirectory | quote }}
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

{{- define "containers.extra" -}}{{- end }}

{{- define "tetragon-aggregator.selectorLabels" -}}
app.kubernetes.io/name: "tetragon-aggregator"
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "tetragon-aggregator.labels" -}}
{{ include "tetragon-aggregator.selectorLabels" . }}
{{ include "commonLabels" . }}
app.kubernetes.io/component: aggregator
{{- end }}

{{- define "clusterrole.extra" -}}
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
{{- end }}

{{- define "role.extra" -}}{{- end }}

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
  verbs:
    - update
    - get
    - list
    - watch
{{- end }}

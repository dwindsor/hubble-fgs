{{- define "container.enterprise" -}}
- name: {{ include "container.enterprise.name" . }}
  securityContext:
    {{- toYaml .Values.enterprise.securityContext | nindent 4 }}
  image: "{{ if .Values.enterprise.image.override }}{{ .Values.enterprise.image.override }}{{ else }}{{ .Values.enterprise.image.repository }}:{{ .Values.enterprise.image.tag | default .Chart.AppVersion }}{{ end }}"
  imagePullPolicy: {{ .Values.imagePullPolicy }}
  terminationMessagePolicy: FallbackToLogsOnError
  command:
{{- with .Values.enterprise.commandOverride }}
  {{- toYaml . | nindent 2 }}
{{- else }}
    - /usr/bin/hubble-fgs
{{- end }}
  args:
    - --config-dir=/etc/hubble-enterprise
{{- with .Values.enterprise.argsOverride }}
  {{- toYaml . | nindent 2 }}
{{- else }}
{{- range $key, $value := .Values.enterprise.extraArgs }}
{{- if $value }}
    - --{{ $key }}={{ $value }}
{{- else }}
    - --{{ $key }}
{{- end }}
{{- end }}
{{- end }}
  volumeMounts:
    {{- with .Values.enterprise.extraVolumeMounts }}
      {{- toYaml . | nindent 4 }}
    {{- end }}
    {{- if .Values.enterprise.metadata.enabled }}
    - mountPath: /var/lib/hubble-fgs/metadata
      name: metadata-files
    {{- end }}
    - mountPath: /etc/hubble-enterprise
      name: fgs-config
      readOnly: true
    - mountPath: /sys/fs/bpf
      mountPropagation: Bidirectional
      name: bpf-maps
    - mountPath: "/var/run/cilium"
      name: cilium-run
    - mountPath: {{ .Values.exportDirectory }}
      name: export-logs
    - mountPath: "/procRoot"
      name: host-proc
{{- range .Values.extraHostPathMounts }}
    - name: {{ .name }}
      mountPath: {{ .mountPath }}
      readOnly: {{ .readOnly }}
{{- if .mountPropagation }}
      mountPropagation: {{ .mountPropagation }}
{{- end }}
{{- end }}
{{- range .Values.extraConfigmapMounts }}
    - name: {{ .name }}
      mountPath: {{ .mountPath }}
      readOnly: {{ .readOnly }}
{{- end }}
  env:
    - name: NODE_NAME
      valueFrom:
        fieldRef:
            fieldPath: spec.nodeName
{{- if .Values.enterprise.extraEnv }}
  {{- toYaml .Values.enterprise.extraEnv | nindent 4 }}
{{- end }}
{{- with .Values.enterprise.resources }}
  resources:
    {{- toYaml . | nindent 4 }}
{{- end }}
{{- if .Values.enterprise.grpc.enabled }}
  livenessProbe:
    exec:
      command:
      - hubble-enterprise
      - status
      - --server-address
      - {{ .Values.enterprise.grpc.address }}
{{- end -}}
{{- end -}}

{{- define "container.enterprise.init" -}}
- name: {{ include "container.enterprise.name" . }}-init
  image: "{{ if .Values.enterprise.metadata.image.override }}{{ .Values.enterprise.metadata.image.override }}{{ else }}{{ .Values.enterprise.metadata.image.repository }}:{{ .Values.enterprise.metadata.image.tag }}{{ end }}"
{{- if .Values.enterprise.metadata.image.imagePullPolicy }}
  imagePullPolicy: {{ .Values.enterprise.metadata.image.imagePullPolicy }}
{{- else }}
  imagePullPolicy: {{ .Values.imagePullPolicy }}
{{- end }}
  terminationMessagePolicy: FallbackToLogsOnError
  command:
  - sh
  args:
    - -c
    - |
        cp -r /var/run/hubble-fgs/* /var/lib/hubble-fgs/metadata
{{- if .Values.enterprise.enableCiliumAPI }}
        until [ -S /var/run/cilium/cilium.sock -a -S /var/run/cilium/monitor1_2.sock ]; do sleep 3; done
{{- end }}
  volumeMounts:
    - mountPath: /var/lib/hubble-fgs/metadata
      name: metadata-files
{{- if .Values.enterprise.enableCiliumAPI }}
    - mountPath: /var/run/cilium
      name: cilium-run
{{- end }}
{{- end -}}

{{- define "container.enterprise.init-operator" -}}
{{- if .Values.hubbleEnterpriseOperator.enabled -}}
- name: {{ include "container.enterprise.name" . }}-operator
  command:
  - hubble-enterprise-operator
  image: "{{ if .Values.hubbleEnterpriseOperator.image.override }}{{ .Values.hubbleEnterpriseOperator.image.override }}{{ else }}{{ .Values.hubbleEnterpriseOperator.image.repository }}:{{ .Values.hubbleEnterpriseOperator.image.tag }}{{ end }}"
  imagePullPolicy: {{ .Values.imagePullPolicy }}
  terminationMessagePolicy: FallbackToLogsOnError
{{- end }}
{{- end -}}

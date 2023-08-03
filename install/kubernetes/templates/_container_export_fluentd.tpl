{{- define "container.export.fluentd" -}}
- name: {{ include "container.export.fluentd.name" . }}
  securityContext:
    {{- toYaml .Values.export.securityContext | nindent 4 }}
  image: "{{ if .Values.export.fluentd.image.override }}{{ .Values.export.fluentd.image.override }}{{ else }}{{ .Values.export.fluentd.image.repository }}:{{ .Values.export.fluentd.image.tag }}{{ end }}"
  imagePullPolicy: {{ .Values.imagePullPolicy }}
  terminationMessagePolicy: FallbackToLogsOnError
  env: {{- include "container.export.fluentd.env" . | nindent 4 }}
  resources:
    {{- toYaml .Values.export.resources | nindent 4 }}
  volumeMounts:
    - mountPath: {{ .Values.exportDirectory }}
      name: export-logs
    - mountPath: /fluentd/etc
      name: fluentd-config
    {{- if .Values.export.fluentd.tls.ca.configMap.name }}
    - mountPath: /fluentd/etc/certs
      name: fluentd-certs
    {{- end -}}
{{- end -}}

{{- define "container.export.fluentd.volumes" -}}
- name: fluentd-config
  configMap:
    name: {{ .Chart.Name }}-{{- include "container.export.fluentd.name" . }}
    items:
      - key: fluent.conf
        path: fluent.conf
      - key: filter.conf
        path: filter.conf
      - key: input.conf
        path: input.conf
      - key: output.conf
        path: output.conf
{{- if .Values.export.fluentd.tls.ca.configMap.name }}
- name: fluentd-certs
  configMap:
    name: {{ .Values.export.fluentd.tls.ca.configMap.name }}
    items:
      - key: {{ .Values.export.fluentd.tls.ca.configMap.key }}
        path: ca.crt
{{- end -}}

{{- end -}}

{{- define "container.export.fluentd.tls.caFile" -}}
/fluentd/etc/certs/ca.crt
{{- end -}}

{{- define "container.export.fluentd.env" -}}
{{- $fluentdEnv := .Values.export.extraEnv -}}
{{- if .Values.export.fluentd.tls.ca.configMap.name }}
{{- $fluentdCAFile := (include "container.export.fluentd.tls.caFile" .) -}}
{{- $fluentdCABundleEnv := dict "name" "FLUENTD_SSL_CA_BUNDLE" "value" $fluentdCAFile  -}}
{{- $fluentdEnv = append $fluentdEnv $fluentdCABundleEnv -}}
{{- end }}
{{- $fluentdEnv | toYaml -}}
{{- end -}}

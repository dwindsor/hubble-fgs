{{- define "prometheus.name" -}}
{{ .Release.Name }}-prometheus
{{- end }}

{{- define "prometheus.labels" -}}
{{ include "prometheus.selectorLabels" . }}
{{ include "commonLabels" . }}
app.kubernetes.io/component: prometheus
{{- end }}

{{- define "prometheus.selectorLabels" -}}
app.kubernetes.io/name: tetragon-prometheus
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

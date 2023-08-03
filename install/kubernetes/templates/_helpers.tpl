{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "hubble-enterprise.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- define "hubble-enterprise-operator.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "hubble-enterprise.labels" -}}
helm.sh/chart: {{ include "hubble-enterprise.chart" . }}
{{ include "hubble-enterprise.selectorLabels" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}
{{- define "hubble-enterprise-operator.labels" -}}
helm.sh/chart: {{ include "hubble-enterprise-operator.chart" . }}
{{ include "hubble-enterprise-operator.selectorLabels" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "hubble-enterprise.selectorLabels" -}}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}
{{- define "hubble-enterprise-operator.selectorLabels" -}}
app.kubernetes.io/name: "hubble-enterprise-operator"
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "container.export.fluentd.name" -}}
{{- print "export-fluentd" -}}
{{- end }}

{{- define "container.export.s3.name" -}}
{{- print "export-s3" -}}
{{- end }}

{{- define "container.export.stdout.name" -}}
{{- print "export-stdout" -}}
{{- end }}

{{- define "container.enterprise.name" -}}
{{- print "enterprise" -}}
{{- end }}

{{- define "container.rbac.name" -}}
{{- "rbac" -}}
{{- end }}
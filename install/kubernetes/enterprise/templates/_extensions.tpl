{{- define "configmap.extra" -}}
fim-runtime-endpoint: {{ .Values.tetragon.fimRuntimeEndpoint | quote }}
fim-fifo-path: {{ .Values.exportDirectory | quote }}
{{- if .Values.tetragon.flowExportFilename }}
flow-export-filename: {{ .Values.exportDirectory}}/{{ .Values.tetragon.flowExportFilename }}
flow-export-file-max-size-mb: {{ .Values.tetragon.flowExportFileMaxSizeMB | quote }}
flow-export-file-max-backups: {{ .Values.tetragon.flowExportFileMaxBackups | quote }}
flow-export-file-compress: {{ .Values.tetragon.flowExportFileCompress | quote }}
{{- end }}
{{- if .Values.tetragon.enableCiliumAPI }}
enable-cilium-api: "true"
{{- end }}
{{- end }}

{{- define "volumes.extra" -}}
{{- if .Values.tetragon.metadata.enabled }}
- emptyDir: {}
  name: metadata-files
{{- end }}
{{- end }}

{{- define "tetragon.volumemounts.extra" -}}
{{- if .Values.tetragon.metadata.enabled }}
- mountPath: /var/lib/tetragon/metadata
  name: metadata-files
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

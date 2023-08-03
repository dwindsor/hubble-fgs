{{- define "container.export.s3" -}}
- name: {{ include "container.export.s3.name" . }}
  image: "{{ if .Values.export.s3.image.override }}{{ .Values.export.s3.image.override }}{{ else }}{{ .Values.export.s3.image.repository }}:{{ .Values.export.s3.image.tag }}{{ end }}"
  imagePullPolicy: {{ .Values.imagePullPolicy }}
  terminationMessagePolicy: FallbackToLogsOnError
  securityContext:
    {{- toYaml .Values.export.securityContext | nindent 4 }}
  resources:
    {{- toYaml .Values.export.resources | nindent 4 }}
  command:
{{- with .Values.export.commandOverride }}
  {{- toYaml . | nindent 2 }}
{{- else }}
  - hubble-s3
{{- end }}
  args:
{{- with .Values.export.argsOverride }}
  {{- toYaml . | nindent 2 }}
{{- else }}
  - --include="^fgs-.*\.log"
  - --include="^hubble-.*\.log"
  - --include="^hubble-.*\.json"
  - {{ .Values.exportDirectory | quote }}
  - {{ required "missing export.s3.bucket" .Values.export.s3.bucket | quote }}
{{- if .Values.export.s3.kms }}
  - --kms
{{- end }}
{{- if .Values.export.s3.kmsId }}
  - --kms-id
  - {{ .Values.export.s3.kmsId | quote }}
{{- end }}
{{- if .Values.export.s3.objectTemplate }}
  - --object-template
  - {{ .Values.export.s3.objectTemplate | quote }}
{{- end }}
{{- if .Values.export.s3.acl }}
  - --acl
  - {{ .Values.export.s3.acl | quote }}
{{- end }}
{{- if .Values.export.s3.partSize }}
  - --part-size
  - {{ .Values.export.s3.partSize | quote }}
{{- end }}
{{- if .Values.export.s3.interval }}
  - --interval
  - {{ .Values.export.s3.interval | quote }}
{{- end }}
{{- if .Values.export.s3.concurrentLimit }}
  - --concurrent-limit
  - {{ .Values.export.s3.concurrentLimit | quote }}
{{- end }}
{{- end }}
{{- if not .Values.export.s3.skipProbe }}
  readinessProbe:
    exec:
      command:
      - hubble-s3
      - --dry-run
      - {{ .Values.exportDirectory | quote }}
      - {{ .Values.export.s3.bucket | quote }}
    failureThreshold: 3
    initialDelaySeconds: 5
    periodSeconds: 30
    successThreshold: 1
    timeoutSeconds: 5
{{- end }}
  env:
    - name: AWS_REGION
      valueFrom:
        secretKeyRef:
          name: {{ .Chart.Name }}-{{- include "container.export.s3.name" . }}
          key: aws-region
  {{- if and .Values.export.s3.awsSecretAccessKey .Values.export.s3.awsAccessKeyId }}
    - name: AWS_SECRET_ACCESS_KEY
      valueFrom:
        secretKeyRef:
          name: {{ .Chart.Name }}-{{- include "container.export.s3.name" . }}
          key: aws-secret-access-key
    - name: AWS_ACCESS_KEY_ID
      valueFrom:
        secretKeyRef:
          name: {{ .Chart.Name }}-{{- include "container.export.s3.name" . }}
          key: aws-access-key-id
  {{- end }}
  {{- with .Values.export.extraEnv }}
    {{- toYaml . | nindent 4 }}
  {{- end }}
  volumeMounts:
  - mountPath: {{ .Values.exportDirectory | quote }}
    name: export-logs
{{- end -}}

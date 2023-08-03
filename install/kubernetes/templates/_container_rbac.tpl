{{- define "container.rbac" -}}
- name: {{ include "container.rbac.name" . }}
  image: "{{ if .Values.rbac.image.override }}{{ .Values.rbac.image.override }}{{ else }}{{ .Values.rbac.image.repository }}:{{ .Values.rbac.image.tag }}{{ end }}"
  imagePullPolicy: {{ .Values.imagePullPolicy }}
  terminationMessagePolicy: FallbackToLogsOnError
  securityContext:
    {{- toYaml .Values.rbac.securityContext | nindent 4 }}
  resources:
    {{- toYaml .Values.rbac.resources | nindent 4 }}
  command:
  - /root/hubble-rbac
  args:
  - --hubble-rbac-socket-path={{ .Values.rbac.socketPath }}
{{- if .Values.rbac.loggingLevel }}
  - --logging-level={{ .Values.rbac.loggingLevel }}
{{- end }}
{{- if .Values.rbac.metricsProxy.port }}
  - --metrics-listen-address=:{{ .Values.rbac.metricsProxy.port }}
{{- end }}
{{- if .Values.rbac.metricsProxy.localAddress }}
  - --metrics-local-server={{ .Values.rbac.metricsProxy.localAddress }}
{{- end }}
  - --metrics-auth={{ .Values.rbac.metricsProxy.authMode }}
  - --metrics-disable-tls={{ .Values.rbac.metricsProxy.tlsDisabled }}
{{- if .Values.rbac.metricsProxy.clientCA }}
  - --metrics-client-ca=/etc/hubble-rbac/metrics-client-ca.pem
{{- end }}
{{- if .Values.rbac.metricsProxy.autoTLS }}
  - --metrics-tls-cert=/etc/hubble-rbac/tls/server.crt
  - --metrics-tls-key=/etc/hubble-rbac/tls/server.key
{{- else }}
{{- if .Values.rbac.metricsProxy.cert }}
  - --metrics-tls-cert=/etc/hubble-rbac/metrics-tls-cert.pem
{{- end }}
{{- if .Values.rbac.metricsProxy.tlsKey }}
  - --metrics-tls-key=/etc/hubble-rbac/metrics-tls-key.pem
{{- end }}
{{- end }}
{{- if  (eq .Values.rbac.metricsProxy.authMode "oidc") }}
{{- if .Values.rbac.metricsProxy.oidcURL }}
  - --metrics-oidc-url={{ .Values.rbac.metricsProxy.oidcURL }}
{{- else if .Values.rbac.metricsProxy.oidcCert }}
  - --metrics-oidc-cert=/etc/hubble-rbac/metrics-oidc-cert.pem
{{- end }}
{{- if .Values.rbac.metricsProxy.oidcCA.configMap.name }}
  - --metrics-oidc-ca=/etc/hubble-rbac/tls/metrics-oidc-provider-ca.pem
{{- end }}
{{- if .Values.rbac.metricsProxy.oidcClientID }}
  - --metrics-oidc-client-id={{ .Values.rbac.metricsProxy.oidcClientID }}
{{- end }}
{{- if .Values.rbac.metricsProxy.jwtScopeField }}
  - --metrics-jwt-scope-field={{ .Values.rbac.metricsProxy.jwtScopeField }}
{{- end }}
{{- end }}
{{- if .Values.rbac.metricsProxy.filtration }}
  - --metrics-filtration
{{- end }}
{{- if eq .Values.rbac.policy.mode "configMap" }}
  - --hubble-policy-mode=config
  - --hubble-policy-file=/etc/hubble-rbac/policy/{{ .Values.rbac.policy.configMap.key }}
  - --hubble-policy-log-roles={{ .Values.rbac.policy.logRoles }}
  - --metrics-policy-mode=config
  - --metrics-policy-file=/etc/hubble-rbac/policy/{{ .Values.rbac.policy.configMap.key }}
{{- end }}
{{- if .Values.rbac.observerProxy.port }}
  - --hubble-listen-address=:{{ .Values.rbac.observerProxy.port }}
{{- end }}
{{- if .Values.rbac.observerProxy.socketPath }}
  - --hubble-local-server=unix://{{ .Values.rbac.observerProxy.socketPath }}
{{- else if .Values.rbac.observerProxy.localAddress }}
  - --hubble-local-server={{ .Values.rbac.observerProxy.localAddress }}
{{- end }}
  - --hubble-peer-api
  - --hubble-auth={{ .Values.rbac.observerProxy.authMode }}
  - --hubble-disable-tls={{ .Values.rbac.observerProxy.tlsDisabled }}
{{- if .Values.rbac.observerProxy.autoTLS }}
  - --hubble-client-ca=/etc/hubble-rbac/tls/client-ca.crt
  - --hubble-tls-cert=/etc/hubble-rbac/tls/server.crt
  - --hubble-tls-key=/etc/hubble-rbac/tls/server.key
{{- else }}
{{- if .Values.rbac.observerProxy.clientCA }}
  - --hubble-client-ca=/etc/hubble-rbac/hubble-client-ca.pem
{{- end }}
{{- if .Values.rbac.observerProxy.cert }}
  - --hubble-tls-cert=/etc/hubble-rbac/hubble-tls-cert.pem
{{- end }}
{{- if .Values.rbac.observerProxy.tlsKey }}
  - --hubble-tls-key=/etc/hubble-rbac/hubble-tls-key.pem
{{- end }}
{{- end }}
{{- if  (eq .Values.rbac.observerProxy.authMode "oidc") }}
{{- if .Values.rbac.observerProxy.oidcURL }}
  - --hubble-oidc-url={{ .Values.rbac.observerProxy.oidcURL }}
{{- else if .Values.rbac.observerProxy.oidcCert }}
  - --hubble-oidc-cert=/etc/hubble-rbac/hubble-oidc-cert.pem
{{- end }}
{{- if .Values.rbac.observerProxy.oidcCA.configMap.name }}
  - --hubble-oidc-ca=/etc/hubble-rbac/tls/hubble-oidc-provider-ca.pem
{{- end }}
{{- if .Values.rbac.observerProxy.oidcClientID }}
  - --hubble-oidc-client-id={{ .Values.rbac.observerProxy.oidcClientID }}
{{- end }}
{{- if .Values.rbac.observerProxy.jwtScopeField }}
  - --hubble-jwt-scope-field={{ .Values.rbac.observerProxy.jwtScopeField }}
{{- end }}
{{- end }}
{{- if .Values.rbac.metricsProxy.proxyPort }}
  ports:
  - containerPort: {{ .Values.rbac.metricsProxy.proxyPort }}
    hostPort: {{ .Values.rbac.metricsProxy.proxyPort }}
    name: hubble-metrics
    protocol: TCP
{{- end }}
  volumeMounts:
  - mountPath: /var/run/cilium
    name: cilium-run
  - mountPath: /etc/hubble-rbac
    name: {{ .Chart.Name }}-{{- include "container.rbac.name" . }}
    readOnly: true
{{- if eq .Values.rbac.policy.mode "configMap" }}
  - name: hubble-rbac-policy
    mountPath: /etc/hubble-rbac/policy
    readOnly: true
{{- end }}
{{- if or .Values.rbac.observerProxy.autoTLS .Values.rbac.metricsProxy.autoTLS }}
  - mountPath: /etc/hubble-rbac/tls
    name: hubble-tls
    readOnly: true
{{- end }}
{{- end -}}

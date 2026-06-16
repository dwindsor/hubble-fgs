// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package agent

import (
	"testing"

	"github.com/stretchr/testify/require"

	appv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	logr "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/yaml"
)

func TestDnsPolicy(t *testing.T) {
	testCases := []struct {
		configMap map[string]any
		expected  corev1.DNSPolicy
	}{
		{
			configMap: nil,
			expected:  corev1.DNSDefault,
		},
		{
			configMap: map[string]any{"dnsPolicy": "bla-bla-bla"},
			expected:  corev1.DNSDefault,
		},
		{
			configMap: map[string]any{"dnsPolicy": "ClusterFirst"},
			expected:  corev1.DNSClusterFirst,
		},
	}

	for _, tt := range testCases {
		// function to test
		actual := dnsPolicy(logr.Log, tt.configMap)

		require.Equal(t, tt.expected, actual)
	}
}

func TestImagePullPolicy(t *testing.T) {
	testCases := []struct {
		configMap map[string]any
		expected  corev1.PullPolicy
	}{
		{
			configMap: nil,
			expected:  corev1.PullIfNotPresent,
		},
		{
			configMap: map[string]any{"imagePullPolicy": "bla-bla-bla"},
			expected:  corev1.PullIfNotPresent,
		},
		{
			configMap: map[string]any{"imagePullPolicy": "Always"},
			expected:  corev1.PullAlways,
		},
	}

	for _, tt := range testCases {
		// function to test
		actual := imagePullPolicy(logr.Log, tt.configMap, "imagePullPolicy")

		require.Equal(t, tt.expected, actual)
	}
}

func TestConfigValue_bool(t *testing.T) {
	key := "test"
	testCases := []struct {
		configMap    map[string]any
		defaultValue bool
		expected     bool
	}{
		{
			configMap:    map[string]any{},
			defaultValue: false,
			expected:     false,
		},
		{
			configMap: map[string]any{
				key: true,
			},
			defaultValue: false,
			expected:     true,
		},
		{
			configMap: map[string]any{
				key: "true",
			},
			defaultValue: false,
			expected:     false,
		},
	}

	for _, tt := range testCases {
		// function to test
		actual := configValue(logr.Log, tt.configMap, key, tt.defaultValue)

		require.Equal(t, tt.expected, actual)
	}
}

func TestConfigValue_string(t *testing.T) {
	key := "test"
	testCases := []struct {
		configMap    map[string]any
		defaultValue string
		expected     string
	}{
		{
			configMap:    map[string]any{},
			defaultValue: "default",
			expected:     "default",
		},
		{
			configMap: map[string]any{
				key: "123",
			},
			defaultValue: "default",
			expected:     "123",
		},
		{
			configMap: map[string]any{
				key: true,
			},
			defaultValue: "default",
			expected:     "default",
		},
	}

	for _, tt := range testCases {
		// function to test
		actual := configValue(logr.Log, tt.configMap, key, tt.defaultValue)

		require.Equal(t, tt.expected, actual)
	}
}

func TestConfigMapOfString(t *testing.T) {
	key := "test"
	testCases := []struct {
		configMap map[string]any
		expected  map[string]string
	}{
		{
			configMap: map[string]any{},
			expected:  map[string]string{},
		},
		{
			configMap: map[string]any{
				key: "not map",
			},
			expected: map[string]string{},
		},
		{
			configMap: map[string]any{
				key: map[string]any{
					"key1": "value1",
					"key2": "true",
					"key3": "-1",
				},
			},
			expected: map[string]string{
				"key1": "value1",
				"key2": "true",
				"key3": "-1",
			},
		},
	}

	for _, tt := range testCases {
		// function to test
		actual := configMapOfString(logr.Log, tt.configMap, key)

		require.Equal(t, tt.expected, actual)
	}
}

func TestConfigArray(t *testing.T) {
	key := "test"
	testCases := []struct {
		yamlString   string
		defaultValue []string
		expected     []string
	}{
		{
			yamlString:   "",
			defaultValue: []string{"default"},
			expected:     []string{"default"},
		},
		{
			yamlString: key + `:
- tetragon-1.log
- tetragon-2.log`,
			defaultValue: []string{"default"},
			expected:     []string{"tetragon-1.log", "tetragon-2.log"},
		},
	}

	for _, tt := range testCases {
		cfgMap := make(map[string]any)
		require.NoError(t, yaml.Unmarshal([]byte(tt.yamlString), &cfgMap))
		// function to test
		actual := configArray(logr.Log, cfgMap, key, tt.defaultValue)

		require.Equal(t, tt.expected, actual)
	}
}

func TestDaemonSet(t *testing.T) {
	dsTerminationGracePeriodSec := int64(1)
	hostPathDirectoryOrCreateVolumeType := corev1.HostPathDirectoryOrCreate
	hostPathDirectoryVolumeType := corev1.HostPathDirectory
	bidirectionalMount := corev1.MountPropagationBidirectional
	dsVolumeDefaultMode := int32(420)
	privileged := true
	livenessProbeService := "liveness"

	testCases := []struct {
		name      string
		namespace string
		dsName    string
		cm        *corev1.ConfigMap
		expected  *appv1.DaemonSet
	}{
		{
			name:      "default values",
			namespace: "kube-system",
			dsName:    "tetragon",
			cm:        DefaultOperatorConfigMap(logr.Log, "kube-system", "tetragon"),
			expected: &appv1.DaemonSet{
				TypeMeta: v1.TypeMeta{
					Kind:       "DaemonSet",
					APIVersion: "apps/v1",
				},
				ObjectMeta: v1.ObjectMeta{
					Name:      "tetragon",
					Namespace: "kube-system",
					Labels: map[string]string{
						"app.kubernetes.io/instance":   "tetragon",
						"app.kubernetes.io/name":       "tetragon",
						"app.kubernetes.io/managed-by": "tetragon-operator",
					},
					Annotations: map[string]string{},
				},
				Spec: appv1.DaemonSetSpec{
					Selector: &v1.LabelSelector{
						MatchLabels: map[string]string{
							"app.kubernetes.io/instance":   "tetragon",
							"app.kubernetes.io/name":       "tetragon",
							"app.kubernetes.io/managed-by": "tetragon-operator",
						},
					},
					Template: corev1.PodTemplateSpec{
						ObjectMeta: v1.ObjectMeta{
							Labels: map[string]string{
								"app.kubernetes.io/instance":   "tetragon",
								"app.kubernetes.io/name":       "tetragon",
								"app.kubernetes.io/managed-by": "tetragon-operator",
							},
							Annotations: map[string]string{},
						},
						Spec: corev1.PodSpec{
							ImagePullSecrets: []corev1.LocalObjectReference{},
							DNSPolicy:        corev1.DNSDefault,
							NodeSelector: map[string]string{
								"kubernetes.io/os": "linux",
							},
							ServiceAccountName:            "tetragon",
							DeprecatedServiceAccount:      "tetragon",
							TerminationGracePeriodSeconds: &dsTerminationGracePeriodSec,
							HostNetwork:                   true,
							SecurityContext:               &corev1.PodSecurityContext{},
							Affinity:                      &corev1.Affinity{},
							Tolerations: []corev1.Toleration{
								{Operator: "Exists"},
							},
							Volumes: []corev1.Volume{
								{
									Name: "cilium-run",
									VolumeSource: corev1.VolumeSource{
										HostPath: &corev1.HostPathVolumeSource{
											Path: "/var/run/cilium",
											Type: &hostPathDirectoryOrCreateVolumeType,
										},
									},
								},
								{
									Name: "export-logs",
									VolumeSource: corev1.VolumeSource{
										HostPath: &corev1.HostPathVolumeSource{
											Path: "/var/run/cilium/tetragon",
											Type: &hostPathDirectoryOrCreateVolumeType,
										},
									},
								},
								{
									Name: "tetragon-config",
									VolumeSource: corev1.VolumeSource{
										ConfigMap: &corev1.ConfigMapVolumeSource{
											LocalObjectReference: corev1.LocalObjectReference{
												Name: "tetragon-config",
											},
											DefaultMode: &dsVolumeDefaultMode,
										},
									},
								},
								{
									Name: "bpf-maps",
									VolumeSource: corev1.VolumeSource{
										HostPath: &corev1.HostPathVolumeSource{
											Path: "/sys/fs/bpf",
											Type: &hostPathDirectoryOrCreateVolumeType,
										},
									},
								},
								{
									Name: "host-proc",
									VolumeSource: corev1.VolumeSource{
										HostPath: &corev1.HostPathVolumeSource{
											Path: "/proc",
											Type: &hostPathDirectoryVolumeType,
										},
									},
								},
							},
							InitContainers: []corev1.Container{},
							Containers: []corev1.Container{
								{
									Name:    "tetragon",
									Command: []string{},
									Args:    []string{"--config-dir=/etc/tetragon/tetragon.conf.d/"},
									Env: []corev1.EnvVar{
										{
											Name: "NODE_NAME",
											ValueFrom: &corev1.EnvVarSource{
												FieldRef: &corev1.ObjectFieldSelector{
													APIVersion: "v1",
													FieldPath:  "spec.nodeName",
												},
											},
										},
									},
									Ports:                    []corev1.ContainerPort{},
									TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
									ImagePullPolicy:          corev1.PullIfNotPresent,
									VolumeMounts: []corev1.VolumeMount{
										{
											Name:      "tetragon-config",
											ReadOnly:  true,
											MountPath: "/etc/tetragon/tetragon.conf.d/",
										},
										{
											Name:             "bpf-maps",
											MountPath:        "/sys/fs/bpf",
											MountPropagation: &bidirectionalMount,
										},
										{
											Name:      "cilium-run",
											MountPath: "/var/run/cilium",
										},
										{
											Name:      "export-logs",
											MountPath: "/var/run/cilium/tetragon",
										},
										{
											Name:      "host-proc",
											MountPath: "/procRoot",
										},
									},
									LivenessProbe: &corev1.Probe{
										TimeoutSeconds: int32(60),
										ProbeHandler: corev1.ProbeHandler{
											GRPC: &corev1.GRPCAction{
												Port:    6789,
												Service: &livenessProbeService,
											},
										},
									},
									SecurityContext: &corev1.SecurityContext{Privileged: &privileged},
								},
							},
						},
					},
				},
			},
		},
		{
			name:      "custom values",
			namespace: "kube-system",
			dsName:    "tetragon",
			cm: &corev1.ConfigMap{
				Data: map[string]string{
					OperatorConfigMapAgentDaemonSetKey: `tetragonEnabled: true
dnsPolicy: ClusterFirst
labelsOverride:
  test-label1: test-value1
  test-label2: test-value2
annotations:
  test-annotation1: test-value1
  test-annotation2: test-value2
podAnnotations:
  pod-annotation1: pod-value1
  pod-annotation2: pod-value2
imagePullSecrets: |
  - name: test-secret1
  - name: test-secret2
podSecurityContext: |
  runAsUser: 123
affinity: |
  podAffinity:
    requiredDuringSchedulingIgnoredDuringExecution:
      - namespaces:
          - test-affinity-ns1
          - test-affinity-ns2
tolerations: |
  - key: test-key1
    value: test-value1
  - key: test-key2
    value: test-value2
updateStrategy: |
  type: RollingUpdate
priorityClassName: system-node-critical
nodeSelector:
  test-selector-key1: test-selector-value1
  test-selector-key2: test-selector-value2
  kubernetes.io/os: linux

exportExtraEnv: |
  - name: test-extra-env1
    value: test-extra-value1
  - name: test-extra-env2
    value: test-extra-value2
exportResources: |
  requests:
    cpu: 1500m
    memory: 1536Mi
exportSecurityContext: |
  privileged: true
tetragonResources: |
  requests:
    cpu: 2500m
    memory: 2536Mi
tetragonSecurityContext: |
  privileged: false
enableCiliumAPI: true

serviceAccountName: tetragon-test
hostNetwork: false
hostProcPath: /proc-test
exportMode: stdout
exportFileNames:
  - tetragon-test1.log
  - tetragon-test2.log
exportDirectory: /var/run/cilium/tetragon-test

# Configure tetragon's init container for setting up tetragon-oci-hook on the host
ociHookSetupEnabled: true

# interface specifies how the hook is configured. There is only one available value for now:
# oci-hooks (https://github.com/containers/common/blob/main/pkg/hooks/docs/oci-hooks.5.md).
ociHookSetupInterface: oci-hooks-test
ociHookSetupInstallDir: /opt/tetragon-test
ociHookSetupSecurityContext: |
 privileged: true
ociHookFailAllowNamespaces: fail-allow-ns

# Extra volume mounts to add to the oci-hook-setup init container
ociHookSetupExtraVolumeMounts: |
  - name: test-oci-extra-volume1
    mountPath: test-oci-extra-path1
  - name: test-oci-extra-volume2
    mountPath: test-oci-extra-path2
ociHookSetupResources: |
  requests:
    cpu: 500m
    memory: 536Mi
metadataEnabled: true
metadataImagePullPolicy: Never
extraVolumes: |
  - name: test-extra-volume1
    hostPath:
      path: test-extra-path1
  - name: test-extra-volume2
    hostPath:
      path: test-extra-path2
extraHostPathMounts: |
  - name: test-extra-host-volume1
    mountPath: test-extra-host-path1
  - name: test-extra-host-volume2
    mountPath: test-extra-host-path2
imagePullPolicy: Never
argsOverride:
  - --test-arg1=test-value1
  - --test-arg2=test-value2
tetragonHealthGrpcEnabled: true
tetragonHealthGrpcPort: "1234"
tetragonGrpcAddress: localhost:54321
serviceMonitorEnabled: true
agentServiceMonitorPrometheusAddress: localhost
agentServiceMonitorPrometheusPort: "1234"`,
					splunkKey: `enabled: true
image:
  repository: quay.io/isovalent/opentelemetry-collector-contrib
  tag: "0.133.0"
resources: |
  limits:
    cpu: "2"
    memory: "4Gi"
  requests:
    cpu: "1"
    memory: "3Gi"
endpoint:
  secretName: splunk-hec
  secretKey: hec-endpoint
token:
  secretName: splunk-hec
  secretKey: hec-token
tls:
  secret:
    name: custom-tetragon-splunk-tls
    keys:
      ca_cert: ca.crt
      client_cert: tls.crt
      client_key: tls.key`,
				},
			},
			expected: &appv1.DaemonSet{
				TypeMeta: v1.TypeMeta{
					Kind:       "DaemonSet",
					APIVersion: "apps/v1",
				},
				ObjectMeta: v1.ObjectMeta{
					Name:      "tetragon",
					Namespace: "kube-system",
					Labels: map[string]string{
						"test-label1": "test-value1",
						"test-label2": "test-value2",
					},
					Annotations: map[string]string{
						"test-annotation1": "test-value1",
						"test-annotation2": "test-value2",
					},
				},
				Spec: appv1.DaemonSetSpec{
					UpdateStrategy: appv1.DaemonSetUpdateStrategy{
						Type: appv1.RollingUpdateDaemonSetStrategyType,
					},
					Selector: &v1.LabelSelector{
						MatchLabels: map[string]string{
							"app.kubernetes.io/instance":   "tetragon",
							"app.kubernetes.io/name":       "tetragon",
							"app.kubernetes.io/managed-by": "tetragon-operator",
						},
					},
					Template: corev1.PodTemplateSpec{
						ObjectMeta: v1.ObjectMeta{
							Labels: map[string]string{
								"app.kubernetes.io/instance":   "tetragon",
								"app.kubernetes.io/name":       "tetragon",
								"app.kubernetes.io/managed-by": "tetragon-operator",
							},
							Annotations: map[string]string{
								"pod-annotation1": "pod-value1",
								"pod-annotation2": "pod-value2",
							},
						},
						Spec: corev1.PodSpec{
							PriorityClassName: "system-node-critical",
							ImagePullSecrets: []corev1.LocalObjectReference{
								{Name: "test-secret1"},
								{Name: "test-secret2"},
							},
							DNSPolicy: corev1.DNSClusterFirst,
							NodeSelector: map[string]string{
								"test-selector-key1": "test-selector-value1",
								"test-selector-key2": "test-selector-value2",
								"kubernetes.io/os":   "linux",
							},
							ServiceAccountName:            "tetragon-test",
							DeprecatedServiceAccount:      "tetragon-test",
							TerminationGracePeriodSeconds: &dsTerminationGracePeriodSec,
							HostNetwork:                   false,
							SecurityContext:               &corev1.PodSecurityContext{RunAsUser: new(int64(123))},
							Affinity: &corev1.Affinity{
								PodAffinity: &corev1.PodAffinity{
									RequiredDuringSchedulingIgnoredDuringExecution: []corev1.PodAffinityTerm{
										{
											Namespaces: []string{"test-affinity-ns1", "test-affinity-ns2"},
										},
									},
								},
							},
							Tolerations: []corev1.Toleration{
								{Key: "test-key1", Value: "test-value1"},
								{Key: "test-key2", Value: "test-value2"},
							},
							Volumes: []corev1.Volume{
								{
									Name: "cilium-run",
									VolumeSource: corev1.VolumeSource{
										HostPath: &corev1.HostPathVolumeSource{
											Path: "/var/run/cilium",
											Type: &hostPathDirectoryOrCreateVolumeType,
										},
									},
								},
								{
									Name: "export-logs",
									VolumeSource: corev1.VolumeSource{
										HostPath: &corev1.HostPathVolumeSource{
											Path: "/var/run/cilium/tetragon-test",
											Type: &hostPathDirectoryOrCreateVolumeType,
										},
									},
								},
								{
									Name: "tetragon-config",
									VolumeSource: corev1.VolumeSource{
										ConfigMap: &corev1.ConfigMapVolumeSource{
											LocalObjectReference: corev1.LocalObjectReference{
												Name: "tetragon-config",
											},
											DefaultMode: &dsVolumeDefaultMode,
										},
									},
								},
								{
									Name: "bpf-maps",
									VolumeSource: corev1.VolumeSource{
										HostPath: &corev1.HostPathVolumeSource{
											Path: "/sys/fs/bpf",
											Type: &hostPathDirectoryOrCreateVolumeType,
										},
									},
								},
								{
									Name: "host-proc",
									VolumeSource: corev1.VolumeSource{
										HostPath: &corev1.HostPathVolumeSource{
											Path: "/proc-test",
											Type: &hostPathDirectoryVolumeType,
										},
									},
								},
								{
									Name: "oci-hooks-path",
									VolumeSource: corev1.VolumeSource{
										HostPath: &corev1.HostPathVolumeSource{
											Path: "/usr/share/containers/oci/hooks.d/",
											Type: &hostPathDirectoryVolumeType,
										},
									},
								},
								{
									Name: "oci-hooks-install-path",
									VolumeSource: corev1.VolumeSource{
										HostPath: &corev1.HostPathVolumeSource{
											Path: "/opt/tetragon-test",
											Type: &hostPathDirectoryOrCreateVolumeType,
										},
									},
								},
								{
									Name: "otel-agent-config-vol",
									VolumeSource: corev1.VolumeSource{
										ConfigMap: &corev1.ConfigMapVolumeSource{
											LocalObjectReference: corev1.LocalObjectReference{
												Name: OtelConfigMapName,
											},
											Items: []corev1.KeyToPath{{
												Key:  "otel-agent-config",
												Path: "otel-agent-config.yaml",
											}},
										},
									},
								},
								{
									Name: "file-storage",
									VolumeSource: corev1.VolumeSource{
										EmptyDir: &corev1.EmptyDirVolumeSource{},
									},
								},
								{
									Name: "otel-splunk-tls",
									VolumeSource: corev1.VolumeSource{
										Secret: &corev1.SecretVolumeSource{
											SecretName: "custom-tetragon-splunk-tls",
										},
									},
								},
								{
									Name: "test-extra-volume1",
									VolumeSource: corev1.VolumeSource{
										HostPath: &corev1.HostPathVolumeSource{
											Path: "test-extra-path1",
										},
									},
								},
								{
									Name: "test-extra-volume2",
									VolumeSource: corev1.VolumeSource{
										HostPath: &corev1.HostPathVolumeSource{
											Path: "test-extra-path2",
										},
									},
								},
								{
									Name: "test-extra-host-volume1",
									VolumeSource: corev1.VolumeSource{
										HostPath: &corev1.HostPathVolumeSource{
											Path: "test-extra-host-path1",
										},
									},
								},
								{
									Name: "test-extra-host-volume2",
									VolumeSource: corev1.VolumeSource{
										HostPath: &corev1.HostPathVolumeSource{
											Path: "test-extra-host-path2",
										},
									},
								},
								{
									Name: "metadata-files",
									VolumeSource: corev1.VolumeSource{
										EmptyDir: &corev1.EmptyDirVolumeSource{},
									},
								},
							},
							InitContainers: []corev1.Container{
								{
									Name:                     "oci-hook-setup",
									SecurityContext:          &corev1.SecurityContext{Privileged: &privileged},
									TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
									Command: []string{
										"tetragon-oci-hook-setup",
										"install",
										"--interface",
										"oci-hooks-test",
										"--local-install-dir=/hostInstall",
										"--host-install-dir",
										"/opt/tetragon-test",
										"--oci-hooks.local-dir=/hostHooks",
										"hook-args",
										"--grpc-address=localhost:54321",
										"--fail-allow-namespaces",
										"kube-system,fail-allow-ns",
									},
									VolumeMounts: []corev1.VolumeMount{
										{
											Name:      "test-oci-extra-volume1",
											MountPath: "test-oci-extra-path1",
										},
										{
											Name:      "test-oci-extra-volume2",
											MountPath: "test-oci-extra-path2",
										},
										{
											Name:      "oci-hooks-path",
											MountPath: "/hostHooks",
										},
										{
											Name:      "oci-hooks-install-path",
											MountPath: "/hostInstall",
										},
									},
									Resources: corev1.ResourceRequirements{
										Requests: map[corev1.ResourceName]resource.Quantity{
											corev1.ResourceCPU:    resource.MustParse("500m"),
											corev1.ResourceMemory: resource.MustParse("536Mi"),
										},
									},
								},
								{
									Name:    "tetragon",
									Command: []string{"sh"},
									Args:    []string{"-c", "|\ncp -r /var/run/tetragon-ee-metadata/* /var/lib/tetragon/metadata\nuntil [ -S /var/run/cilium/cilium.sock -a -S /var/run/cilium/monitor1_2.sock ]; do sleep 3; done"},
									VolumeMounts: []corev1.VolumeMount{
										{
											Name:      "metadata-files",
											MountPath: "/var/lib/tetragon/metadata",
										},
										{
											Name:      "cilium-run",
											MountPath: "/var/run/cilium",
										},
									},
									TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
									ImagePullPolicy:          corev1.PullNever,
								},
							},
							Containers: []corev1.Container{
								{
									Name:                     "export-stdout",
									ImagePullPolicy:          corev1.PullNever,
									TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
									Command:                  []string{"hubble-export-stdout"},
									Args: []string{
										"/var/run/cilium/tetragon-test/tetragon-test1.log",
										"/var/run/cilium/tetragon-test/tetragon-test2.log",
									},
									Env: []corev1.EnvVar{
										{Name: "test-extra-env1", Value: "test-extra-value1"},
										{Name: "test-extra-env2", Value: "test-extra-value2"},
									},
									VolumeMounts: []corev1.VolumeMount{{
										Name:      "export-logs",
										MountPath: "/var/run/cilium/tetragon-test",
									}},
									SecurityContext: &corev1.SecurityContext{Privileged: &privileged},
									Resources: corev1.ResourceRequirements{
										Requests: map[corev1.ResourceName]resource.Quantity{
											corev1.ResourceCPU:    resource.MustParse("1500m"),
											corev1.ResourceMemory: resource.MustParse("1536Mi"),
										},
									},
								},
								{
									Name:    "tetragon",
									Command: []string{},
									Args: []string{
										"--config-dir=/etc/tetragon/tetragon.conf.d/",
										"--metrics-server=localhost:1234",
										"--test-arg1=test-value1",
										"--test-arg2=test-value2",
									},
									Env: []corev1.EnvVar{
										{
											Name: "NODE_NAME",
											ValueFrom: &corev1.EnvVarSource{
												FieldRef: &corev1.ObjectFieldSelector{
													APIVersion: "v1",
													FieldPath:  "spec.nodeName",
												},
											},
										},
									},
									Ports: []corev1.ContainerPort{{
										Name:          "metrics",
										ContainerPort: 1234,
										Protocol:      "TCP",
									}},
									TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
									ImagePullPolicy:          corev1.PullNever,
									VolumeMounts: []corev1.VolumeMount{
										{
											Name:      "tetragon-config",
											ReadOnly:  true,
											MountPath: "/etc/tetragon/tetragon.conf.d/",
										},
										{
											Name:             "bpf-maps",
											MountPath:        "/sys/fs/bpf",
											MountPropagation: &bidirectionalMount,
										},
										{
											Name:      "cilium-run",
											MountPath: "/var/run/cilium",
										},
										{
											Name:      "export-logs",
											MountPath: "/var/run/cilium/tetragon-test",
										},
										{
											Name:      "host-proc",
											MountPath: "/procRoot",
										},
										{
											Name:      "test-extra-host-volume1",
											MountPath: "test-extra-host-path1",
										},
										{
											Name:      "test-extra-host-volume2",
											MountPath: "test-extra-host-path2",
										},
										{
											Name:      "metadata-files",
											MountPath: "/var/lib/tetragon/metadata",
										},
									},
									LivenessProbe: &corev1.Probe{
										TimeoutSeconds: int32(60),
										ProbeHandler: corev1.ProbeHandler{
											GRPC: &corev1.GRPCAction{
												Port:    1234,
												Service: &livenessProbeService,
											},
										},
									},
									SecurityContext: &corev1.SecurityContext{Privileged: new(false)},
									Resources: corev1.ResourceRequirements{
										Requests: map[corev1.ResourceName]resource.Quantity{
											corev1.ResourceCPU:    resource.MustParse("2500m"),
											corev1.ResourceMemory: resource.MustParse("2536Mi"),
										},
									},
								},
								{
									Name:    "tetragon-otel-agent",
									Command: []string{"/otelcol-contrib", "--config=/conf/otel-agent-config.yaml"},
									Args:    []string{},
									Image:   "quay.io/isovalent/opentelemetry-collector-contrib:0.133.0",
									Env: []corev1.EnvVar{
										{
											Name: "K8S_NODE",
											ValueFrom: &corev1.EnvVarSource{
												FieldRef: &corev1.ObjectFieldSelector{
													APIVersion: "v1",
													FieldPath:  "spec.nodeName",
												},
											},
										},
										{
											Name: "SPLUNK_HEC_TOKEN",
											ValueFrom: &corev1.EnvVarSource{
												SecretKeyRef: &corev1.SecretKeySelector{
													LocalObjectReference: corev1.LocalObjectReference{
														Name: "splunk-hec",
													},
													Key: "hec-token",
												},
											},
										},
										{
											Name: "SPLUNK_HEC_ENDPOINT",
											ValueFrom: &corev1.EnvVarSource{
												SecretKeyRef: &corev1.SecretKeySelector{
													LocalObjectReference: corev1.LocalObjectReference{
														Name: "splunk-hec",
													},
													Key: "hec-endpoint",
												},
											},
										},
									},
									Ports:                    []corev1.ContainerPort{},
									TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
									ImagePullPolicy:          corev1.PullIfNotPresent,
									VolumeMounts: []corev1.VolumeMount{
										{
											Name:      "otel-agent-config-vol",
											ReadOnly:  true,
											MountPath: "/conf",
										},
										{
											Name:      "export-logs",
											MountPath: "/var/run/cilium/tetragon-test",
										},
										{
											Name:      "file-storage",
											MountPath: "/var/lib/otelcol/file-storage",
										},
										{
											Name:      "otel-splunk-tls",
											MountPath: "/tls",
											ReadOnly:  true,
										},
									},
									Resources: corev1.ResourceRequirements{
										Limits: corev1.ResourceList{
											corev1.ResourceCPU:    resource.MustParse("2"),
											corev1.ResourceMemory: resource.MustParse("4Gi"),
										},
										Requests: corev1.ResourceList{
											corev1.ResourceCPU:    resource.MustParse("1"),
											corev1.ResourceMemory: resource.MustParse("3Gi"),
										},
									},
									SecurityContext: &corev1.SecurityContext{
										AllowPrivilegeEscalation: new(false),
										Capabilities: &corev1.Capabilities{
											Drop: []corev1.Capability{"All"},
										},
										ReadOnlyRootFilesystem: new(true),
										RunAsUser:              new(int64(0)),
										RunAsGroup:             new(int64(0)),
									},
								},
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			// function to test
			actual, err := DaemonSet(logr.Log, tt.namespace, tt.dsName, tt.cm)
			require.NoError(t, err)
			require.Equal(t, tt.expected, actual)
		})
	}
}

func TestDaemonSetInitContainers(t *testing.T) {
	privileged := true
	testCases := []struct {
		name            string
		agentYAMLString string
		rtYAMLString    string
		expected        []corev1.Container
	}{
		{
			name: "init containers disabled (explicitly)",
			agentYAMLString: `ociHookSetupEnabled: false
metadataEnabled: false`,
			expected: []corev1.Container{},
		},
		{
			name: "oci-hook-setup init container enabled (with default values)",
			agentYAMLString: `ociHookSetupEnabled: true
ociHookSetupInterface: oci-hooks
ociHookSetupInstallDir: /opt/tetragon
ociHookSetupSecurityContext: |
  privileged: true`,
			rtYAMLString: ``,
			expected: []corev1.Container{{
				Name: "oci-hook-setup",
				Command: []string{
					"tetragon-oci-hook-setup",
					"install",
					"--interface",
					"oci-hooks",
					"--local-install-dir=/hostInstall",
					"--host-install-dir",
					"/opt/tetragon",
					"--oci-hooks.local-dir=/hostHooks",
					"hook-args",
					"--grpc-address=",
					"--fail-allow-namespaces",
					"kube-system",
				},
				VolumeMounts: []corev1.VolumeMount{
					{
						Name:      "oci-hooks-path",
						MountPath: "/hostHooks",
					},
					{
						Name:      "oci-hooks-install-path",
						MountPath: "/hostInstall",
					},
				},
				TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
				SecurityContext:          &corev1.SecurityContext{Privileged: &privileged},
			}},
		},
		{
			name:            "tetragon init container enabled (with default values)",
			agentYAMLString: "metadataEnabled: true",
			expected: []corev1.Container{{
				Name:    "tetragon",
				Command: []string{"sh"},
				Args:    []string{"-c", "|\ncp -r /var/run/tetragon-ee-metadata/* /var/lib/tetragon/metadata"},
				VolumeMounts: []corev1.VolumeMount{
					{
						Name:      "metadata-files",
						MountPath: "/var/lib/tetragon/metadata",
					},
				},
				TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
				ImagePullPolicy:          corev1.PullIfNotPresent,
			}},
		},
		{
			name: "oci-hook-setup and tetragon init containers enabled (with default values)",
			agentYAMLString: `ociHookSetupEnabled: true
ociHookSetupInterface: oci-hooks
ociHookSetupInstallDir: /opt/tetragon
ociHookSetupSecurityContext: |
  privileged: true
metadataEnabled: true`,
			rtYAMLString: ``,
			expected: []corev1.Container{
				{
					Name: "oci-hook-setup",
					Command: []string{
						"tetragon-oci-hook-setup",
						"install",
						"--interface",
						"oci-hooks",
						"--local-install-dir=/hostInstall",
						"--host-install-dir",
						"/opt/tetragon",
						"--oci-hooks.local-dir=/hostHooks",
						"hook-args",
						"--grpc-address=",
						"--fail-allow-namespaces",
						"kube-system",
					},
					VolumeMounts: []corev1.VolumeMount{
						{
							Name:      "oci-hooks-path",
							MountPath: "/hostHooks",
						},
						{
							Name:      "oci-hooks-install-path",
							MountPath: "/hostInstall",
						},
					},
					TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
					SecurityContext:          &corev1.SecurityContext{Privileged: &privileged},
				},
				{
					Name:    "tetragon",
					Command: []string{"sh"},
					Args:    []string{"-c", "|\ncp -r /var/run/tetragon-ee-metadata/* /var/lib/tetragon/metadata"},
					VolumeMounts: []corev1.VolumeMount{
						{
							Name:      "metadata-files",
							MountPath: "/var/lib/tetragon/metadata",
						},
					},
					TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
					ImagePullPolicy:          corev1.PullIfNotPresent,
				},
			},
		},
		{
			name: "oci-hook-setup and tetragon init containers enabled (with custom values)",
			agentYAMLString: `ociHookSetupEnabled: true
ociHookSetupSecurityContext: |
  privileged: false
ociHookSetupExtraVolumeMounts: |
  - name: extra-mount-test1
    mountPath: /extra/test1
  - name: extra-mount-test2
    mountPath: /extra/test2
ociHookSetupResources: |
  requests:
    cpu: 1500m
    memory: 1536Mi
ociHookSetupInterface: oci-hooks-test
ociHookSetupInstallDir: /test/install
ociHookFailAllowNamespaces: fail-allow-ns
tetragonGrpcAddress: localhost:54321
metadataEnabled: true
enableCiliumAPI: true
metadataImagePullPolicy: Always
`,
			rtYAMLString: ``,
			expected: []corev1.Container{
				{
					Name: "oci-hook-setup",
					Command: []string{
						"tetragon-oci-hook-setup",
						"install",
						"--interface",
						"oci-hooks-test",
						"--local-install-dir=/hostInstall",
						"--host-install-dir",
						"/test/install",
						"--oci-hooks.local-dir=/hostHooks",
						"hook-args",
						"--grpc-address=localhost:54321",
						"--fail-allow-namespaces",
						"kube-system,fail-allow-ns",
					},
					VolumeMounts: []corev1.VolumeMount{
						{
							Name:      "extra-mount-test1",
							MountPath: "/extra/test1",
						},
						{
							Name:      "extra-mount-test2",
							MountPath: "/extra/test2",
						},
						{
							Name:      "oci-hooks-path",
							MountPath: "/hostHooks",
						},
						{
							Name:      "oci-hooks-install-path",
							MountPath: "/hostInstall",
						},
					},
					TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
					SecurityContext:          &corev1.SecurityContext{Privileged: new(false)},
					Resources: corev1.ResourceRequirements{
						Requests: map[corev1.ResourceName]resource.Quantity{
							corev1.ResourceCPU:    resource.MustParse("1500m"),
							corev1.ResourceMemory: resource.MustParse("1536Mi"),
						},
					},
				},
				{
					Name:    "tetragon",
					Command: []string{"sh"},
					Args:    []string{"-c", "|\ncp -r /var/run/tetragon-ee-metadata/* /var/lib/tetragon/metadata\nuntil [ -S /var/run/cilium/cilium.sock -a -S /var/run/cilium/monitor1_2.sock ]; do sleep 3; done"},
					VolumeMounts: []corev1.VolumeMount{
						{
							Name:      "metadata-files",
							MountPath: "/var/lib/tetragon/metadata",
						},
						{
							Name:      "cilium-run",
							MountPath: "/var/run/cilium",
						},
					},
					TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
					ImagePullPolicy:          corev1.PullAlways,
				},
			},
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			agentConfigMap := make(map[string]any)
			require.NoError(t, yaml.Unmarshal([]byte(tt.agentYAMLString), &agentConfigMap))
			require.NoError(t, yaml.Unmarshal([]byte(tt.rtYAMLString), new(make(map[string]any))))
			// function to test
			actual := daemonSetInitContainers(logr.Log, "kube-system", agentConfigMap)
			require.Equal(t, tt.expected, actual)
		})
	}
}

func TestDaemonSetContainers(t *testing.T) {
	privileged := true
	bidirectionalMount := corev1.MountPropagationBidirectional
	livenessProbeService := "liveness"

	testCases := []struct {
		name       string
		yamlString string
		expected   []corev1.Container
	}{
		{
			name: "tetragon container enabled (with default values)",
			yamlString: `exportDirectory: /var/run/cilium/tetragon
tetragonEnabled: true
tetragonSecurityContext: |
  privileged: true
tetragonHealthGrpcEnabled: true
tetragonHealthGrpcPort: 6789`,
			expected: []corev1.Container{{
				Name:                     "tetragon",
				ImagePullPolicy:          corev1.PullIfNotPresent,
				TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
				Command:                  []string{},
				Args:                     []string{"--config-dir=/etc/tetragon/tetragon.conf.d/"},
				Env: []corev1.EnvVar{{
					Name: "NODE_NAME",
					ValueFrom: &corev1.EnvVarSource{
						FieldRef: &corev1.ObjectFieldSelector{
							APIVersion: "v1",
							FieldPath:  "spec.nodeName",
						},
					},
				}},
				Ports: []corev1.ContainerPort{},
				VolumeMounts: []corev1.VolumeMount{
					{
						Name:      "tetragon-config",
						ReadOnly:  true,
						MountPath: "/etc/tetragon/tetragon.conf.d/",
					},
					{
						Name:             "bpf-maps",
						MountPath:        "/sys/fs/bpf",
						MountPropagation: &bidirectionalMount,
					},
					{
						Name:      "cilium-run",
						MountPath: "/var/run/cilium",
					},
					{
						Name:      "export-logs",
						MountPath: "/var/run/cilium/tetragon",
					},
					{
						Name:      "host-proc",
						MountPath: "/procRoot",
					},
				},
				SecurityContext: &corev1.SecurityContext{Privileged: &privileged},
				LivenessProbe: &corev1.Probe{
					TimeoutSeconds: int32(60),
					ProbeHandler: corev1.ProbeHandler{
						GRPC: &corev1.GRPCAction{
							Port:    6789,
							Service: &livenessProbeService,
						},
					},
				},
			}},
		},
		{
			name:       "export and tetragon containers enabled (with default values)",
			yamlString: defaultDSConfig,
			expected: []corev1.Container{
				{
					Name:                     "tetragon",
					ImagePullPolicy:          corev1.PullIfNotPresent,
					TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
					Command:                  []string{},
					Args:                     []string{"--config-dir=/etc/tetragon/tetragon.conf.d/"},
					Env: []corev1.EnvVar{{
						Name: "NODE_NAME",
						ValueFrom: &corev1.EnvVarSource{
							FieldRef: &corev1.ObjectFieldSelector{
								APIVersion: "v1",
								FieldPath:  "spec.nodeName",
							},
						},
					}},
					Ports: []corev1.ContainerPort{},
					VolumeMounts: []corev1.VolumeMount{
						{
							Name:      "tetragon-config",
							ReadOnly:  true,
							MountPath: "/etc/tetragon/tetragon.conf.d/",
						},
						{
							Name:             "bpf-maps",
							MountPath:        "/sys/fs/bpf",
							MountPropagation: &bidirectionalMount,
						},
						{
							Name:      "cilium-run",
							MountPath: "/var/run/cilium",
						},
						{
							Name:      "export-logs",
							MountPath: "/var/run/cilium/tetragon",
						},
						{
							Name:      "host-proc",
							MountPath: "/procRoot",
						},
					},
					SecurityContext: &corev1.SecurityContext{Privileged: &privileged},
					LivenessProbe: &corev1.Probe{
						TimeoutSeconds: int32(60),
						ProbeHandler: corev1.ProbeHandler{
							GRPC: &corev1.GRPCAction{
								Port:    6789,
								Service: &livenessProbeService,
							},
						},
					},
				},
			},
		},
		{
			name: "export and tetragon containers enabled (with custom values)",
			yamlString: `imagePullPolicy: Always
exportDirectory: /test/export
tetragonHealthGrpcEnabled: true
tetragonHealthGrpcPort: "1234"
metadataEnabled: true
exportMode: stdout
exportExtraEnv: |
  - name: export-env1
    value: export-value1
  - name: export-env2
    value: export-value2
exportResources: |
  requests:
    cpu: 1500m
    memory: 1536Mi
exportSecurityContext: |
  privileged: true
exportFileNames:
  - export-file1.log
  - export-file2.log
tetragonEnabled: true
tetragonResources: |
  requests:
    cpu: 2500m
    memory: 2536Mi
tetragonSecurityContext: |
  privileged: false
argsOverride:
  - test-arg1
  - test-arg2
extraVolumeMounts: |
  - name: extra-volume1
    mountPath: /extra/test1
  - name: extra-volume2
    mountPath: /extra/test2
extraHostPathMounts: |
  - name: host-volume1
    mountPath: /host/test1
  - name: host-volume2
    mountPath: /host/test2
extraConfigmapMounts: |
  - name: cm-volume1
    mountPath: /cm/test1
  - name: cm-volume2
    mountPath: /cm/test2
extraEnv: |
  - name: extra-env1
    value: extra-value1
  - name: extra-env2
    value: extra-value2
commandOverride: |
  - cmd1
  - cmd2`,
			expected: []corev1.Container{
				{
					Name:                     "export-stdout",
					ImagePullPolicy:          corev1.PullAlways,
					TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
					Command:                  []string{"hubble-export-stdout"},
					Args: []string{
						"/test/export/export-file1.log",
						"/test/export/export-file2.log",
					},
					Env: []corev1.EnvVar{
						{Name: "export-env1", Value: "export-value1"},
						{Name: "export-env2", Value: "export-value2"},
					},
					VolumeMounts: []corev1.VolumeMount{{
						Name:      "export-logs",
						MountPath: "/test/export",
					}},
					SecurityContext: &corev1.SecurityContext{Privileged: &privileged},
					Resources: corev1.ResourceRequirements{
						Requests: map[corev1.ResourceName]resource.Quantity{
							corev1.ResourceCPU:    resource.MustParse("1500m"),
							corev1.ResourceMemory: resource.MustParse("1536Mi"),
						},
					},
				},
				{
					Name:                     "tetragon",
					ImagePullPolicy:          corev1.PullAlways,
					TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
					Command:                  []string{},
					Args: []string{
						"--config-dir=/etc/tetragon/tetragon.conf.d/",
						"test-arg1",
						"test-arg2",
					},
					Env: []corev1.EnvVar{
						{
							Name: "NODE_NAME",
							ValueFrom: &corev1.EnvVarSource{
								FieldRef: &corev1.ObjectFieldSelector{
									APIVersion: "v1",
									FieldPath:  "spec.nodeName",
								},
							},
						},
						{Name: "extra-env1", Value: "extra-value1"},
						{Name: "extra-env2", Value: "extra-value2"},
					},
					Ports: []corev1.ContainerPort{},
					VolumeMounts: []corev1.VolumeMount{
						{
							Name:      "tetragon-config",
							ReadOnly:  true,
							MountPath: "/etc/tetragon/tetragon.conf.d/",
						},
						{
							Name:             "bpf-maps",
							MountPath:        "/sys/fs/bpf",
							MountPropagation: &bidirectionalMount,
						},
						{
							Name:      "cilium-run",
							MountPath: "/var/run/cilium",
						},
						{
							Name:      "export-logs",
							MountPath: "/test/export",
						},
						{
							Name:      "host-proc",
							MountPath: "/procRoot",
						},
						{
							Name:      "extra-volume1",
							MountPath: "/extra/test1",
						},
						{
							Name:      "extra-volume2",
							MountPath: "/extra/test2",
						},
						{
							Name:      "host-volume1",
							MountPath: "/host/test1",
						},
						{
							Name:      "host-volume2",
							MountPath: "/host/test2",
						},
						{
							Name:      "cm-volume1",
							MountPath: "/cm/test1",
						},
						{
							Name:      "cm-volume2",
							MountPath: "/cm/test2",
						},
						{
							Name:      "metadata-files",
							MountPath: "/var/lib/tetragon/metadata",
						},
					},
					SecurityContext: &corev1.SecurityContext{Privileged: new(false)},
					Resources: corev1.ResourceRequirements{
						Requests: map[corev1.ResourceName]resource.Quantity{
							corev1.ResourceCPU:    resource.MustParse("2500m"),
							corev1.ResourceMemory: resource.MustParse("2536Mi"),
						},
					},
					LivenessProbe: &corev1.Probe{
						TimeoutSeconds: int32(60),
						ProbeHandler: corev1.ProbeHandler{
							GRPC: &corev1.GRPCAction{
								Port:    1234,
								Service: &livenessProbeService,
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			cfgMap := make(map[string]any)
			require.NoError(t, yaml.Unmarshal([]byte(tt.yamlString), &cfgMap))
			// function to test
			actual := daemonSetContainers(logr.Log, cfgMap)

			require.Equal(t, tt.expected, actual)
		})
	}
}

func TestVolumes(t *testing.T) {
	hostPathDirectoryVolumeType := corev1.HostPathDirectory
	hostPathDirectoryOrCreateVolumeType := corev1.HostPathDirectoryOrCreate
	dsVolumeDefaultMode := int32(420)

	testCases := []struct {
		name         string
		yamlString   string
		splunkString string
		expected     []corev1.Volume
	}{
		{
			name: "default values",
			yamlString: `tetragonEnabled: true
exportDirectory: /var/run/cilium/tetragon
hostProcPath: /proc`,
			splunkString: ``,
			expected: []corev1.Volume{
				{
					Name: "cilium-run",
					VolumeSource: corev1.VolumeSource{
						HostPath: &corev1.HostPathVolumeSource{
							Path: "/var/run/cilium",
							Type: &hostPathDirectoryOrCreateVolumeType,
						},
					},
				},
				{
					Name: "export-logs",
					VolumeSource: corev1.VolumeSource{
						HostPath: &corev1.HostPathVolumeSource{
							Path: "/var/run/cilium/tetragon",
							Type: &hostPathDirectoryOrCreateVolumeType,
						},
					},
				},
				{
					Name: "tetragon-config",
					VolumeSource: corev1.VolumeSource{
						ConfigMap: &corev1.ConfigMapVolumeSource{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: "tetragon-config",
							},
							DefaultMode: &dsVolumeDefaultMode,
						},
					},
				},
				{
					Name: "bpf-maps",
					VolumeSource: corev1.VolumeSource{
						HostPath: &corev1.HostPathVolumeSource{
							Path: "/sys/fs/bpf",
							Type: &hostPathDirectoryOrCreateVolumeType,
						},
					},
				},
				{
					Name: "host-proc",
					VolumeSource: corev1.VolumeSource{
						HostPath: &corev1.HostPathVolumeSource{
							Path: "/proc",
							Type: &hostPathDirectoryVolumeType,
						},
					},
				},
			},
		},
		{
			name: "tetragon disabled",
			yamlString: `tetragonEnabled: false
exportDirectory: /var/run/cilium/tetragon
hostProcPath: /proc`,
			splunkString: ``,
			expected: []corev1.Volume{
				{
					Name: "cilium-run",
					VolumeSource: corev1.VolumeSource{
						HostPath: &corev1.HostPathVolumeSource{
							Path: "/var/run/cilium",
							Type: &hostPathDirectoryOrCreateVolumeType,
						},
					},
				},
				{
					Name: "export-logs",
					VolumeSource: corev1.VolumeSource{
						HostPath: &corev1.HostPathVolumeSource{
							Path: "/var/run/cilium/tetragon",
							Type: &hostPathDirectoryOrCreateVolumeType,
						},
					},
				},
			},
		},
		{
			name: "tetragon, oci-hook and splunk_hec enabled",
			yamlString: `ociHookSetupEnabled: true
tetragonEnabled: true
exportDirectory: /var/run/cilium/tetragon
hostProcPath: /proc
ociHookSetupInstallDir: /opt/tetragon`,
			splunkString: `enabled: true
tls:
  secret:
    name: custom-tetragon-splunk-tls`,
			expected: []corev1.Volume{
				{
					Name: "cilium-run",
					VolumeSource: corev1.VolumeSource{
						HostPath: &corev1.HostPathVolumeSource{
							Path: "/var/run/cilium",
							Type: &hostPathDirectoryOrCreateVolumeType,
						},
					},
				},
				{
					Name: "export-logs",
					VolumeSource: corev1.VolumeSource{
						HostPath: &corev1.HostPathVolumeSource{
							Path: "/var/run/cilium/tetragon",
							Type: &hostPathDirectoryOrCreateVolumeType,
						},
					},
				},
				{
					Name: "tetragon-config",
					VolumeSource: corev1.VolumeSource{
						ConfigMap: &corev1.ConfigMapVolumeSource{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: "tetragon-config",
							},
							DefaultMode: &dsVolumeDefaultMode,
						},
					},
				},
				{
					Name: "bpf-maps",
					VolumeSource: corev1.VolumeSource{
						HostPath: &corev1.HostPathVolumeSource{
							Path: "/sys/fs/bpf",
							Type: &hostPathDirectoryOrCreateVolumeType,
						},
					},
				},
				{
					Name: "host-proc",
					VolumeSource: corev1.VolumeSource{
						HostPath: &corev1.HostPathVolumeSource{
							Path: "/proc",
							Type: &hostPathDirectoryVolumeType,
						},
					},
				},
				{
					Name: "oci-hooks-path",
					VolumeSource: corev1.VolumeSource{
						HostPath: &corev1.HostPathVolumeSource{
							Path: "/usr/share/containers/oci/hooks.d/",
							Type: &hostPathDirectoryVolumeType,
						},
					},
				},
				{
					Name: "oci-hooks-install-path",
					VolumeSource: corev1.VolumeSource{
						HostPath: &corev1.HostPathVolumeSource{
							Path: "/opt/tetragon",
							Type: &hostPathDirectoryOrCreateVolumeType,
						},
					},
				},
				{
					Name: "otel-agent-config-vol",
					VolumeSource: corev1.VolumeSource{
						ConfigMap: &corev1.ConfigMapVolumeSource{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: OtelConfigMapName,
							},
							Items: []corev1.KeyToPath{{
								Key:  "otel-agent-config",
								Path: "otel-agent-config.yaml",
							}},
						},
					},
				},
				{
					Name: "file-storage",
					VolumeSource: corev1.VolumeSource{
						EmptyDir: &corev1.EmptyDirVolumeSource{},
					},
				},
				{
					Name: "otel-splunk-tls",
					VolumeSource: corev1.VolumeSource{
						Secret: &corev1.SecretVolumeSource{
							SecretName: "custom-tetragon-splunk-tls",
						},
					},
				},
			},
		},
		{
			name: "tetragon, oci-hook and splunk_hec enabled",
			yamlString: `ociHookSetupEnabled: true
tetragonEnabled: true
exportDirectory: /var/run/cilium/tetragon
hostProcPath: /proc
ociHookSetupInstallDir: /opt/tetragon`,
			splunkString: `enabled: true
tls:
  ca: |
    -----BEGIN CERTIFICATE-----
    xxxxxxxxxxxxxxxxxxxxxxxxxxx
    -----END CERTIFICATE-------
  crt: |
    -----BEGIN CERTIFICATE-----
    xxxxxxxxxxxxxxxxxxxxxxxxxxx
    -----END CERTIFICATE-------
  key: |
    -----BEGIN CERTIFICATE-----
    xxxxxxxxxxxxxxxxxxxxxxxxxxx
    -----END CERTIFICATE-------`,
			expected: []corev1.Volume{
				{
					Name: "cilium-run",
					VolumeSource: corev1.VolumeSource{
						HostPath: &corev1.HostPathVolumeSource{
							Path: "/var/run/cilium",
							Type: &hostPathDirectoryOrCreateVolumeType,
						},
					},
				},
				{
					Name: "export-logs",
					VolumeSource: corev1.VolumeSource{
						HostPath: &corev1.HostPathVolumeSource{
							Path: "/var/run/cilium/tetragon",
							Type: &hostPathDirectoryOrCreateVolumeType,
						},
					},
				},
				{
					Name: "tetragon-config",
					VolumeSource: corev1.VolumeSource{
						ConfigMap: &corev1.ConfigMapVolumeSource{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: "tetragon-config",
							},
							DefaultMode: &dsVolumeDefaultMode,
						},
					},
				},
				{
					Name: "bpf-maps",
					VolumeSource: corev1.VolumeSource{
						HostPath: &corev1.HostPathVolumeSource{
							Path: "/sys/fs/bpf",
							Type: &hostPathDirectoryOrCreateVolumeType,
						},
					},
				},
				{
					Name: "host-proc",
					VolumeSource: corev1.VolumeSource{
						HostPath: &corev1.HostPathVolumeSource{
							Path: "/proc",
							Type: &hostPathDirectoryVolumeType,
						},
					},
				},
				{
					Name: "oci-hooks-path",
					VolumeSource: corev1.VolumeSource{
						HostPath: &corev1.HostPathVolumeSource{
							Path: "/usr/share/containers/oci/hooks.d/",
							Type: &hostPathDirectoryVolumeType,
						},
					},
				},
				{
					Name: "oci-hooks-install-path",
					VolumeSource: corev1.VolumeSource{
						HostPath: &corev1.HostPathVolumeSource{
							Path: "/opt/tetragon",
							Type: &hostPathDirectoryOrCreateVolumeType,
						},
					},
				},
				{
					Name: "otel-agent-config-vol",
					VolumeSource: corev1.VolumeSource{
						ConfigMap: &corev1.ConfigMapVolumeSource{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: OtelConfigMapName,
							},
							Items: []corev1.KeyToPath{{
								Key:  "otel-agent-config",
								Path: "otel-agent-config.yaml",
							}},
						},
					},
				},
				{
					Name: "file-storage",
					VolumeSource: corev1.VolumeSource{
						EmptyDir: &corev1.EmptyDirVolumeSource{},
					},
				},
				{
					Name: "otel-splunk-tls",
					VolumeSource: corev1.VolumeSource{
						Secret: &corev1.SecretVolumeSource{
							SecretName: "tetragon-splunk-tls",
						},
					},
				},
			},
		},
		{
			name: "tetragon and oci-hook enabled with extra volumes and metadata",
			yamlString: `ociHookSetupEnabled: true
tetragonEnabled: true
exportDirectory: /var/run/cilium/tetragon
hostProcPath: /proc
ociHookSetupInstallDir: /opt/tetragon
extraVolumes: |
  - name: extra-volume1
    hostPath:
      path: /extra/test1
      type: DirectoryOrCreate
  - name: extra-volume2
    hostPath:
      path: /extra/test2
      type: DirectoryOrCreate
extraHostPathMounts: |
  - name: host-volume1
    mountPath: /host/test1
  - name: host-volume2
    mountPath: /host/test2
metadataEnabled: true
`,
			splunkString: ``,
			expected: []corev1.Volume{
				{
					Name: "cilium-run",
					VolumeSource: corev1.VolumeSource{
						HostPath: &corev1.HostPathVolumeSource{
							Path: "/var/run/cilium",
							Type: &hostPathDirectoryOrCreateVolumeType,
						},
					},
				},
				{
					Name: "export-logs",
					VolumeSource: corev1.VolumeSource{
						HostPath: &corev1.HostPathVolumeSource{
							Path: "/var/run/cilium/tetragon",
							Type: &hostPathDirectoryOrCreateVolumeType,
						},
					},
				},
				{
					Name: "tetragon-config",
					VolumeSource: corev1.VolumeSource{
						ConfigMap: &corev1.ConfigMapVolumeSource{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: "tetragon-config",
							},
							DefaultMode: &dsVolumeDefaultMode,
						},
					},
				},
				{
					Name: "bpf-maps",
					VolumeSource: corev1.VolumeSource{
						HostPath: &corev1.HostPathVolumeSource{
							Path: "/sys/fs/bpf",
							Type: &hostPathDirectoryOrCreateVolumeType,
						},
					},
				},
				{
					Name: "host-proc",
					VolumeSource: corev1.VolumeSource{
						HostPath: &corev1.HostPathVolumeSource{
							Path: "/proc",
							Type: &hostPathDirectoryVolumeType,
						},
					},
				},
				{
					Name: "oci-hooks-path",
					VolumeSource: corev1.VolumeSource{
						HostPath: &corev1.HostPathVolumeSource{
							Path: "/usr/share/containers/oci/hooks.d/",
							Type: &hostPathDirectoryVolumeType,
						},
					},
				},
				{
					Name: "oci-hooks-install-path",
					VolumeSource: corev1.VolumeSource{
						HostPath: &corev1.HostPathVolumeSource{
							Path: "/opt/tetragon",
							Type: &hostPathDirectoryOrCreateVolumeType,
						},
					},
				},
				{
					Name: "extra-volume1",
					VolumeSource: corev1.VolumeSource{
						HostPath: &corev1.HostPathVolumeSource{
							Path: "/extra/test1",
							Type: &hostPathDirectoryOrCreateVolumeType,
						},
					},
				},
				{
					Name: "extra-volume2",
					VolumeSource: corev1.VolumeSource{
						HostPath: &corev1.HostPathVolumeSource{
							Path: "/extra/test2",
							Type: &hostPathDirectoryOrCreateVolumeType,
						},
					},
				},
				{
					Name: "host-volume1",
					VolumeSource: corev1.VolumeSource{
						HostPath: &corev1.HostPathVolumeSource{
							Path: "/host/test1",
						},
					},
				},
				{
					Name: "host-volume2",
					VolumeSource: corev1.VolumeSource{
						HostPath: &corev1.HostPathVolumeSource{
							Path: "/host/test2",
						},
					},
				},
				{
					Name: "metadata-files",
					VolumeSource: corev1.VolumeSource{
						EmptyDir: &corev1.EmptyDirVolumeSource{},
					},
				},
			},
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			cfgMap := make(map[string]any)
			require.NoError(t, yaml.Unmarshal([]byte(tt.yamlString), &cfgMap))
			splunkCfgMap := make(map[string]any)
			require.NoError(t, yaml.Unmarshal([]byte(tt.splunkString), &splunkCfgMap))
			// function to test
			actual := volumes(logr.Log, cfgMap, splunkCfgMap)

			require.Equal(t, tt.expected, actual)
		})
	}
}

func TestVolumeMountsFromConfigMap(t *testing.T) {
	key := "test"
	testCases := []struct {
		yamlString string
		expected   []corev1.VolumeMount
	}{
		{
			yamlString: "",
			expected:   []corev1.VolumeMount{},
		},
		{
			yamlString: `test: |
  - name: volume1
    mountPath: /mount1
  - name: volume2
    mountPath: /mount2`,
			expected: []corev1.VolumeMount{
				{Name: "volume1", MountPath: "/mount1"},
				{Name: "volume2", MountPath: "/mount2"},
			},
		},
	}

	for _, tt := range testCases {
		cfgMap := make(map[string]any)
		require.NoError(t, yaml.Unmarshal([]byte(tt.yamlString), &cfgMap))
		// function to test
		actual := volumeMountsFromConfigMap(logr.Log, cfgMap, key)

		require.Equal(t, tt.expected, actual)
	}
}

func TestVolumesFromConfigMap(t *testing.T) {
	key := "test"
	hostPathDirectoryOrCreateVolumeType := corev1.HostPathDirectoryOrCreate
	testCases := []struct {
		yamlString string
		expected   []corev1.Volume
	}{
		{
			yamlString: "",
			expected:   []corev1.Volume{},
		},
		{
			yamlString: `test: |
  - name: volume1
    hostPath:
      path: /path1
      type: DirectoryOrCreate
  - name: volume2
    hostPath:
      path: /path2
      type: DirectoryOrCreate`,
			expected: []corev1.Volume{
				{
					Name: "volume1",
					VolumeSource: corev1.VolumeSource{
						HostPath: &corev1.HostPathVolumeSource{
							Path: "/path1",
							Type: &hostPathDirectoryOrCreateVolumeType,
						},
					},
				},
				{
					Name: "volume2",
					VolumeSource: corev1.VolumeSource{
						HostPath: &corev1.HostPathVolumeSource{
							Path: "/path2",
							Type: &hostPathDirectoryOrCreateVolumeType,
						},
					},
				},
			},
		},
	}

	for _, tt := range testCases {
		cfgMap := make(map[string]any)
		require.NoError(t, yaml.Unmarshal([]byte(tt.yamlString), &cfgMap))
		// function to test
		actual := volumesFromConfigMap(logr.Log, cfgMap, key)

		require.Equal(t, tt.expected, actual)
	}
}

func TestConfigValueInt(t *testing.T) {
	key := "test"
	testCases := []struct {
		configMap    map[string]any
		defaultValue int
		expected     int
	}{
		{
			configMap:    map[string]any{},
			defaultValue: 1,
			expected:     1,
		},
		{
			configMap: map[string]any{
				key: "123",
			},
			defaultValue: 1,
			expected:     123,
		},
		{
			configMap: map[string]any{
				key: "abc",
			},
			defaultValue: 1,
			expected:     1,
		},
	}

	for _, tt := range testCases {
		// function to test
		actual := configValueInt(logr.Log, tt.configMap, key, 32, tt.defaultValue)

		require.Equal(t, tt.expected, actual)
	}
}

func TestRTDaemonSet(t *testing.T) {
	hostPathDirectoryOrCreateVolumeType := corev1.HostPathDirectoryOrCreate
	boolFalse := false

	testCases := []struct {
		name      string
		namespace string
		dsName    string
		cm        *corev1.ConfigMap
		expected  *appv1.DaemonSet
	}{
		{
			name:      "default values",
			namespace: "kube-system",
			dsName:    RTDaemonSetName,
			cm:        DefaultOperatorConfigMap(logr.Log, "kube-system", "tetragon"),
			expected:  nil,
		},
		{
			name:      "oci hooks enabled",
			namespace: "kube-system",
			dsName:    RTDaemonSetName,
			cm: &corev1.ConfigMap{
				Data: map[string]string{
					OperatorConfigMapAgentDaemonSetKey: `
nodeSelector:
  kubernetes.io/os: linux
tolerations: |
  - operator: Exists
`,
					OperatorConfigMapRTHooksDaemonSetKey: `
enabled: true
interface: oci-hooks
ociHooksPath: "/usr/share/containers/oci/hooks.d"
installDir: "/opt/tetragon"
podSecurityContext: |
    privileged: true
`,
				},
			},
			expected: &appv1.DaemonSet{
				TypeMeta: v1.TypeMeta{
					Kind:       "DaemonSet",
					APIVersion: "apps/v1",
				},
				ObjectMeta: v1.ObjectMeta{
					Name:      RTDaemonSetName,
					Namespace: "kube-system",
					Labels: map[string]string{
						"app.kubernetes.io/instance":   RTDaemonSetName,
						"app.kubernetes.io/name":       RTDaemonSetName,
						"app.kubernetes.io/managed-by": "tetragon-operator",
					},
					Annotations: map[string]string{},
				},
				Spec: appv1.DaemonSetSpec{
					Selector: &v1.LabelSelector{
						MatchLabels: map[string]string{
							"app.kubernetes.io/instance":   RTDaemonSetName,
							"app.kubernetes.io/name":       RTDaemonSetName,
							"app.kubernetes.io/managed-by": "tetragon-operator",
						},
					},
					Template: corev1.PodTemplateSpec{
						ObjectMeta: v1.ObjectMeta{
							Labels: map[string]string{
								"app.kubernetes.io/instance":   RTDaemonSetName,
								"app.kubernetes.io/name":       RTDaemonSetName,
								"app.kubernetes.io/managed-by": "tetragon-operator",
							},
							Annotations: map[string]string{},
						},
						Spec: corev1.PodSpec{
							ImagePullSecrets: []corev1.LocalObjectReference{},
							SecurityContext:  &corev1.PodSecurityContext{},
							NodeSelector: map[string]string{
								"kubernetes.io/os": "linux",
							},
							Affinity: &corev1.Affinity{},
							Tolerations: []corev1.Toleration{
								{Operator: "Exists"},
							},
							AutomountServiceAccountToken: &boolFalse,
							Containers: []corev1.Container{
								{
									Name: "tetragon-rthooks",
									Command: []string{
										"tetragon-oci-hook-setup",
										"install",
										"--interface=oci-hooks",
										"--local-install-dir=/hostInstall",
										"--host-install-dir",
										"/opt/tetragon",
										"--oci-hooks.local-dir=/hostHooks",
										"--daemonize",
										"hook-args",
										"--grpc-address=",
										"--fail-allow-namespaces",
										"kube-system",
									},
									TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
									ImagePullPolicy:          corev1.PullIfNotPresent,
									SecurityContext:          &corev1.SecurityContext{},
									VolumeMounts: []corev1.VolumeMount{
										{
											Name:      "oci-hooks-install-path",
											MountPath: "/hostInstall",
										},
										{
											Name:      "oci-hooks-path",
											MountPath: "/hostHooks",
										},
									},
								},
							},
							Volumes: []corev1.Volume{
								{
									Name: "oci-hooks-install-path",
									VolumeSource: corev1.VolumeSource{
										HostPath: &corev1.HostPathVolumeSource{
											Path: "/opt/tetragon",
											Type: &hostPathDirectoryOrCreateVolumeType,
										},
									},
								},
								{
									Name: "oci-hooks-path",
									VolumeSource: corev1.VolumeSource{
										HostPath: &corev1.HostPathVolumeSource{
											Path: "/usr/share/containers/oci/hooks.d",
											Type: new(corev1.HostPathDirectory),
										},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name:      "custom values",
			namespace: "kube-system",
			dsName:    RTDaemonSetName,
			cm: &corev1.ConfigMap{
				Data: map[string]string{
					OperatorConfigMapAgentDaemonSetKey: `
imagePullSecrets: |
  - name: test-secret1
  - name: test-secret2
nodeSelector:
  test-selector-key1: test-selector-value1
  test-selector-key2: test-selector-value2
  kubernetes.io/os: linux
affinity: |
  podAffinity:
    requiredDuringSchedulingIgnoredDuringExecution:
      - namespaces:
          - test-affinity-ns1
          - test-affinity-ns2
tolerations: |
  - key: test-key1
    value: test-value1
  - key: test-key2
    value: test-value2
`,
					OperatorConfigMapRTHooksDaemonSetKey: `
enabled: true
interface: nri-hook
nriHookSocket: "/var/run/nri/nri-custom.sock"
installDir: "/opt/custom-tetragon"
securityContext: |
  privileged: true
labelsOverride:
  test-label1: test-value1
  test-label2: test-value2
annotations:
  test-annotation1: test-value1
  test-annotation2: test-value2
podAnnotations:
  pod-annotation1: pod-value1
  pod-annotation2: pod-value2
priorityClassName: system-node-critical
podSecurityContext: |
  runAsUser: 123
failAllowNamespaces: fail-allow-ns
`,
				},
			},
			expected: &appv1.DaemonSet{
				TypeMeta: v1.TypeMeta{
					Kind:       "DaemonSet",
					APIVersion: "apps/v1",
				},
				ObjectMeta: v1.ObjectMeta{
					Name:      RTDaemonSetName,
					Namespace: "kube-system",
					Labels: map[string]string{
						"test-label1": "test-value1",
						"test-label2": "test-value2",
					},
					Annotations: map[string]string{
						"test-annotation1": "test-value1",
						"test-annotation2": "test-value2",
					},
				},
				Spec: appv1.DaemonSetSpec{
					Selector: &v1.LabelSelector{
						MatchLabels: map[string]string{
							"app.kubernetes.io/instance":   RTDaemonSetName,
							"app.kubernetes.io/name":       RTDaemonSetName,
							"app.kubernetes.io/managed-by": "tetragon-operator",
						},
					},
					Template: corev1.PodTemplateSpec{
						ObjectMeta: v1.ObjectMeta{
							Labels: map[string]string{
								"app.kubernetes.io/instance":   RTDaemonSetName,
								"app.kubernetes.io/name":       RTDaemonSetName,
								"app.kubernetes.io/managed-by": "tetragon-operator",
							},
							Annotations: map[string]string{
								"pod-annotation1": "pod-value1",
								"pod-annotation2": "pod-value2",
							},
						},
						Spec: corev1.PodSpec{
							PriorityClassName: "system-node-critical",
							ImagePullSecrets: []corev1.LocalObjectReference{
								{Name: "test-secret1"},
								{Name: "test-secret2"},
							},
							SecurityContext: &corev1.PodSecurityContext{RunAsUser: new(int64(123))},
							NodeSelector: map[string]string{
								"test-selector-key1": "test-selector-value1",
								"test-selector-key2": "test-selector-value2",
								"kubernetes.io/os":   "linux",
							},
							Affinity: &corev1.Affinity{
								PodAffinity: &corev1.PodAffinity{
									RequiredDuringSchedulingIgnoredDuringExecution: []corev1.PodAffinityTerm{
										{
											Namespaces: []string{"test-affinity-ns1", "test-affinity-ns2"},
										},
									},
								},
							},
							Tolerations: []corev1.Toleration{
								{Key: "test-key1", Value: "test-value1"},
								{Key: "test-key2", Value: "test-value2"},
							},
							AutomountServiceAccountToken: &boolFalse,
							Containers: []corev1.Container{
								{
									Name: "tetragon-rthooks",
									Command: []string{
										"tetragon-oci-hook-setup",
										"install",
										"--interface=nri-hook",
										"--local-install-dir=/hostInstall",
										"--host-install-dir",
										"/opt/custom-tetragon",
										"--oci-hooks.local-dir=/hostHooks",
										"--daemonize",
										"hook-args",
										"--grpc-address=",
										"--fail-allow-namespaces",
										"kube-system,fail-allow-ns",
									},
									TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
									ImagePullPolicy:          corev1.PullIfNotPresent,
									SecurityContext: &corev1.SecurityContext{
										Privileged: new(true),
									},
									VolumeMounts: []corev1.VolumeMount{
										{
											Name:      "oci-hooks-install-path",
											MountPath: "/hostInstall",
										},
										{
											Name:      "nri-socket-path",
											MountPath: "/var/run/nri/nri-custom.sock",
										},
									},
								},
							},
							Volumes: []corev1.Volume{
								{
									Name: "oci-hooks-install-path",
									VolumeSource: corev1.VolumeSource{
										HostPath: &corev1.HostPathVolumeSource{
											Path: "/opt/custom-tetragon",
											Type: &hostPathDirectoryOrCreateVolumeType,
										},
									},
								},
								{
									Name: "nri-socket-path",
									VolumeSource: corev1.VolumeSource{
										HostPath: &corev1.HostPathVolumeSource{
											Path: "/var/run/nri/nri-custom.sock",
											Type: new(corev1.HostPathSocket),
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			// function to test
			actual, err := RTDaemonSet(logr.Log, tt.namespace, tt.dsName, tt.cm)
			require.NoError(t, err)
			require.Equal(t, tt.expected, actual)
		})
	}
}

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

func TestAggregatorDeployment(t *testing.T) {
	replicas := int32(1)
	automountServiceAccount := false
	runAsUser := int64(123)
	allowPriviledgeEscalation := true
	terminationGracePeriodSec := int64(10)

	testCases := []struct {
		name           string
		namespace      string
		deploymentName string
		cm             *corev1.ConfigMap
		expected       *appv1.Deployment
	}{
		{
			name:           "default values [aggregator disabled]",
			namespace:      "kube-system",
			deploymentName: "tetragon-aggregator",
			cm:             &corev1.ConfigMap{},
			expected:       nil,
		},
		{
			name:           "default values [aggregator enabled]",
			namespace:      "kube-system",
			deploymentName: "tetragon-aggregator",
			cm: &corev1.ConfigMap{
				Data: map[string]string{
					OperatorConfigMapAggregatorKey: "enabled: true",
				},
			},
			expected: &appv1.Deployment{
				TypeMeta: v1.TypeMeta{
					Kind:       "Deployment",
					APIVersion: "apps/v1",
				},
				ObjectMeta: v1.ObjectMeta{
					Name:      "tetragon-aggregator",
					Namespace: "kube-system",
					Labels: map[string]string{
						"app.kubernetes.io/instance":   "tetragon-aggregator",
						"app.kubernetes.io/name":       "tetragon-aggregator",
						"app.kubernetes.io/managed-by": "tetragon-operator",
					},
					Annotations: map[string]string{},
				},
				Spec: appv1.DeploymentSpec{
					Selector: &v1.LabelSelector{
						MatchLabels: map[string]string{
							"app.kubernetes.io/instance":   "tetragon-aggregator",
							"app.kubernetes.io/name":       "tetragon-aggregator",
							"app.kubernetes.io/managed-by": "tetragon-operator",
						},
					},
					Replicas: &replicas,
					Template: corev1.PodTemplateSpec{
						ObjectMeta: v1.ObjectMeta{
							Labels: map[string]string{
								"app.kubernetes.io/instance":   "tetragon-aggregator",
								"app.kubernetes.io/name":       "tetragon-aggregator",
								"app.kubernetes.io/managed-by": "tetragon-operator",
							},
							Annotations: map[string]string{},
						},
						Spec: corev1.PodSpec{
							AutomountServiceAccountToken:  &automountServiceAccount,
							ImagePullSecrets:              []corev1.LocalObjectReference{},
							NodeSelector:                  map[string]string{},
							TerminationGracePeriodSeconds: &terminationGracePeriodSec,
							HostNetwork:                   false,
							SecurityContext:               &corev1.PodSecurityContext{},
							Affinity:                      &corev1.Affinity{},
							Tolerations:                   []corev1.Toleration{},
							Volumes:                       []corev1.Volume{},
							Resources:                     &corev1.ResourceRequirements{},
							Containers: []corev1.Container{
								{
									Name:            "tetragon-aggregator",
									Command:         []string{"/usr/bin/tetragon-aggregator", "aggregate"},
									ImagePullPolicy: corev1.PullIfNotPresent,
									VolumeMounts:    []corev1.VolumeMount{},
									SecurityContext: &corev1.SecurityContext{},
								},
							},
						},
					},
				},
			},
		},
		{
			name:           "custom values [aggregator enabled]",
			namespace:      "kube-system",
			deploymentName: "tetragon-aggregator",
			cm: &corev1.ConfigMap{
				Data: map[string]string{
					OperatorConfigMapAggregatorKey: `enabled: true

# Annotations for the Tetragon Aggregator Deployment.
annotations:
  key1: value1
# Annotations for the Tetragon Aggregator Deployment Pods.
podAnnotations:
  key10: value10
# Extra labels to be added on the Tetragon Aggregator Deployment.
extraLabels:
  label1: value1
# Extra labels to be added on the Tetragon Aggregator Deployment Pods.
extraPodLabels:
  label10: value10
# priorityClassName for the Tetragon Aggregator Deployment Pods.
priorityClassName: "test"
# securityContext for the Tetragon Aggregator Deployment Pods.
securityContext: |
  allowPrivilegeEscalation: true
  capabilities:
    drop:
      - "ALL"
# securityContext for the Tetragon Aggregator Deployment Pod container.
podSecurityContext: |
  runAsUser: 123
# resources for the Tetragon Operator Deployment Pod container.
resources: |
  requests:
    cpu: 2500m
    memory: 2536Mi
strategy: |
  type: RollingUpdate
# Steer the Tetragon Aggregator Deployment Pod placement via nodeSelector, tolerations and affinity rules.
nodeSelector:
  test-selector-key1: test-selector-value1
tolerations: |
  - key: test-key1
    value: test-value1
affinity: |
  podAffinity:
    requiredDuringSchedulingIgnoredDuringExecution:
      - namespaces:
          - test-affinity-ns1
          - test-affinity-ns2
# tetragon-aggregator image.
imagePullPolicy: IfNotPresent
imagePullSecrets: |
  - name: test-secret1
# Extra volumes for the Tetragon Aggregator Deployment.
extraVolumes: |
  - name: test-extra-volume1
    hostPath:
      path: test-extra-path1
extraVolumeMounts: |
  - name: test-extra-host-volume1
    mountPath: test-extra-host-path1
`,
				},
			},
			expected: &appv1.Deployment{
				TypeMeta: v1.TypeMeta{
					Kind:       "Deployment",
					APIVersion: "apps/v1",
				},
				ObjectMeta: v1.ObjectMeta{
					Name:      "tetragon-aggregator",
					Namespace: "kube-system",
					Labels: map[string]string{
						"app.kubernetes.io/instance":   "tetragon-aggregator",
						"app.kubernetes.io/name":       "tetragon-aggregator",
						"app.kubernetes.io/managed-by": "tetragon-operator",
						"label1":                       "value1",
					},
					Annotations: map[string]string{
						"key1": "value1",
					},
				},
				Spec: appv1.DeploymentSpec{
					Selector: &v1.LabelSelector{
						MatchLabels: map[string]string{
							"app.kubernetes.io/instance":   "tetragon-aggregator",
							"app.kubernetes.io/name":       "tetragon-aggregator",
							"app.kubernetes.io/managed-by": "tetragon-operator",
						},
					},
					Replicas: &replicas,
					Template: corev1.PodTemplateSpec{
						ObjectMeta: v1.ObjectMeta{
							Labels: map[string]string{
								"app.kubernetes.io/instance":   "tetragon-aggregator",
								"app.kubernetes.io/name":       "tetragon-aggregator",
								"app.kubernetes.io/managed-by": "tetragon-operator",
								"label10":                      "value10",
							},
							Annotations: map[string]string{
								"key10": "value10",
							},
						},
						Spec: corev1.PodSpec{
							AutomountServiceAccountToken: &automountServiceAccount,
							PriorityClassName:            "test",
							ImagePullSecrets: []corev1.LocalObjectReference{
								{Name: "test-secret1"},
							},
							NodeSelector: map[string]string{
								"test-selector-key1": "test-selector-value1",
							},
							TerminationGracePeriodSeconds: &terminationGracePeriodSec,
							HostNetwork:                   false,
							SecurityContext: &corev1.PodSecurityContext{
								RunAsUser: &runAsUser,
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
								{
									Key:   "test-key1",
									Value: "test-value1",
								},
							},
							Volumes: []corev1.Volume{
								{
									Name: "test-extra-volume1",
									VolumeSource: corev1.VolumeSource{
										HostPath: &corev1.HostPathVolumeSource{
											Path: "test-extra-path1",
										},
									},
								},
							},
							Resources: &corev1.ResourceRequirements{
								Requests: corev1.ResourceList{
									"cpu":    resource.MustParse("2500m"),
									"memory": resource.MustParse("2536Mi"),
								},
							},
							Containers: []corev1.Container{
								{
									Name:            "tetragon-aggregator",
									Command:         []string{"/usr/bin/tetragon-aggregator", "aggregate"},
									ImagePullPolicy: corev1.PullIfNotPresent,
									VolumeMounts: []corev1.VolumeMount{
										{
											Name:      "test-extra-host-volume1",
											MountPath: "test-extra-host-path1",
										},
									},
									SecurityContext: &corev1.SecurityContext{
										AllowPrivilegeEscalation: &allowPriviledgeEscalation,
										Capabilities: &corev1.Capabilities{
											Drop: []corev1.Capability{
												"ALL",
											},
										},
									},
								},
							},
						},
					},
					Strategy: appv1.DeploymentStrategy{
						Type: appv1.RollingUpdateDeploymentStrategyType,
					},
				},
			},
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			// get the config
			config := make(map[string]interface{})
			err := yaml.Unmarshal([]byte(tt.cm.Data[OperatorConfigMapAggregatorKey]), &config)
			require.NoError(t, err)

			// function to test
			actual, err := AggregatorDeployment(logr.Log, tt.namespace, tt.deploymentName, config)
			require.NoError(t, err)
			require.Equal(t, tt.expected, actual)
		})
	}
}

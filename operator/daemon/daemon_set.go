package daemon

import (
	"fmt"

	appv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	k8sv1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/isovalent/hubble-fgs/operator/options"
)

const (
	dsName                 = "tetragon"
	dsManagedByLabel       = "app.kubernetes.io/managed-by"
	dsManagedByValue       = "tetragon-operator"
	dsUpdateMaxUnavailable = int32(1)
	dsUpdateMaxSurge       = int32(0)
)

func daemonSet() *appv1.DaemonSet {
	var (
		dirHostPath                 = corev1.HostPathDirectory
		dirOrCreateHostPath         = corev1.HostPathDirectoryOrCreate
		dsVolumeDefaultMode         = int32(420)
		dsRevisionHistoryLimit      = int32(10)
		dsTerminationGracePeriodSec = int64(1)
	)
	ds := &appv1.DaemonSet{
		TypeMeta: k8sv1.TypeMeta{
			Kind:       "DaemonSet",
			APIVersion: "apps/v1",
		},
		ObjectMeta: k8sv1.ObjectMeta{
			Name:      dsName,
			Namespace: options.Config.DaemonSetNamespace,
			//TODO: add annotation and make them configurable
			Labels: map[string]string{ //TODO: make configurable
				"app.kubernetes.io/instance": dsName,
				"app.kubernetes.io/name":     dsName,
				dsManagedByLabel:             dsManagedByValue,
			},
		},
		Spec: appv1.DaemonSetSpec{
			Selector: &k8sv1.LabelSelector{ //TODO: make configurable
				MatchLabels: map[string]string{
					"app.kubernetes.io/instance": dsName,
					"app.kubernetes.io/name":     dsName,
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: k8sv1.ObjectMeta{
					Labels: map[string]string{ //TODO: make configurable
						"app.kubernetes.io/instance": dsName,
						"app.kubernetes.io/name":     dsName,
						dsManagedByLabel:             dsManagedByValue,
					},
				},
				Spec: corev1.PodSpec{
					//TODO: add init container with condition
					Containers: daemonSetContainers(),
					Volumes: []corev1.Volume{
						{
							Name: "cilium-run",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/var/run/cilium",
									Type: &dirOrCreateHostPath,
								},
							},
						},
						{
							Name: "export-logs",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/var/run/cilium/tetragon",
									Type: &dirOrCreateHostPath,
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
									Type: &dirOrCreateHostPath,
								},
							},
						},
						{
							Name: "host-proc",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/procHost",
									Type: &dirHostPath,
								},
							},
						},
					},
					RestartPolicy:                 corev1.RestartPolicyAlways,
					TerminationGracePeriodSeconds: &dsTerminationGracePeriodSec,
					DNSPolicy:                     options.Config.DaemonSetDNSPolicy,
					ServiceAccountName:            options.Config.DaemonSetServiceAccountName,
					HostNetwork:                   options.Config.DaemonSetHostNetwork,
					SchedulerName:                 "default-scheduler",
					SecurityContext:               &corev1.PodSecurityContext{},
					Tolerations: []corev1.Toleration{
						{
							Operator: "Exists",
						},
					},
					// This is required to avoid diff with actual K8S object
					DeprecatedServiceAccount: options.Config.DaemonSetServiceAccountName,
				},
			},
			UpdateStrategy: appv1.DaemonSetUpdateStrategy{
				Type: appv1.RollingUpdateDaemonSetStrategyType,
				RollingUpdate: &appv1.RollingUpdateDaemonSet{
					MaxUnavailable: &intstr.IntOrString{
						Type:   intstr.Int,
						IntVal: dsUpdateMaxUnavailable,
					},
					MaxSurge: &intstr.IntOrString{
						Type:   intstr.Int,
						IntVal: dsUpdateMaxSurge,
					},
				},
			},
			RevisionHistoryLimit: &dsRevisionHistoryLimit,
		},
	}
	return ds
}

func daemonSetContainers() []corev1.Container {
	privilegedContext := true
	bidirectionalMount := corev1.MountPropagationBidirectional
	containers := make([]corev1.Container, 0)

	if options.Config.ExportContainerMode == "stdout" {
		args := make([]string, 0, len(options.Config.ExportContainerFilenames))
		for _, f := range options.Config.ExportContainerFilenames {
			args = append(args, fmt.Sprintf("%s/%s", options.Config.DaemonSetExportDirectory, f))
		}
		containers = append(containers, corev1.Container{
			Name:    "export-stdout",
			Image:   options.Config.ExportContainerImage,
			Command: []string{"hubble-export-stdout"},
			Args:    args,
			Env:     []corev1.EnvVar{}, //TODO: make configurable
			VolumeMounts: []corev1.VolumeMount{
				{
					Name:      "export-logs",
					MountPath: options.Config.DaemonSetExportDirectory,
				},
			},
			Resources:                corev1.ResourceRequirements{}, //TODO: make configurable
			SecurityContext:          &corev1.SecurityContext{},     //TODO: make configurable
			TerminationMessagePath:   "/dev/termination-log",
			TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
			ImagePullPolicy:          options.Config.DaemonSetImagePullPolicy,
		})
	}

	tetragon := corev1.Container{
		Name:  "tetragon",
		Image: options.Config.TetragonContainerImage,
		Args: append(
			[]string{"--config-dir=/etc/tetragon/tetragon.conf.d/"},
			options.Config.TetragonContainerArgsOverride...,
		),
		EnvFrom: nil,
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
		TerminationMessagePath:   "/dev/termination-log",
		TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
		ImagePullPolicy:          options.Config.DaemonSetImagePullPolicy,
		SecurityContext: &corev1.SecurityContext{ //TODO: make configurable
			Privileged: &privilegedContext,
		},
	}
	if options.Config.TetragonContainerGRPCEnabled {
		tetragon.LivenessProbe = &corev1.Probe{
			ProbeHandler: corev1.ProbeHandler{
				Exec: &corev1.ExecAction{
					Command: []string{
						"tetra",
						"status",
						"--server-address",
						options.Config.TetragonContainerGRPCAddr,
						"--retries",
						"5",
					},
				},
			},
			TimeoutSeconds:   int32(60),
			PeriodSeconds:    int32(10),
			SuccessThreshold: int32(1),
			FailureThreshold: int32(3),
		}
	}

	return append(containers, tetragon)
}

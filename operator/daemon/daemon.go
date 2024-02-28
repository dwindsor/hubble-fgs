// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package daemon

import (
	"context"
	"net/http"

	v1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	k8sv1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"

	"github.com/isovalent/hubble-fgs/operator/options"
)

func isDaemonSetExists(ctx context.Context, client *kubernetes.Clientset) (bool, error) {
	cfg := options.Config
	_, err := client.AppsV1().DaemonSets(cfg.Namespace).Get(ctx, cfg.DaemonSetName, k8sv1.GetOptions{})
	if err != nil {
		if err, ok := err.(*k8serrors.StatusError); ok && err.Status().Code == http.StatusNotFound {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

const managedBy = "tetragon-operator"

func createDaemonSet(ctx context.Context, client *kubernetes.Clientset) error {
	var (
		namespace           = options.Config.Namespace
		daemonSetName       = options.Config.DaemonSetName
		bidirectionalMount  = corev1.MountPropagationBidirectional
		dirHostPath         = corev1.HostPathDirectory
		dirOrCreateHostPath = corev1.HostPathDirectoryOrCreate
		privilegedContext   = true
		volumeDefaultMode   = int32(420)
	)
	ds := &v1.DaemonSet{
		TypeMeta: k8sv1.TypeMeta{
			Kind:       "DaemonSet",
			APIVersion: "apps/v1",
		},
		ObjectMeta: k8sv1.ObjectMeta{
			Name:      daemonSetName,
			Namespace: namespace,
			Labels: map[string]string{
				"app.kubernetes.io/instance":   daemonSetName,
				"app.kubernetes.io/name":       daemonSetName,
				"app.kubernetes.io/managed-by": managedBy,
			},
		},
		Spec: v1.DaemonSetSpec{
			Selector: &k8sv1.LabelSelector{
				MatchLabels: map[string]string{
					"app.kubernetes.io/instance": daemonSetName,
					"app.kubernetes.io/name":     daemonSetName,
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: k8sv1.ObjectMeta{
					Labels: map[string]string{
						"app.kubernetes.io/instance":   daemonSetName,
						"app.kubernetes.io/name":       daemonSetName,
						"app.kubernetes.io/managed-by": managedBy,
					},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:    options.Config.ExportContainerName,
							Image:   options.Config.ExportContainerImage,
							Command: options.Config.ExportContainerCommand,
							Args:    options.Config.ExportContainerArgs,
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "export-logs",
									MountPath: "/var/run/cilium/tetragon",
								},
							},
							SecurityContext:          &corev1.SecurityContext{},
							TerminationMessagePath:   options.Config.ExportContainerTerminationMessagePath,
							TerminationMessagePolicy: options.Config.ExportContainerTerminationMessagePolicy,
							ImagePullPolicy:          options.Config.ExportContainerImagePullPolicy,
						},
						{
							Name:    options.Config.TetragonContainerName,
							Image:   options.Config.TetragonContainerImage,
							Args:    options.Config.TetragonContainerArgs,
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
							LivenessProbe: &corev1.Probe{
								ProbeHandler: corev1.ProbeHandler{
									Exec: &corev1.ExecAction{
										Command: options.Config.TetragonContainerLivenessProbeCommand,
									},
								},
								TimeoutSeconds:   options.Config.TetragonContainerLivenessProbeTimeoutSec,
								PeriodSeconds:    options.Config.TetragonContainerLivenessProbePeriodSec,
								SuccessThreshold: options.Config.TetragonContainerLivenessProbeSuccessThreshold,
								FailureThreshold: options.Config.TetragonContainerLivenessProbeFailureThreshold,
							},
							TerminationMessagePath:   options.Config.TetragonContainerTerminationMessagePath,
							TerminationMessagePolicy: options.Config.TetragonContainerTerminationMessagePolicy,
							ImagePullPolicy:          options.Config.TetragonContainerImagePullPolicy,
							SecurityContext: &corev1.SecurityContext{
								Privileged: &privilegedContext,
							},
						},
					},
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
									DefaultMode: &volumeDefaultMode,
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
					RestartPolicy:                 options.Config.DaemonSetRestartPolicy,
					TerminationGracePeriodSeconds: &options.Config.DaemonSetTerminationGracePeriodSeconds,
					DNSPolicy:                     options.Config.DaemonSetDNSPolicy,
					ServiceAccountName:            options.Config.DaemonSetServiceAccountName,
					HostNetwork:                   options.Config.DaemonSetHostNetwork,
					SchedulerName:                 options.Config.DaemonSetSchedulerName,
					Tolerations: []corev1.Toleration{
						{
							Operator: "Exists",
						},
					},
				},
			},
			UpdateStrategy: v1.DaemonSetUpdateStrategy{
				Type: v1.RollingUpdateDaemonSetStrategyType,
				RollingUpdate: &v1.RollingUpdateDaemonSet{
					MaxUnavailable: &intstr.IntOrString{
						Type:   intstr.Int,
						IntVal: options.Config.DaemonSetUpdateMaxUnavailable,
					},
					MaxSurge: &intstr.IntOrString{
						Type:   intstr.Int,
						IntVal: options.Config.DaemonSetUpdateMaxSurge,
					},
				},
			},
		},
	}
	_, err := client.AppsV1().DaemonSets(namespace).Create(ctx, ds, k8sv1.CreateOptions{})
	return err
}

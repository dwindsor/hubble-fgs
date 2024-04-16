package agent

import (
	"errors"
	"fmt"
	"os"

	"github.com/go-logr/logr"
	appv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	k8sv1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/yaml"
)

// daemonSet instantiates a Tetragon DaemonSet configuration.
func daemonSet(log logr.Logger, namespace string, name string, cm *corev1.ConfigMap) (*appv1.DaemonSet, error) {
	dsTerminationGracePeriodSec := int64(1)
	dsRevisionHistoryLimit := int32(10)

	configYaml := cm.Data[OperatorConfigMapAgentDaemonSetKey]
	cmFields := make(map[string]interface{})
	err := yaml.Unmarshal([]byte(configYaml), &cmFields)
	if err != nil {
		log.WithValues("value", configYaml).Error(err, "could not unmarshal the DaemonSet configuration")
		return nil, err
	}

	securityContext := corev1.PodSecurityContext{}
	securityContextValue := configValue(log, cmFields, "podSecurityContext", "")
	if securityContextValue != "" {
		if err := yaml.Unmarshal([]byte(securityContextValue), &securityContext); err != nil {
			log.WithValues("value", securityContextValue).Error(err, "could not unmarshal the pod security context, default value used instead")
		}
	}

	ds := &appv1.DaemonSet{
		TypeMeta: k8sv1.TypeMeta{
			Kind:       "DaemonSet",
			APIVersion: "apps/v1",
		},
		ObjectMeta: k8sv1.ObjectMeta{
			Name:        name,
			Namespace:   namespace,
			Annotations: configMapOfString(log, cmFields, "annotations"),
			Labels:      aggregatedLabels(log, cm, "labels"),
		},
		Spec: appv1.DaemonSetSpec{
			Selector: &k8sv1.LabelSelector{
				MatchLabels: labelsForManaged(),
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: k8sv1.ObjectMeta{
					Labels: labelsForManaged(),
				},
				Spec: corev1.PodSpec{
					InitContainers:                daemonSetInitContainers(log, cmFields),
					Containers:                    daemonSetContainers(log, cmFields),
					Volumes:                       volumes(log, cmFields),
					RestartPolicy:                 corev1.RestartPolicyAlways,
					TerminationGracePeriodSeconds: &dsTerminationGracePeriodSec,
					DNSPolicy:                     dnsPolicy(log, cmFields),
					ServiceAccountName:            configValue(log, cmFields, "serviceAccountName", "tetragon"),
					HostNetwork:                   configValue(log, cmFields, "hostNetwork", true),
					SchedulerName:                 "default-scheduler",
					NodeSelector:                  nodeSelector(log, cmFields, "nodeSelector"),
					SecurityContext:               &securityContext,
					Tolerations: []corev1.Toleration{
						{
							Operator: "Exists",
						},
					},
					// This is required to avoid diff with actual K8S object
					DeprecatedServiceAccount: configValue(log, cmFields, "serviceAccountName", "tetragon"),
				},
			},
			UpdateStrategy: appv1.DaemonSetUpdateStrategy{
				Type: appv1.RollingUpdateDaemonSetStrategyType,
				RollingUpdate: &appv1.RollingUpdateDaemonSet{
					MaxUnavailable: &intstr.IntOrString{
						Type:   intstr.Int,
						IntVal: 1,
					},
					MaxSurge: &intstr.IntOrString{
						Type:   intstr.Int,
						IntVal: 0,
					},
				},
			},
			RevisionHistoryLimit: &dsRevisionHistoryLimit,
		},
	}
	return ds, nil
}

func daemonSetInitContainers(log logr.Logger, cmFields map[string]any) []corev1.Container {
	if !configValue(log, cmFields, "ociHookSetupEnabled", false) {
		return []corev1.Container{}
	}

	privileged := true
	securityContext := corev1.SecurityContext{Privileged: &privileged}
	securityContextValue := configValue(log, cmFields, "ociHookSetupSecurityContext", "")
	if securityContextValue != "" {
		if err := yaml.Unmarshal([]byte(securityContextValue), &securityContext); err != nil {
			log.WithValues("value", securityContextValue).Error(err, "could not unmarshal the security context, default value used instead")
		}
	}

	extraMounts := make([]corev1.VolumeMount, 0)
	for _, m := range configArray(log, cmFields, "ociHookSetupExtraVolumeMounts", []string{}) {
		v := corev1.VolumeMount{}
		if err := yaml.Unmarshal([]byte(m), &v); err != nil {
			log.WithValues("value", m).Error(err, "could not unmarshal the extra volume mount, mount not applied")
			continue
		}
		extraMounts = append(extraMounts, v)
	}

	resources := corev1.ResourceRequirements{}
	resourcesValue := configValue(log, cmFields, "ociHookSetupResources", "")
	if resourcesValue != "" {
		if err := yaml.Unmarshal([]byte(resourcesValue), &resources); err != nil {
			log.WithValues("value", resourcesValue).Error(err, "could not unmarshal the resources, default value used instead")
		}
	}

	return []corev1.Container{
		{
			Name:                     "oci-hook-setup",
			SecurityContext:          &securityContext,
			Image:                    os.Getenv("TETRAGON_IMAGE"),
			TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
			Command: []string{
				"tetragon-oci-hook-setup",
				"install",
				"--interface",
				configValue(log, cmFields, "ociHookSetupInterface", "oci-hooks"),
				"--local-install-dir=/hostInstall",
				"--host-install-dir",
				configValue(log, cmFields, "ociHookSetupInstallDir", "/opt/tetragon"),
				"--oci-hooks.local-dir=/hostHooks",
			},
			VolumeMounts: append(
				extraMounts,
				corev1.VolumeMount{
					Name:      "oci-hooks-path",
					MountPath: "/hostHooks",
				},
				corev1.VolumeMount{
					Name:      "oci-hooks-install-path",
					MountPath: "/hostInstall",
				},
			),
			Resources: resources,
		},
	}
}

func daemonSetContainers(log logr.Logger, cmFields map[string]any) []corev1.Container {
	bidirectionalMount := corev1.MountPropagationBidirectional
	containers := make([]corev1.Container, 0)

	if cmFields["exportMode"] == "stdout" {
		env := make([]corev1.EnvVar, 0)
		envValue := configValue(log, cmFields, "exportExtraEnv", "")
		if envValue != "" {
			if err := yaml.Unmarshal([]byte(envValue), &env); err != nil {
				log.WithValues("value", envValue).Error(err, "could not unmarshal the export container extraEnv, default value used instead")
			}
		}

		resources := corev1.ResourceRequirements{}
		resourcesValue := configValue(log, cmFields, "exportResources", "")
		if resourcesValue != "" {
			if err := yaml.Unmarshal([]byte(resourcesValue), &resources); err != nil {
				log.WithValues("value", resourcesValue).Error(err, "could not unmarshal the export container resources, default value used instead")
			}
		}

		securityContext := corev1.SecurityContext{}
		securityContextValue := configValue(log, cmFields, "exportSecurityContext", "")
		if securityContextValue != "" {
			if err := yaml.Unmarshal([]byte(securityContextValue), &securityContext); err != nil {
				log.WithValues("value", securityContextValue).Error(err, "could not unmarshal the export container security context, default value used instead")
			}
		}

		exportFilenames := configArray(log, cmFields, "exportFilenames", []string{"tetragon.log"})
		args := make([]string, 0, len(exportFilenames))
		for _, f := range exportFilenames {
			args = append(args, fmt.Sprintf("%s/%s", configValue(log, cmFields, "exportDirectory", "/var/run/cilium/tetragon"), f))
		}
		containers = append(containers, corev1.Container{
			Name:    "export-stdout",
			Image:   os.Getenv("EXPORT_IMAGE"),
			Command: []string{"hubble-export-stdout"},
			Args:    args,
			Env:     env,
			VolumeMounts: []corev1.VolumeMount{
				{
					Name:      "export-logs",
					MountPath: configValue(log, cmFields, "exportDirectory", "/var/run/cilium/tetragon"),
				},
			},
			Resources:                resources,
			SecurityContext:          &securityContext,
			TerminationMessagePath:   "/dev/termination-log",
			TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
			ImagePullPolicy:          corev1.PullPolicy(configValue(log, cmFields, "imagePullPolicy", "IfNotPresent")),
		})
	}

	resources := corev1.ResourceRequirements{}
	resourcesValue := configValue(log, cmFields, "tetragonResources", "")
	if resourcesValue != "" {
		if err := yaml.Unmarshal([]byte(resourcesValue), &resources); err != nil {
			log.WithValues("value", resourcesValue).Error(err, "could not unmarshal the tetragon container resources, default value used instead")
		}
	}

	privileged := true
	securityContext := corev1.SecurityContext{Privileged: &privileged}
	securityContextValue := configValue(log, cmFields, "tetragonSecurityContext", "")
	if securityContextValue != "" {
		if err := yaml.Unmarshal([]byte(securityContextValue), &securityContext); err != nil {
			log.WithValues("value", securityContextValue).Error(err, "could not unmarshal the tetragon container security context, default value used instead")
		}
	}

	volumeMounts := []corev1.VolumeMount{
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
			MountPath: configValue(log, cmFields, "exportDirectory", "/var/run/cilium/tetragon"),
		},
		{
			Name:      "host-proc",
			MountPath: "/procRoot",
		},
	}
	for _, v := range configArray(log, cmFields, "extraVolumeMounts", []string{}) {
		vm := corev1.VolumeMount{}
		if err := yaml.Unmarshal([]byte(v), &vm); err != nil {
			log.WithValues("value", v).Error(err, "could not unmarshal the extraVolumeMount, skipped")
			continue
		}
		volumeMounts = append(volumeMounts, vm)
	}
	for _, v := range configArray(log, cmFields, "extraHostPathMounts", []string{}) {
		vm := corev1.VolumeMount{}
		if err := yaml.Unmarshal([]byte(v), &vm); err != nil {
			log.WithValues("value", v).Error(err, "could not unmarshal the extraHostPathMount, skipped")
			continue
		}
		volumeMounts = append(volumeMounts, vm)
	}
	for _, v := range configArray(log, cmFields, "extraConfigmapMounts", []string{}) {
		vm := corev1.VolumeMount{}
		if err := yaml.Unmarshal([]byte(v), &vm); err != nil {
			log.WithValues("value", v).Error(err, "could not unmarshal the extraConfigmapMount, skipped")
			continue
		}
		volumeMounts = append(volumeMounts, vm)
	}
	if configValue(log, cmFields, "metadataEnabled", false) {
		volumeMounts = append(volumeMounts, corev1.VolumeMount{
			Name:      "metadata-files",
			MountPath: "/var/lib/tetragon/metadata",
		})
	}

	args := []string{"--config-dir=/etc/tetragon/tetragon.conf.d/"}
	argsOverride := configArray(log, cmFields, "argsOverride", []string{})
	if len(argsOverride) > 0 {
		args = append(args, argsOverride...)
	} else {
		for k, v := range configMapOfString(log, cmFields, "extraArgs") {
			if v != "" {
				args = append(args, fmt.Sprintf("--%s=%s", k, v))
				continue
			}
			args = append(args, fmt.Sprintf("--%s", k))
		}
	}

	tetragon := corev1.Container{
		Name:    "tetragon",
		Image:   os.Getenv("TETRAGON_IMAGE"),
		Args:    args,
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
		VolumeMounts:             volumeMounts,
		TerminationMessagePath:   "/dev/termination-log",
		TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
		ImagePullPolicy:          imagePullPolicy(log, cmFields),
		Resources:                resources,
		SecurityContext:          &securityContext,
	}
	if configValue(log, cmFields, "grpcEnabled", true) {
		tetragon.LivenessProbe = &corev1.Probe{
			ProbeHandler: corev1.ProbeHandler{
				Exec: &corev1.ExecAction{
					Command: []string{
						"tetra",
						"status",
						"--server-address",
						configValue(log, cmFields, "grpcAddress", "localhost:54321"),
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

// nodeSelector returns the selectors configured by the user in the operator ConfigMap
// in addition to the ones that always get applied.
func nodeSelector(log logr.Logger, values map[string]any, key string) map[string]string {
	selector := configMapOfString(log, values, key)
	selector["kubernetes.io/os"] = "linux"
	return selector
}

func dnsPolicy(log logr.Logger, config map[string]any) corev1.DNSPolicy {
	policy := corev1.DNSPolicy(configValue(log, config, "dnsPolicy", string(corev1.DNSDefault)))
	switch policy {
	case corev1.DNSClusterFirstWithHostNet, corev1.DNSClusterFirst, corev1.DNSNone, corev1.DNSDefault:
		return policy
	}
	log.WithValues("key", "dnsPolicy", "value", policy).Error(errors.New("could not resolve dnsPolicy"), "default value used instead")
	return corev1.DNSDefault
}

func imagePullPolicy(log logr.Logger, config map[string]any) corev1.PullPolicy {
	policy := corev1.PullPolicy(configValue(log, config, "imagePullPolicy", string(corev1.DNSDefault)))
	switch policy {
	case corev1.PullAlways, corev1.PullNever, corev1.PullIfNotPresent:
		return policy
	}
	log.WithValues("key", "imagePullPolicy", "value", policy).Error(errors.New("could not resolve imagePullPolicy"), "default value used instead")
	return corev1.PullIfNotPresent
}

func volumes(log logr.Logger, cmFields map[string]any) []corev1.Volume {
	hostPathDirectoryVolumeType := corev1.HostPathDirectory
	hostPathDirectoryOrCreateVolumeType := corev1.HostPathDirectoryOrCreate
	dsVolumeDefaultMode := int32(420)
	volumes := []corev1.Volume{
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
					Path: configValue(log, cmFields, "hostProcPath", "/proc"),
					Type: &hostPathDirectoryVolumeType,
				},
			},
		},
	}
	if configValue(log, cmFields, "ociHookSetupEnabled", false) {
		volumes = append(volumes,
			corev1.Volume{
				Name: "oci-hooks-path",
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{
						Path: "/usr/share/containers/oci/hooks.d/",
						Type: &hostPathDirectoryVolumeType,
					},
				},
			},
			corev1.Volume{
				Name: "oci-hooks-install-path",
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{
						Path: configValue(log, cmFields, "ociHookSetupInstallDir", "/opt/tetragon"),
						Type: &hostPathDirectoryOrCreateVolumeType,
					},
				},
			},
		)
	}
	if configValue(log, cmFields, "metadataEnabled", false) {
		// TODO: this needs to be mounted
		volumes = append(volumes,
			corev1.Volume{
				Name: "metadata-files",
				VolumeSource: corev1.VolumeSource{
					EmptyDir: &corev1.EmptyDirVolumeSource{},
				},
			},
		)
	}
	for _, v := range configArray(log, cmFields, "extraVolumes", []string{}) {
		volume := corev1.Volume{}
		if err := yaml.Unmarshal([]byte(v), &volume); err != nil {
			log.WithValues("value", v).Error(err, "could not unmarshal an extraVolume, skipped")
		}
		volumes = append(volumes, volume)
	}
	for _, extraHostPathMountStr := range configArray(log, cmFields, "extraHostPathMounts", []string{}) {
		extraHostPathMount := corev1.Volume{}
		if err := yaml.Unmarshal([]byte(extraHostPathMountStr), &extraHostPathMount); err != nil {
			log.WithValues("value", extraHostPathMount).Error(err, "could not unmarshal an extraHostPathMount, skipped")
		}
		volumes = append(volumes, extraHostPathMount)
	}

	return volumes
}

func configValue[V string | bool](log logr.Logger, config map[string]any, key string, defaultValue V) V {
	if value, ok := config[key]; ok {
		if typedValue, ok := value.(V); ok {
			return typedValue
		}
		log.WithValues("key", key, "value", value).Error(errors.New("could not unmarshal"), "default value used instead")
	}
	return defaultValue
}

func configArray(log logr.Logger, config map[string]any, key string, defaultValue []string) []string {
	if value, ok := config[key]; ok {
		if a, ok := value.([]interface{}); ok {
			result := make([]string, 0, len(a))
			for _, v := range a {
				result = append(result, v.(string))
			}
			return result
		}
		log.WithValues("key", key, "value", value).Error(errors.New("could not unmarshal"), "default values used instead")
	}
	return defaultValue
}

func configMapOfString(log logr.Logger, m map[string]any, key string) map[string]string {
	stringValues := map[string]string{}
	if values, ok := m[key]; ok {
		typedValues, ok := values.(map[string]interface{})
		if !ok {
			log.WithValues("key", key, "value", values).Error(errors.New("could not unmarshal"), "not applied")
		} else {
			for k, v := range typedValues {
				stringValues[k] = v.(string)
			}
		}
	}
	return stringValues
}

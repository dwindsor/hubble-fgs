package agent

import (
	"errors"
	"fmt"
	"os"

	"github.com/go-logr/logr"
	appv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	k8sv1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"
)

// daemonSet instantiates a Tetragon DaemonSet configuration.
func daemonSet(log logr.Logger, namespace string, name string, cm *corev1.ConfigMap) (*appv1.DaemonSet, error) {
	dsTerminationGracePeriodSec := int64(1)

	configYaml := cm.Data[OperatorConfigMapAgentDaemonSetKey]
	cmFields := make(map[string]interface{})
	if err := yaml.Unmarshal([]byte(configYaml), &cmFields); err != nil {
		log.WithValues("value", configYaml).Error(err, "could not unmarshal the DaemonSet configuration")
		return nil, err
	}

	imagePullSecrets := make([]corev1.LocalObjectReference, 0)
	imagePullSecretsValue := configValue(log, cmFields, "imagePullSecrets", "")
	if imagePullSecretsValue != "" {
		if err := yaml.Unmarshal([]byte(imagePullSecretsValue), &imagePullSecrets); err != nil {
			log.WithValues("value", imagePullSecretsValue).Error(err, "could not unmarshal the imagePullSecrets, skipped")
		}
	}

	securityContext := corev1.PodSecurityContext{}
	securityContextValue := configValue(log, cmFields, "podSecurityContext", "")
	if securityContextValue != "" {
		if err := yaml.Unmarshal([]byte(securityContextValue), &securityContext); err != nil {
			log.WithValues("value", securityContextValue).Error(err, "could not unmarshal the podSecurityContext, default value used instead")
		}
	}

	var affinity corev1.Affinity
	affinityValue := configValue(log, cmFields, "affinity", "")
	if affinityValue != "" {
		if err := yaml.Unmarshal([]byte(affinityValue), &affinity); err != nil {
			log.WithValues("value", affinityValue).Error(err, "could not unmarshal the affinity, affinity not applied")
		}
	}

	tolerations := make([]corev1.Toleration, 0)
	tolerationValues := configValue(log, cmFields, "tolerations", "")
	if tolerationValues != "" {
		if err := yaml.Unmarshal([]byte(tolerationValues), &tolerations); err != nil {
			log.WithValues("value", tolerationValues).Error(err, "could not unmarshal the toleration, toleration not applied")
		}
	}

	var updateStrategy appv1.DaemonSetUpdateStrategy
	updateStrategyValue := configValue(log, cmFields, "updateStrategy", "")
	if updateStrategyValue != "" {
		if err := yaml.Unmarshal([]byte(updateStrategyValue), &updateStrategy); err != nil {
			log.WithValues("value", updateStrategyValue).Error(err, "could not unmarshal the update strategy, update strategy not applied")
		}
	}

	labels := labelsForManaged()
	for k, v := range configMapOfString(log, cmFields, "extraLabels") {
		labels[k] = v
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
			Labels:      labels,
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
					PriorityClassName:             configValue(log, cmFields, "priorityClassName", ""),
					ImagePullSecrets:              imagePullSecrets,
					ServiceAccountName:            configValue(log, cmFields, "serviceAccountName", "tetragon"),
					SecurityContext:               &securityContext,
					InitContainers:                daemonSetInitContainers(log, cmFields),
					Containers:                    daemonSetContainers(log, cmFields),
					NodeSelector:                  nodeSelector(log, cmFields, "nodeSelector"),
					Affinity:                      &affinity,
					Tolerations:                   tolerations,
					HostNetwork:                   configValue(log, cmFields, "hostNetwork", true),
					DNSPolicy:                     dnsPolicy(log, cmFields),
					TerminationGracePeriodSeconds: &dsTerminationGracePeriodSec,
					Volumes:                       volumes(log, cmFields),
					// This is required to avoid diff with actual K8S object
					DeprecatedServiceAccount: configValue(log, cmFields, "serviceAccountName", "tetragon"),
				},
			},
			UpdateStrategy: updateStrategy,
		},
	}
	return ds, nil
}

func daemonSetInitContainers(log logr.Logger, cmFields map[string]any) []corev1.Container {
	containers := make([]corev1.Container, 0)
	if configValue(log, cmFields, "ociHookSetupEnabled", false) {
		privileged := true
		securityContext := corev1.SecurityContext{Privileged: &privileged}
		securityContextValue := configValue(log, cmFields, "ociHookSetupSecurityContext", "")
		if securityContextValue != "" {
			if err := yaml.Unmarshal([]byte(securityContextValue), &securityContext); err != nil {
				log.WithValues("value", securityContextValue).Error(err, "could not unmarshal the security context, default value used instead")
			}
		}

		resources := corev1.ResourceRequirements{}
		resourcesValue := configValue(log, cmFields, "ociHookSetupResources", "")
		if resourcesValue != "" {
			if err := yaml.Unmarshal([]byte(resourcesValue), &resources); err != nil {
				log.WithValues("value", resourcesValue).Error(err, "could not unmarshal the resources, default value used instead")
			}
		}

		containers = append(containers, corev1.Container{
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
				volumeMountsFromConfigMap(log, cmFields, "ociHookSetupExtraVolumeMounts"),
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
		})
	}

	if configValue(log, cmFields, "metadataEnabled", false) {
		args := []string{"-c", "|\ncp -r /var/run/tetragon-ee-metadata/* /var/lib/tetragon/metadata"}
		volumeMounts := []corev1.VolumeMount{
			{
				Name:      "metadata-files",
				MountPath: "/var/lib/tetragon/metadata",
			},
		}
		if configValue(log, cmFields, "enableCiliumAPI", false) {
			args[1] = fmt.Sprintf("%s\nuntil [ -S /var/run/cilium/cilium.sock -a -S /var/run/cilium/monitor1_2.sock ]; do sleep 3; done", args[1])
			volumeMounts = append(volumeMounts, corev1.VolumeMount{
				Name:      "cilium-run",
				MountPath: "/var/run/cilium",
			})
		}
		containers = append(containers, corev1.Container{
			Name:                     "tetragon",
			Image:                    os.Getenv("TETRAGON_METADATA_IMAGE"),
			ImagePullPolicy:          imagePullPolicy(log, cmFields, "metadataImagePullPolicy", corev1.PullAlways),
			TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
			Command:                  []string{"sh"},
			Args:                     args,
			VolumeMounts:             volumeMounts,
		})
	}

	return containers
}

func daemonSetContainers(log logr.Logger, cmFields map[string]any) []corev1.Container {
	bidirectionalMount := corev1.MountPropagationBidirectional
	containers := make([]corev1.Container, 0)

	if configValue(log, cmFields, "exportMode", "") == "stdout" {
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

		exportFileNames := configArray(log, cmFields, "exportFileNames", []string{"tetragon.log"})
		args := make([]string, 0, len(exportFileNames))
		for _, f := range exportFileNames {
			args = append(args, fmt.Sprintf("%s/%s", configValue(log, cmFields, "exportDirectory", "/var/run/cilium/tetragon"), f))
		}
		containers = append(containers, corev1.Container{
			Name:                     "export-stdout",
			Image:                    os.Getenv("EXPORT_IMAGE"),
			ImagePullPolicy:          imagePullPolicy(log, cmFields, "imagePullPolicy", corev1.PullIfNotPresent),
			TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
			Env:                      env,
			SecurityContext:          &securityContext,
			Resources:                resources,
			Command:                  []string{"hubble-export-stdout"},
			Args:                     args,
			VolumeMounts: []corev1.VolumeMount{{
				Name:      "export-logs",
				MountPath: configValue(log, cmFields, "exportDirectory", "/var/run/cilium/tetragon"),
			}},
		})
	}

	if configValue(log, cmFields, "tetragonEnabled", true) {
		resources := corev1.ResourceRequirements{}
		resourcesValue := configValue(log, cmFields, "tetragonResources", "")
		if resourcesValue != "" {
			if err := yaml.Unmarshal([]byte(resourcesValue), &resources); err != nil {
				log.WithValues("value", resourcesValue).Error(err, "could not unmarshal the tetragonResources, default value used instead")
			}
		}

		privileged := true
		securityContext := corev1.SecurityContext{Privileged: &privileged}
		securityContextValue := configValue(log, cmFields, "tetragonSecurityContext", "")
		if securityContextValue != "" {
			if err := yaml.Unmarshal([]byte(securityContextValue), &securityContext); err != nil {
				log.WithValues("value", securityContextValue).Error(err, "could not unmarshal the tetragonSecurityContext, default value used instead")
			}
		}

		args := []string{"--config-dir=/etc/tetragon/tetragon.conf.d/"}
		argsOverride := configArray(log, cmFields, "argsOverride", []string{})
		if len(argsOverride) > 0 {
			args = append(args, argsOverride...)
		} else {
			for k, v := range configMapOfString(log, cmFields, "extraArgs") {
				if v != "" {
					args = append(args, fmt.Sprintf("--%s=%s", k, v))
				} else {
					args = append(args, fmt.Sprintf("--%s", k))
				}
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
		volumeMounts = append(volumeMounts, volumeMountsFromConfigMap(log, cmFields, "extraVolumeMounts")...)
		volumeMounts = append(volumeMounts, volumeMountsFromConfigMap(log, cmFields, "extraHostPathMounts")...)
		volumeMounts = append(volumeMounts, volumeMountsFromConfigMap(log, cmFields, "extraConfigmapMounts")...)
		if configValue(log, cmFields, "metadataEnabled", false) {
			volumeMounts = append(volumeMounts, corev1.VolumeMount{
				Name:      "metadata-files",
				MountPath: "/var/lib/tetragon/metadata",
			})
		}

		env := []corev1.EnvVar{{
			Name: "NODE_NAME",
			ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{
					APIVersion: "v1",
					FieldPath:  "spec.nodeName",
				},
			},
		}}
		extraEnv := make([]corev1.EnvVar, 0)
		extraEnvStr := configValue(log, cmFields, "extraEnv", "")
		if extraEnvStr != "" {
			if err := yaml.Unmarshal([]byte(extraEnvStr), &extraEnv); err != nil {
				log.WithValues("value", extraEnvStr).Error(err, "could not unmarshal the extraEnv, skipped")
			}
		}
		env = append(env, extraEnv...)

		var livenessProbe *corev1.Probe
		if configValue(log, cmFields, "grpcEnabled", true) {
			livenessProbe = &corev1.Probe{
				TimeoutSeconds: int32(60),
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
			}
		}

		containers = append(containers, corev1.Container{
			Name:                     "tetragon",
			SecurityContext:          &securityContext,
			Image:                    os.Getenv("TETRAGON_IMAGE"),
			ImagePullPolicy:          imagePullPolicy(log, cmFields, "imagePullPolicy", corev1.PullIfNotPresent),
			TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
			Command:                  configArray(log, cmFields, "commandOverride", []string{}),
			Args:                     args,
			VolumeMounts:             volumeMounts,
			Env:                      env,
			Resources:                resources,
			LivenessProbe:            livenessProbe,
		})
	}

	return containers
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

func imagePullPolicy(log logr.Logger, config map[string]any, key string, defaultValue corev1.PullPolicy) corev1.PullPolicy {
	policy := corev1.PullPolicy(configValue(log, config, key, string(corev1.PullIfNotPresent)))
	switch policy {
	case corev1.PullAlways, corev1.PullNever, corev1.PullIfNotPresent:
		return policy
	}
	log.WithValues("key", key, "value", policy).Error(errors.New("could not resolve image pull policy"), "default value used instead")
	return defaultValue
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
					Path: configValue(log, cmFields, "exportDirectory", "/var/run/cilium/tetragon"),
					Type: &hostPathDirectoryOrCreateVolumeType,
				},
			},
		},
	}
	if configValue(log, cmFields, "tetragonEnabled", true) {
		volumes = append(volumes,
			corev1.Volume{
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
			corev1.Volume{
				Name: "bpf-maps",
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{
						Path: "/sys/fs/bpf",
						Type: &hostPathDirectoryOrCreateVolumeType,
					},
				},
			},
			corev1.Volume{
				Name: "host-proc",
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{
						Path: configValue(log, cmFields, "hostProcPath", "/proc"),
						Type: &hostPathDirectoryVolumeType,
					},
				},
			},
		)
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
	}
	volumes = append(volumes, volumesFromConfigMap(log, cmFields, "extraVolumes")...)
	volumes = append(volumes, volumesFromConfigMap(log, cmFields, "extraHostPathMounts")...)
	if configValue(log, cmFields, "metadataEnabled", false) {
		volumes = append(volumes, corev1.Volume{
			Name: "metadata-files",
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{},
			},
		})
	}
	return volumes
}

func volumeMountsFromConfigMap(log logr.Logger, cmFields map[string]any, key string) []corev1.VolumeMount {
	value := configValue(log, cmFields, key, "")
	if value == "" {
		return []corev1.VolumeMount{}
	}
	mounts := make([]corev1.VolumeMount, 0)
	if err := yaml.Unmarshal([]byte(value), &mounts); err != nil {
		log.WithValues("value", value).Error(err, fmt.Sprintf("could not unmarshal the %s volume mount, skipped", key))
	}
	return mounts
}

func volumesFromConfigMap(log logr.Logger, cmFields map[string]any, key string) []corev1.Volume {
	value := configValue(log, cmFields, key, "")
	if value == "" {
		return []corev1.Volume{}
	}
	volumes := make([]corev1.Volume, 0)
	if err := yaml.Unmarshal([]byte(value), &volumes); err != nil {
		log.WithValues("value", value).Error(err, fmt.Sprintf("could not unmarshal the %s volume, skipped", key))
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

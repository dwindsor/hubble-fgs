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
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/go-logr/logr"
	appv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	k8sv1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"
)

// DaemonSet instantiates a Tetragon DaemonSet configuration.
func DaemonSet(log logr.Logger, namespace string, name string, cm *corev1.ConfigMap) (*appv1.DaemonSet, error) {
	// TODO: Unmarshalling of the CM should be done once: before calling DaemonSet and RTDaemonSet
	// Separating the code in 3 files could be considered
	// - common
	// - specific to the agent DS
	// - specific to the RT DS
	configYaml := cm.Data[OperatorConfigMapAgentDaemonSetKey]
	cmFields := make(map[string]any)
	if err := yaml.Unmarshal([]byte(configYaml), &cmFields); err != nil {
		log.WithValues("value", configYaml).Error(err, "could not unmarshal the DaemonSet configuration")
		return nil, err
	}
	// RT hooks fail namespaces need to be passed to the agent
	rtConfigYaml := cm.Data[OperatorConfigMapRTHooksDaemonSetKey]
	if err := yaml.Unmarshal([]byte(rtConfigYaml), new(make(map[string]any))); err != nil {
		log.WithValues("value", rtConfigYaml).Error(err, "could not unmarshal the runtime hooks DaemonSet configuration")
		return nil, err
	}

	splunkYaml := cm.Data[splunkKey]
	splunkCMFields := make(map[string]any)
	if err := yaml.Unmarshal([]byte(splunkYaml), &splunkCMFields); err != nil {
		log.WithValues("value", splunkYaml).Error(err, "could not unmarshal the splunk_hec configuration")
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

	labels := configMapOfString(log, cmFields, "labelsOverride")
	if len(labels) == 0 {
		labels = labelsForManaged(name)
	}

	ds := &appv1.DaemonSet{
		Kind:        "DaemonSet",
		APIVersion:  "apps/v1",
		Name:        name,
		Namespace:   namespace,
		Annotations: configMapOfString(log, cmFields, "annotations"),
		Labels:      labels,
		Spec: appv1.DaemonSetSpec{
			Selector: &k8sv1.LabelSelector{
				MatchLabels: labelsForManaged(name),
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: k8sv1.ObjectMeta{
					Labels:      labelsForManaged(name),
					Annotations: configMapOfString(log, cmFields, "podAnnotations"),
				},
				Spec: corev1.PodSpec{
					PriorityClassName:             configValue(log, cmFields, "priorityClassName", ""),
					ImagePullSecrets:              imagePullSecrets,
					ServiceAccountName:            configValue(log, cmFields, "serviceAccountName", ""),
					SecurityContext:               &securityContext,
					InitContainers:                daemonSetInitContainers(log, namespace, cmFields),
					Containers:                    daemonSetContainersWithOtel(log, cmFields, splunkCMFields),
					NodeSelector:                  configMapOfString(log, cmFields, "nodeSelector"),
					Affinity:                      &affinity,
					Tolerations:                   tolerations,
					HostNetwork:                   configValue(log, cmFields, "hostNetwork", false),
					DNSPolicy:                     dnsPolicy(log, cmFields),
					TerminationGracePeriodSeconds: new(int64(1)),
					Volumes:                       volumes(log, cmFields, splunkCMFields),
					// This is required to avoid diff with actual K8S object
					DeprecatedServiceAccount: configValue(log, cmFields, "serviceAccountName", ""),
				},
			},
			UpdateStrategy: updateStrategy,
		},
	}
	return ds, nil
}

// RTDaemonSet instantiates a Tetragon DaemonSet for the runtime hooks.
func RTDaemonSet(log logr.Logger, namespace string, name string, cm *corev1.ConfigMap) (*appv1.DaemonSet, error) {
	// TODO: Unmarshalling of the CM should be done once: before calling DaemonSet and RTDaemonSet (see above)
	configYaml := cm.Data[OperatorConfigMapAgentDaemonSetKey]
	cmFields := make(map[string]any)
	if err := yaml.Unmarshal([]byte(configYaml), &cmFields); err != nil {
		log.WithValues("value", configYaml).Error(err, "could not unmarshal the DaemonSet configuration")
		return nil, err
	}
	rtConfigYaml := cm.Data[OperatorConfigMapRTHooksDaemonSetKey]
	rtCMFields := make(map[string]any)
	if err := yaml.Unmarshal([]byte(rtConfigYaml), &rtCMFields); err != nil {
		log.WithValues("value", rtConfigYaml).Error(err, "could not unmarshal the runtime hooks DaemonSet configuration")
		return nil, err
	}
	// the runtime hooks DaemonSet gets only created if it is enabled
	if !configValue(log, rtCMFields, "enabled", false) {
		return nil, nil
	}

	labels := configMapOfString(log, rtCMFields, "labelsOverride")
	if len(labels) == 0 {
		labels = labelsForManaged(name)
	}

	imagePullSecrets := make([]corev1.LocalObjectReference, 0)
	imagePullSecretsValue := configValue(log, cmFields, "imagePullSecrets", "")
	if imagePullSecretsValue != "" {
		if err := yaml.Unmarshal([]byte(imagePullSecretsValue), &imagePullSecrets); err != nil {
			log.WithValues("value", imagePullSecretsValue).Error(err, "could not unmarshal the imagePullSecrets, skipped")
		}
	}

	podSecurityContext := corev1.PodSecurityContext{}
	podSecurityContextValue := configValue(log, rtCMFields, "podSecurityContext", "")
	if podSecurityContextValue != "" {
		if err := yaml.Unmarshal([]byte(podSecurityContextValue), &podSecurityContext); err != nil {
			log.WithValues("value", podSecurityContextValue).Error(err, "could not unmarshal the podSecurityContext, default value used instead")
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

	ds := &appv1.DaemonSet{
		Kind:        "DaemonSet",
		APIVersion:  "apps/v1",
		Name:        name,
		Namespace:   namespace,
		Annotations: configMapOfString(log, rtCMFields, "annotations"),
		Labels:      labels,
		Spec: appv1.DaemonSetSpec{
			Selector: &k8sv1.LabelSelector{
				MatchLabels: labelsForManaged(name),
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: k8sv1.ObjectMeta{
					Labels:      labelsForManaged(name),
					Annotations: configMapOfString(log, rtCMFields, "podAnnotations"),
				},
				Spec: corev1.PodSpec{
					PriorityClassName:            configValue(log, rtCMFields, "priorityClassName", ""),
					ImagePullSecrets:             imagePullSecrets,
					ServiceAccountName:           configValue(log, rtCMFields, "serviceAccountName", ""),
					AutomountServiceAccountToken: new(false),
					SecurityContext:              &podSecurityContext,
					Containers:                   rtDaemonSetContainers(log, rtCMFields, cmFields, namespace),
					NodeSelector:                 configMapOfString(log, cmFields, "nodeSelector"),
					Affinity:                     &affinity,
					Tolerations:                  tolerations,
					Volumes:                      rtVolumes(log, rtCMFields),
				},
			},
		},
	}
	return ds, nil
}

func daemonSetInitContainers(log logr.Logger, namespace string, cmFields map[string]any) []corev1.Container {
	containers := make([]corev1.Container, 0)
	if configValue(log, cmFields, "ociHookSetupEnabled", false) {
		securityContext := corev1.SecurityContext{}
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

		grpcAddress := fmt.Sprintf("--grpc-address=%s", configValue(log, cmFields, "tetragonGrpcAddress", ""))
		failNs := configValue(log, cmFields, "ociHookFailAllowNamespaces", "")
		if failNs != "" {
			failNs = strings.Join([]string{namespace, failNs}, ",")
		} else {
			failNs = namespace
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
				configValue(log, cmFields, "ociHookSetupInterface", ""),
				"--local-install-dir=/hostInstall",
				"--host-install-dir",
				configValue(log, cmFields, "ociHookSetupInstallDir", ""),
				"--oci-hooks.local-dir=/hostHooks",
				"hook-args",
				grpcAddress,
				"--fail-allow-namespaces",
				failNs,
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
			ImagePullPolicy:          imagePullPolicy(log, cmFields, "metadataImagePullPolicy"),
			TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
			Command:                  []string{"sh"},
			Args:                     args,
			VolumeMounts:             volumeMounts,
		})
	}

	return containers
}

func daemonSetContainers(log logr.Logger, cmFields map[string]any) []corev1.Container {
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

		exportFileNames := configArray(log, cmFields, "exportFileNames", []string{})
		args := make([]string, 0, len(exportFileNames))
		for _, f := range exportFileNames {
			args = append(args, fmt.Sprintf("%s/%s", configValue(log, cmFields, "exportDirectory", ""), f))
		}
		containers = append(containers, corev1.Container{
			Name:                     "export-stdout",
			Image:                    os.Getenv("EXPORT_IMAGE"),
			ImagePullPolicy:          imagePullPolicy(log, cmFields, "imagePullPolicy"),
			TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
			Env:                      env,
			SecurityContext:          &securityContext,
			Resources:                resources,
			Command:                  []string{"hubble-export-stdout"},
			Args:                     args,
			VolumeMounts: []corev1.VolumeMount{{
				Name:      "export-logs",
				MountPath: configValue(log, cmFields, "exportDirectory", ""),
			}},
		})
	}

	if configValue(log, cmFields, "tetragonEnabled", false) {
		resources := corev1.ResourceRequirements{}
		resourcesValue := configValue(log, cmFields, "tetragonResources", "")
		if resourcesValue != "" {
			if err := yaml.Unmarshal([]byte(resourcesValue), &resources); err != nil {
				log.WithValues("value", resourcesValue).Error(err, "could not unmarshal the tetragonResources, default value used instead")
			}
		}

		securityContext := corev1.SecurityContext{}
		securityContextValue := configValue(log, cmFields, "tetragonSecurityContext", "")
		if securityContextValue != "" {
			if err := yaml.Unmarshal([]byte(securityContextValue), &securityContext); err != nil {
				log.WithValues("value", securityContextValue).Error(err, "could not unmarshal the tetragonSecurityContext, default value used instead")
			}
		}

		ports := make([]corev1.ContainerPort, 0)
		args := []string{"--config-dir=/etc/tetragon/tetragon.conf.d/"}
		if configValue(log, cmFields, "serviceMonitorEnabled", false) {
			metricAddress := configValue(log, cmFields, "agentServiceMonitorPrometheusAddress", "")
			metricPort := configValueInt(log, cmFields, "agentServiceMonitorPrometheusPort", 32, 2112)
			args = append(args, fmt.Sprintf("--metrics-server=%s:%d", metricAddress, metricPort))
			ports = append(ports, corev1.ContainerPort{
				Name:          "metrics",
				ContainerPort: int32(metricPort),
				Protocol:      "TCP",
			})
		}
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
				MountPropagation: new(corev1.MountPropagationBidirectional),
			},
			{
				Name:      "cilium-run",
				MountPath: "/var/run/cilium",
			},
			{
				Name:      "export-logs",
				MountPath: configValue(log, cmFields, "exportDirectory", ""),
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
		livenessProbeStr := configValue(log, cmFields, "tetragonLivenessProbe", "")
		if livenessProbeStr != "" {
			if err := yaml.Unmarshal([]byte(livenessProbeStr), &livenessProbe); err != nil {
				log.WithValues("value", livenessProbeStr).Error(err, "could not unmarshal the tetragonLivenessProbe, skipped")
			}
		} else if configValue(log, cmFields, "tetragonHealthGrpcEnabled", false) {
			healthGrpcPort := configValueInt(log, cmFields, "tetragonHealthGrpcPort", 32, 6789)
			livenessProbe = &corev1.Probe{
				TimeoutSeconds: int32(60),
				GRPC: &corev1.GRPCAction{
					Port:    int32(healthGrpcPort),
					Service: new("liveness"),
				},
			}
		}

		var startupProbe *corev1.Probe
		startupProbeStr := configValue(log, cmFields, "tetragonStartupProbe", "")
		if startupProbeStr != "" {
			if err := yaml.Unmarshal([]byte(startupProbeStr), &startupProbe); err != nil {
				log.WithValues("value", startupProbeStr).Error(err, "could not unmarshal the tetragonStartupProbe, skipped")
			}
		} else if configValue(log, cmFields, "tetragonHealthGrpcEnabled", false) {
			healthGrpcPort := configValueInt(log, cmFields, "tetragonHealthGrpcPort", 32, 6789)
			startupProbe = &corev1.Probe{
				TimeoutSeconds: int32(60),
				GRPC: &corev1.GRPCAction{
					Port:    int32(healthGrpcPort),
					Service: new("startup"),
				},
			}
		}

		containers = append(containers, corev1.Container{
			Name:                     "tetragon",
			SecurityContext:          &securityContext,
			Image:                    os.Getenv("TETRAGON_IMAGE"),
			ImagePullPolicy:          imagePullPolicy(log, cmFields, "imagePullPolicy"),
			TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
			Command:                  configArray(log, cmFields, "commandOverride", []string{}),
			Args:                     args,
			VolumeMounts:             volumeMounts,
			Env:                      env,
			Resources:                resources,
			LivenessProbe:            livenessProbe,
			StartupProbe:             startupProbe,
			Ports:                    ports,
		})
	}

	return containers
}

func rtDaemonSetContainers(log logr.Logger, rtCMFields map[string]any, cmFields map[string]any, namespace string) []corev1.Container {
	securityContext := corev1.SecurityContext{}
	securityContextValue := configValue(log, rtCMFields, "securityContext", "")
	if securityContextValue != "" {
		if err := yaml.Unmarshal([]byte(securityContextValue), &securityContext); err != nil {
			log.WithValues("value", securityContextValue).Error(err, "could not unmarshal the rthooks container security context, default value used instead")
		}
	}

	failNs := configValue(log, rtCMFields, "failAllowNamespaces", "")
	if failNs != "" {
		failNs = strings.Join([]string{namespace, failNs}, ",")
	} else {
		failNs = namespace
	}

	commands := []string{
		"tetragon-oci-hook-setup",
		"install",
		fmt.Sprintf("--interface=%s", configValue(log, rtCMFields, "interface", "")),
		"--local-install-dir=/hostInstall",
		"--host-install-dir",
		configValue(log, rtCMFields, "installDir", ""),
		"--oci-hooks.local-dir=/hostHooks",
		"--daemonize",
		"hook-args",
		fmt.Sprintf("--grpc-address=%s", configValue(log, cmFields, "tetragonGrpcAddress", "")),
		"--fail-allow-namespaces",
		failNs,
	}
	for k, v := range configMapOfString(log, rtCMFields, "extraHookArgs") {
		if v != "" {
			commands = append(commands, fmt.Sprintf("%s=%s", k, v))
		} else {
			commands = append(commands, k)
		}
	}

	volumeMounts := []corev1.VolumeMount{
		{
			Name:      "oci-hooks-install-path",
			MountPath: "/hostInstall",
		},
	}
	switch configValue(log, rtCMFields, "interface", "") {
	case "oci-hooks":
		volumeMounts = append(volumeMounts, corev1.VolumeMount{
			Name:      "oci-hooks-path",
			MountPath: "/hostHooks",
		})
	case "nri-hook":
		volumeMounts = append(volumeMounts, corev1.VolumeMount{
			Name:      "nri-socket-path",
			MountPath: configValue(log, rtCMFields, "nriHookSocket", ""),
		})
	}
	volumeMounts = append(volumeMounts, volumeMountsFromConfigMap(log, rtCMFields, "extraVolumeMounts")...)

	containers := make([]corev1.Container, 0)
	containers = append(containers, corev1.Container{
		Name:                     "tetragon-rthooks",
		Image:                    os.Getenv("TETRAGON_RTHOOKS_IMAGE"),
		SecurityContext:          &securityContext,
		TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
		ImagePullPolicy:          imagePullPolicy(log, cmFields, "imagePullPolicy"),
		Command:                  commands,
		VolumeMounts:             volumeMounts,
	})
	return containers
}

func dnsPolicy(log logr.Logger, config map[string]any) corev1.DNSPolicy {
	policy := corev1.DNSPolicy(configValue(log, config, "dnsPolicy", ""))
	switch policy {
	case corev1.DNSClusterFirstWithHostNet, corev1.DNSClusterFirst, corev1.DNSNone, corev1.DNSDefault:
		return policy
	}
	log.WithValues("key", "dnsPolicy", "value", policy).Error(errors.New("could not resolve dnsPolicy"), "default value used instead")
	return corev1.DNSDefault
}

func volumes(log logr.Logger, cmFields map[string]any, splunkCMFields map[string]any) []corev1.Volume {
	hostPathDirectoryVolumeType := corev1.HostPathDirectory
	hostPathDirectoryOrCreateVolumeType := corev1.HostPathDirectoryOrCreate
	volumes := []corev1.Volume{
		{
			Name: "cilium-run",
			HostPath: &corev1.HostPathVolumeSource{
				Path: "/var/run/cilium",
				Type: &hostPathDirectoryOrCreateVolumeType,
			},
		},
		{
			Name: "export-logs",
			HostPath: &corev1.HostPathVolumeSource{
				Path: configValue(log, cmFields, "exportDirectory", ""),
				Type: &hostPathDirectoryOrCreateVolumeType,
			},
		},
	}
	if configValue(log, cmFields, "tetragonEnabled", false) {
		volumes = append(volumes,
			corev1.Volume{
				Name: "tetragon-config",
				ConfigMap: &corev1.ConfigMapVolumeSource{
					Name:        "tetragon-config",
					DefaultMode: new(int32(420)),
				},
			},
			corev1.Volume{
				Name: "bpf-maps",
				HostPath: &corev1.HostPathVolumeSource{
					Path: "/sys/fs/bpf",
					Type: &hostPathDirectoryOrCreateVolumeType,
				},
			},
			corev1.Volume{
				Name: "host-proc",
				HostPath: &corev1.HostPathVolumeSource{
					Path: configValue(log, cmFields, "hostProcPath", ""),
					Type: &hostPathDirectoryVolumeType,
				},
			},
		)
		if configValue(log, cmFields, "ociHookSetupEnabled", false) {
			volumes = append(volumes,
				corev1.Volume{
					Name: "oci-hooks-path",
					HostPath: &corev1.HostPathVolumeSource{
						Path: "/usr/share/containers/oci/hooks.d/",
						Type: &hostPathDirectoryVolumeType,
					},
				},
				corev1.Volume{
					Name: "oci-hooks-install-path",
					HostPath: &corev1.HostPathVolumeSource{
						Path: configValue(log, cmFields, "ociHookSetupInstallDir", ""),
						Type: &hostPathDirectoryOrCreateVolumeType,
					},
				},
			)
		}
		if configValue(log, splunkCMFields, "enabled", false) {
			volumes = append(volumes,
				corev1.Volume{
					Name: "otel-agent-config-vol",
					ConfigMap: &corev1.ConfigMapVolumeSource{
						Name: OtelConfigMapName,
						Items: []corev1.KeyToPath{{
							Key:  "otel-agent-config",
							Path: "otel-agent-config.yaml",
						}},
					},
				},
				corev1.Volume{
					Name:     "file-storage",
					EmptyDir: &corev1.EmptyDirVolumeSource{},
				},
			)

			tlsSecretName := ""
			if tlsFields, ok := splunkCMFields[tlsKey].(map[string]any); ok {
				if secretFields, ok := tlsFields[tlsSecretKey].(map[string]any); ok {
					if n, ok := secretFields[tlsSecretNameKey].(string); ok {
						tlsSecretName = n
					}
				}
			}
			tlsCAFile := ""
			if tlsFields, ok := splunkCMFields[tlsKey].(map[string]any); ok {
				if secretFields, ok := tlsFields[tlsSecretKey].(map[string]any); ok {
					if ca, ok := secretFields[tlsSecretCACertKey].(string); ok {
						tlsCAFile = ca
					}
				}
			}
			tlsCertFile := ""
			if tlsFields, ok := splunkCMFields[tlsKey].(map[string]any); ok {
				if secretFields, ok := tlsFields[tlsSecretKey].(map[string]any); ok {
					if cert, ok := secretFields[tlsSecretClientCertKey].(string); ok {
						tlsCertFile = cert
					}
				}
			}
			tlsKeyFile := ""
			if tlsFields, ok := splunkCMFields[tlsKey].(map[string]any); ok {
				if secretFields, ok := tlsFields[tlsSecretKey].(map[string]any); ok {
					if key, ok := secretFields[tlsSecretClientKeyKey].(string); ok {
						tlsKeyFile = key
					}
				}
			}
			if tlsSecretName == "" || (tlsCAFile == "" && tlsCertFile == "" && tlsKeyFile == "") {
				tlsInlineCA := ""
				if tlsFields, ok := splunkCMFields[tlsKey].(map[string]any); ok {
					tlsInlineCA, _ = tlsFields[tlsCAKey].(string)
				}
				tlsInlineCert := ""
				if tlsFields, ok := splunkCMFields[tlsKey].(map[string]any); ok {
					tlsInlineCert, _ = tlsFields[tlsCertKey].(string)
				}
				tlsInlineKey := ""
				if tlsFields, ok := splunkCMFields[tlsKey].(map[string]any); ok {
					tlsInlineKey, _ = tlsFields[tlsKeyKey].(string)
				}
				if tlsInlineCA != "" || tlsInlineCert != "" || tlsInlineKey != "" {
					tlsSecretName = "tetragon-splunk-tls"
				}
			}
			if tlsSecretName != "" {
				volumes = append(volumes,
					corev1.Volume{
						Name: "otel-splunk-tls",
						Secret: &corev1.SecretVolumeSource{
							SecretName: tlsSecretName,
						},
					},
				)
			}
		}

	}
	volumes = append(volumes, volumesFromConfigMap(log, cmFields, "extraVolumes")...)
	volumes = append(volumes, hostPathVolumesFromConfigMap(log, cmFields, "extraHostPathMounts")...)
	if configValue(log, cmFields, "metadataEnabled", false) {
		volumes = append(volumes, corev1.Volume{
			Name:     "metadata-files",
			EmptyDir: &corev1.EmptyDirVolumeSource{},
		})
	}
	return volumes
}

func rtVolumes(log logr.Logger, cmFields map[string]any) []corev1.Volume {
	volumes := []corev1.Volume{
		{
			Name: "oci-hooks-install-path",
			HostPath: &corev1.HostPathVolumeSource{
				Path: configValue(log, cmFields, "installDir", ""),
				Type: new(corev1.HostPathDirectoryOrCreate),
			},
		},
	}
	switch configValue(log, cmFields, "interface", "") {
	case "oci-hooks":
		volumes = append(volumes, corev1.Volume{
			Name: "oci-hooks-path",
			HostPath: &corev1.HostPathVolumeSource{
				Path: configValue(log, cmFields, "ociHooksPath", ""),
				Type: new(corev1.HostPathDirectory),
			},
		})
	case "nri-hook":
		volumes = append(volumes, corev1.Volume{
			Name: "nri-socket-path",
			HostPath: &corev1.HostPathVolumeSource{
				Path: configValue(log, cmFields, "nriHookSocket", ""),
				Type: new(corev1.HostPathSocket),
			},
		})
	}
	return volumes
}

func hostPathVolumesFromConfigMap(log logr.Logger, cmFields map[string]any, key string) []corev1.Volume {
	value := configValue(log, cmFields, key, "")
	if value == "" {
		return []corev1.Volume{}
	}
	// For extra hostpath volumes the volume definition in helm is induced from the volumeMount specification
	volumeMounts := make([]corev1.VolumeMount, 0)
	if err := yaml.Unmarshal([]byte(value), &volumeMounts); err != nil {
		log.WithValues("value", value).Error(err, fmt.Sprintf("could not unmarshal the %s hostpath volume, skipped", key))
	}
	volumes := make([]corev1.Volume, 0)
	for _, volumeMount := range volumeMounts {
		volume := corev1.Volume{
			Name: volumeMount.Name,
			HostPath: &corev1.HostPathVolumeSource{
				Path: volumeMount.MountPath,
			},
		}
		volumes = append(volumes, volume)
	}
	return volumes
}

func configArray(log logr.Logger, config map[string]any, key string, defaultValue []string) []string {
	if value, ok := config[key]; ok {
		if a, ok := value.([]any); ok {
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

func daemonSetContainersWithOtel(log logr.Logger, cmFields map[string]any, splunkCMFields map[string]any) []corev1.Container {
	containers := daemonSetContainers(log, cmFields)
	if configValue(log, splunkCMFields, "enabled", false) {
		if c := otelContainer(log, splunkCMFields, cmFields); c != nil {
			containers = append(containers, *c)
		}
	}
	return containers
}

func otelContainer(log logr.Logger, splunkFields map[string]any, cmFields map[string]any) *corev1.Container {
	imageFields, _ := splunkFields["image"].(map[string]any)
	override := ""
	repository := ""
	tag := ""
	if imageFields != nil {
		override, _ = imageFields["override"].(string)
		repository, _ = imageFields["repository"].(string)
		tag, _ = imageFields["tag"].(string)
	}
	image := ""
	if override != "" {
		image = override
	} else {
		if repository != "" && tag != "" {
			image = fmt.Sprintf("%s:%s", repository, tag)
		}
	}

	tokenName := ""
	tokenKey := ""
	if tokenFields, ok := splunkFields["token"].(map[string]any); ok {
		tokenName, _ = tokenFields["secretName"].(string)
		tokenKey, _ = tokenFields["secretKey"].(string)
	}
	endpointName := ""
	endpointKey := ""
	if endpointFields, ok := splunkFields["endpoint"].(map[string]any); ok {
		endpointName, _ = endpointFields["secretName"].(string)
		endpointKey, _ = endpointFields["secretKey"].(string)
	}

	exportDir := configValue(log, cmFields, "exportDirectory", "")

	resources := corev1.ResourceRequirements{}
	resourcesValue := configValue(log, splunkFields, "resources", "")
	if resourcesValue != "" {
		if err := yaml.Unmarshal([]byte(resourcesValue), &resources); err != nil {
			log.WithValues("value", resourcesValue).Error(err, "could not unmarshal the resources, default value used instead")
		}
	}
	mounts := []corev1.VolumeMount{
		{
			Name:      "otel-agent-config-vol",
			ReadOnly:  true,
			MountPath: "/conf",
		},
		{
			Name:      "export-logs",
			MountPath: exportDir,
		},
		{
			Name:      "file-storage",
			MountPath: "/var/lib/otelcol/file-storage",
		},
	}

	if tlsSecret(splunkFields) {
		mounts = append(mounts, corev1.VolumeMount{
			Name:      "otel-splunk-tls",
			MountPath: "/tls",
			ReadOnly:  true,
		})
	}

	return &corev1.Container{
		Name:    "tetragon-otel-agent",
		Image:   image,
		Command: []string{"/otelcol-contrib", "--config=/conf/otel-agent-config.yaml"},
		Args:    []string{},
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
						Name: tokenName,
						Key:  tokenKey,
					},
				},
			},
			{
				Name: "SPLUNK_HEC_ENDPOINT",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						Name: endpointName,
						Key:  endpointKey,
					},
				},
			},
		},
		Ports:                    []corev1.ContainerPort{},
		TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
		ImagePullPolicy:          corev1.PullIfNotPresent,
		VolumeMounts:             mounts,
		Resources:                resources,
		SecurityContext: &corev1.SecurityContext{
			AllowPrivilegeEscalation: new(false),
			Capabilities: &corev1.Capabilities{
				Drop: []corev1.Capability{"All"},
			},
			ReadOnlyRootFilesystem: new(true),
			RunAsUser:              new(int64(0)),
			RunAsGroup:             new(int64(0)),
		},
	}
}

func configValueInt(log logr.Logger, config map[string]any, key string, bitSize int, defaultValue int) int {
	value := configValue(log, config, key, "")
	if value == "" {
		return defaultValue
	}
	valueInt, err := strconv.ParseInt(value, 10, bitSize)
	if err != nil {
		log.WithValues("value", value).Error(err, fmt.Sprintf("could not parse the %s, default int value used instead", key))
		return defaultValue
	}
	return int(valueInt)
}

// tlsSecret returns true if a TLS secret should be mounted for the otel container.
// This mirrors the Helm logic in install/kubernetes/enterprise/templates/_extensions.tpl:
// - external secret: name is set AND at least one of ca_cert/client_cert/client_key is set
// - inline certs:    at least one of ca/crt/key is set
func tlsSecret(splunkConfig map[string]any) bool {
	tlsFields, ok := splunkConfig[tlsKey].(map[string]any)
	if !ok {
		return false
	}
	if secretFields, ok := tlsFields[tlsSecretKey].(map[string]any); ok {
		extName, _ := secretFields[tlsSecretNameKey].(string)
		if len(extName) > 0 {
			if keysFields, ok := secretFields[tlsSecretKeysKey].(map[string]any); ok {
				hasCA, _ := keysFields[tlsSecretCACertKey].(string)
				hasCert, _ := keysFields[tlsSecretClientCertKey].(string)
				hasKey, _ := keysFields[tlsSecretClientKeyKey].(string)
				if len(hasCA) > 0 || len(hasCert) > 0 || len(hasKey) > 0 {
					return true
				}
			}
		}
	}
	tlsInlineCA, _ := tlsFields[tlsCAKey].(string)
	tlsInlineCert, _ := tlsFields[tlsCertKey].(string)
	tlsInlineKey, _ := tlsFields[tlsKeyKey].(string)
	return len(tlsInlineCA) > 0 || len(tlsInlineCert) > 0 || len(tlsInlineKey) > 0
}

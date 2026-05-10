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
	_ "embed"

	"context"
	"fmt"
	"strconv"

	"github.com/go-logr/logr"
	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	"github.com/prometheus/common/model"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"
)

var (
	//go:embed manifests/servicemonitor-agent.yaml
	serviceMonitorAgentYAML string

	//go:embed manifests/service-agent.yaml
	serviceAgentYAML string

	//go:embed manifests/servicemonitor-operator.yaml
	serviceMonitorOperatorYAML string

	//go:embed manifests/service-operator.yaml
	serviceOperatorYAML string
)

type monitorServiceCfg struct {
	enabled                    bool
	monitorYAML                string
	serviceYAML                string
	monitorLabels              map[string]string
	monitorEndpointsInterval   monitoringv1.Duration
	serviceLabels              map[string]string
	serviceTargetPort          intstr.IntOrString
	serviceLabelSelectorLabels map[string]string
}

func createServiceMonitors(ctx context.Context, log logr.Logger, client client.Client, namespace string, cm *corev1.ConfigMap) error {
	monitors := map[string]func(log logr.Logger, cm *corev1.ConfigMap) (monitorServiceCfg, error){
		"agent":    agentMonitorCfg,
		"operator": operatorMonitorCfg,
	}
	for component, cfgFn := range monitors {
		cfg, err := cfgFn(log, cm)
		if err != nil {
			return err
		}

		if !cfg.enabled {
			log.Info(fmt.Sprintf("Tetragon %s ServiceMonitor disabled", component))
			continue
		}

		log.Info(fmt.Sprintf("creating Tetragon %s ServiceMonitor", component))
		monitor, err := serviceMonitor(log, namespace, cfg)
		if err != nil {
			return err
		}
		if err := client.Create(ctx, monitor); err != nil {
			if !apierrors.IsAlreadyExists(err) {
				return err
			}
			log.Info("Tetragon ServiceMonitor already exists")
		} else {
			log.Info("Tetragon ServiceMonitor has been created")
		}

		log.Info("creating Tetragon ServiceMonitor service")
		service, err := serviceMonitorService(log, namespace, cfg)
		if err != nil {
			return err
		}
		if err := client.Create(ctx, service); err != nil {
			if !apierrors.IsAlreadyExists(err) {
				return err
			}
			log.Info("Tetragon ServiceMonitor service already exists")
		} else {
			log.Info("Tetragon ServiceMonitor service has been created")
		}
	}
	return nil
}

func agentMonitorCfg(log logr.Logger, cm *corev1.ConfigMap) (monitorServiceCfg, error) {
	configYaml := cm.Data[OperatorConfigMapAgentDaemonSetKey]
	cmFields := make(map[string]any)
	if err := yaml.Unmarshal([]byte(configYaml), &cmFields); err != nil {
		log.WithValues("value", configYaml).Error(err, "could not unmarshal the DaemonSet configuration")
		return monitorServiceCfg{}, err
	}

	cfg := monitorServiceCfg{
		enabled:                    configValue(log, cmFields, "serviceMonitorEnabled", false),
		monitorYAML:                serviceMonitorAgentYAML,
		serviceYAML:                serviceAgentYAML,
		monitorLabels:              configMapOfString(log, cmFields, "serviceMonitorLabelsOverride"),
		monitorEndpointsInterval:   intervalDuration(log, configValue(log, cmFields, "serviceMonitorScrapeInterval", "")),
		serviceLabels:              configMapOfString(log, cmFields, "serviceLabelsOverride"),
		serviceTargetPort:          intstr.Parse(configValue(log, cmFields, "serviceMonitorPrometheusPort", "")),
		serviceLabelSelectorLabels: configMapOfString(log, cmFields, "labelsOverride"),
	}
	return cfg, nil
}

func operatorMonitorCfg(log logr.Logger, cm *corev1.ConfigMap) (monitorServiceCfg, error) {
	enabled, err := strconv.ParseBool(cm.Data["serviceMonitorEnabled"])
	if err != nil {
		log.WithValues("value", cm.Data["serviceMonitorEnabled"]).Error(err, "could not parse serviceMonitorEnabled, default value used instead")
	}

	cfg := monitorServiceCfg{
		enabled:                    enabled,
		monitorYAML:                serviceMonitorOperatorYAML,
		serviceYAML:                serviceOperatorYAML,
		monitorLabels:              ValuesAsMap(log, cm.Data["serviceMonitorLabelsOverride"]),
		monitorEndpointsInterval:   intervalDuration(log, cm.Data["serviceMonitorScrapeInterval"]),
		serviceLabels:              ValuesAsMap(log, cm.Data["serviceLabelsOverride"]),
		serviceTargetPort:          intstr.Parse(cm.Data["serviceMonitorPrometheusPort"]),
		serviceLabelSelectorLabels: map[string]string{},
	}
	return cfg, nil
}

func serviceMonitor(log logr.Logger, namespace string, cfg monitorServiceCfg) (*monitoringv1.ServiceMonitor, error) {
	var monitor *monitoringv1.ServiceMonitor
	if err := yaml.Unmarshal([]byte(cfg.monitorYAML), &monitor); err != nil {
		log.WithValues("value", cfg.monitorYAML).Error(err, "could not unmarshal the ServiceMonitor configuration")
		return nil, err
	}

	monitor.Namespace = namespace
	if len(cfg.monitorLabels) > 0 {
		monitor.Labels = cfg.monitorLabels
	}
	monitor.Spec.NamespaceSelector = monitoringv1.NamespaceSelector{
		MatchNames: []string{namespace},
	}
	monitor.Spec.Endpoints[0].Interval = cfg.monitorEndpointsInterval
	if len(cfg.serviceLabels) > 0 {
		monitor.Spec.Selector.MatchLabels = cfg.serviceLabels
	}
	return monitor, nil
}

func serviceMonitorService(log logr.Logger, namespace string, cfg monitorServiceCfg) (*corev1.Service, error) {
	var service *corev1.Service
	if err := yaml.Unmarshal([]byte(cfg.serviceYAML), &service); err != nil {
		log.WithValues("value", cfg.serviceYAML).Error(err, "could not unmarshal the ServiceMonitor service configuration")
		return nil, err
	}

	service.Namespace = namespace
	if len(cfg.serviceLabels) > 0 {
		service.Labels = cfg.serviceLabels
	}
	service.Spec.Ports[0].TargetPort = cfg.serviceTargetPort
	if len(cfg.serviceLabelSelectorLabels) > 0 {
		service.Spec.Selector = cfg.serviceLabelSelectorLabels
	}
	return service, nil
}

func intervalDuration(log logr.Logger, value string) monitoringv1.Duration {
	if _, err := model.ParseDuration(value); err != nil {
		log.WithValues("value", value).Error(err, "could not parse monitor interval, default value used instead")
		value = "10s"
	}
	return monitoringv1.Duration(value)
}

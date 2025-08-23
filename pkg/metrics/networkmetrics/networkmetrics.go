//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package networkmetrics

import (
	"strconv"

	"github.com/cilium/tetragon/pkg/metrics/consts"
	appModelV1 "github.com/isovalent/ipa/application_model/v1alpha"
	common "github.com/isovalent/ipa/common/k8s/type/v1alpha"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	metricsNamePrefix = "network_"
)

var (
	labels = []string{
		"policy",
		"rule",
		"namespace",
		"workload",
		"destination_type",
		"destination_name",
		"destination_port",
		"destination_namespace",
		"destination_workload",
		"protocol",
	}
	txBytesTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:      metricsNamePrefix + "txbytes_total",
		Namespace: consts.MetricsNamespace,
		Help:      "Number of bytes transmitted.",
	}, labels)
	droppedSessionsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:      metricsNamePrefix + "dropped_sessions_total",
		Namespace: consts.MetricsNamespace,
		Help:      "Number of sessions that got dropped by a Tetragon network policy rule.",
	}, labels)

	allowExample = appModelV1.NetworkConnectTelemetry{
		KubernetesNamespace:               consts.ExampleNamespace,
		KubernetesWorkloadName:            consts.ExampleWorkload,
		DestinationName:                   "default:WORKLOAD_KIND_SERVICE:kubernetes",
		DestinationType:                   appModelV1.DestinationType_DESTINATION_TYPE_KUBERNETES,
		DestinationPort:                   443,
		DestinationKubernetesNamespace:    "default",
		DestinationKubernetesWorkloadKind: common.WorkloadKind_WORKLOAD_KIND_UNSPECIFIED, //common.WorkloadKind_WORKLOAD_KIND_SERVICE,
		DestinationKubernetesResourceName: "kubernetes",
		Protocol:                          appModelV1.NetworkProtocolType_NETWORK_PROTOCOL_TYPE_TCP,
		PolicyName:                        "my-network-policy",
		RuleName:                          "Allow TCP traffic to Kubernetes API server on port 443",
		Verdict:                           appModelV1.PolicyVerdict_POLICY_VERDICT_ALLOW,
		TxBytes:                           1,
	}
	dropExample = appModelV1.NetworkConnectTelemetry{
		KubernetesNamespace:    consts.ExampleNamespace,
		KubernetesWorkloadName: consts.ExampleWorkload,
		DestinationName:        "bad.example.com",
		DestinationType:        appModelV1.DestinationType_DESTINATION_TYPE_DNS,
		DestinationPort:        80,
		Protocol:               appModelV1.NetworkProtocolType_NETWORK_PROTOCOL_TYPE_TCP,
		PolicyName:             "my-network-policy",
		RuleName:               "Drop TCP traffic to bad.example.com on port 80",
		Verdict:                appModelV1.PolicyVerdict_POLICY_VERDICT_DROP,
		TxBytes:                2,
	}
)

func InitMetrics(registry *prometheus.Registry) {
	registry.MustRegister(txBytesTotal)
	registry.MustRegister(droppedSessionsTotal)
}

func InitMetricsForDocs(registry *prometheus.Registry) {
	InitMetrics(registry)
	Collect(&allowExample)
	Collect(&dropExample)
}

func Collect(event *appModelV1.NetworkConnectTelemetry) {
	labels := prometheus.Labels{
		"policy":                event.PolicyName,
		"rule":                  event.RuleName,
		"namespace":             event.KubernetesNamespace,
		"workload":              event.KubernetesWorkloadName,
		"destination_type":      event.DestinationType.String(),
		"destination_name":      event.DestinationName,
		"destination_port":      strconv.Itoa(int(event.DestinationPort)),
		"destination_namespace": event.DestinationKubernetesNamespace,
		"destination_workload":  event.DestinationKubernetesResourceName,
		"protocol":              event.Protocol.String(),
	}
	if event.Verdict == appModelV1.PolicyVerdict_POLICY_VERDICT_DROP {
		droppedSessionsTotal.With(labels).Add(float64(event.Sessions))
	} else {
		txBytesTotal.With(labels).Add(float64(event.TxBytes))
	}
}

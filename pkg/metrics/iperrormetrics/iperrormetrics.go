//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package iperrormetrics

import (
	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	processIpErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:      "layer3_event_errors_total",
		Namespace: consts.MetricsNamespace,
		Help:      "Errors propagated to userspace by the L3 event sensors",
	}, []string{"error", "version"})
)

func ProcessIpErrors(err string, version string) prometheus.Counter {
	return processIpErrors.WithLabelValues(err, version)
}

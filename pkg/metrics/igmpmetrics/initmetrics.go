// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package igmpmetrics

import (
	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/prometheus/client_golang/prometheus"

	enterpriseMetrics "github.com/isovalent/hubble-fgs/pkg/metrics"
)

func InitMetrics(registry *prometheus.Registry) {
	// IGMP metrics
	registry.MustRegister(IgmpJoinsVol)
	registry.MustRegister(IgmpLeavesVol)
	registry.MustRegister(IgmpGroupMembershipVol)
}

func InitMetricsForDocs(registry *prometheus.Registry) {
	InitMetrics(registry)

	IgmpJoinsVol.WithLabelValues(append(consts.ExampleProcessLabels, enterpriseMetrics.ExampleGroupAddress)...).Add(0)
	IgmpLeavesVol.WithLabelValues(append(consts.ExampleProcessLabels, enterpriseMetrics.ExampleGroupAddress)...).Add(0)
	IgmpGroupMembershipVol.WithLabelValues(consts.ExampleNodeName, enterpriseMetrics.ExampleGroupAddress, enterpriseMetrics.ExampleIgmpMembershipReportType).Add(0)
}

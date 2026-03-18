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
	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/prometheus/client_golang/prometheus"
)

// ICMP socket metrics
var (
	IgmpJoinsVol = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "igmp_joins_total",
		Namespace: consts.MetricsNamespace,
		Help:      "The number of observed IGMP join messages",
	}, []string{"namespace", "workload", "pod", "binary", "node_name", "group_address"})
	IgmpLeavesVol = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "igmp_leaves_total",
		Namespace: consts.MetricsNamespace,
		Help:      "The number of observed IGMP leave messages",
	}, []string{"namespace", "workload", "pod", "binary", "node_name", "group_address"})
	IgmpGroupMembershipVol = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "igmp_group_membership_reports_total",
		Namespace: consts.MetricsNamespace,
		Help:      "The number of observed IGMP group membership messages",
	}, []string{"node_name", "group_address", "type"})
)

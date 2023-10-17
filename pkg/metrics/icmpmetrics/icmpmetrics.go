//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package icmpmetrics

import (
	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/prometheus/client_golang/prometheus"
)

// ICMP socket metrics
var (
	IcmpStatsVol = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "icmp_datagrams_total",
		Namespace: consts.MetricsNamespace,
		Help:      "The number of sent/received ICMP datagrams",
	}, []string{"namespace", "workload", "pod", "binary", "dstnamespace", "dstworkload", "dstpod", "dstdns"})
)

// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package socketmetrics

import (
	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/prometheus/client_golang/prometheus"
)

// Raw socket metrics
var (
	RawsockCreateVol = metrics.MustNewGranularCounter[metrics.ProcessLabels](prometheus.CounterOpts{
		Name:      "rawsock_create_total",
		Namespace: consts.MetricsNamespace,
		Help:      "The number of raw sockets created",
	}, nil)

	RawsockCloseVol = metrics.MustNewGranularCounter[metrics.ProcessLabels](prometheus.CounterOpts{
		Name:      "rawsock_close_total",
		Namespace: consts.MetricsNamespace,
		Help:      "The number of raw sockets closed",
	}, nil)
)

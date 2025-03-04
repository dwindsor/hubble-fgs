//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package tcpconfig

import (
	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/isovalent/hubble-fgs/pkg/sensors/networklatency"
)

var (
	MetricsEnabled  = false
	LatencyConfig   networklatency.ProtocolConfig
	RttHistogramMax uint32
	RttHistogramMin uint32
	CurrentLabels   = DefaultLabelFilter()
)

// The returned label filter should be kept in sync with:
// SocketLabels.Keys in pkg/metrics/socketmetrics
// createSocketLabels in pkg/metrics/eventmetrics
// TcpPolicySpec.Metrics docs in pkg/k8s (CRD)
func DefaultLabelFilter() metrics.LabelFilter {
	return metrics.LabelFilter{
		"namespace":    true,
		"workload":     true,
		"pod":          false,
		"binary":       true,
		"dstnamespace": true,
		"dstworkload":  true,
		"dstpod":       false,
		"dstdns":       true,
		"dstip":        false,
	}
}

func ClearConfig() {
	MetricsEnabled = false
	LatencyConfig.Enable = 0
	RttHistogramMax = 0
	RttHistogramMin = 0
	CurrentLabels = DefaultLabelFilter()
}

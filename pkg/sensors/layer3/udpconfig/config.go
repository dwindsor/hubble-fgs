// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package udpconfig

import (
	"sync"

	"github.com/cilium/tetragon/pkg/metrics"
)

const (
	UdpMapStatsName = "tg_l3_udpsk_cnt"
)

var (
	MetricsEnabled = false
	CurrentLabels  = DefaultLabelFilter()

	UdpMapRemoves       = int64(0)
	UdpMapRemovesUpdate sync.Mutex
)

// The returned label filter should be kept in sync with:
// SocketLabels.Keys and MulticastSocketLabels.Keys in pkg/metrics/socketmetrics
// createSocketLabels and createMulticastSocketLabels in pkg/metrics/eventmetrics
// UdpPolicySpec.Metrics docs in pkg/k8s (CRD)
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
		"srcmcast":     true,
		"dstmcast":     true,
		"dstip":        false,
	}
}

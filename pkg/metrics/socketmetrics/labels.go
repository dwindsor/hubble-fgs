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

import "github.com/cilium/tetragon/pkg/metrics"

type SocketLabels struct {
	metrics.ProcessLabels
	DstNs       string
	DstWorkload string
	DstPod      string
	DstDNS      string
	DstIp       string
}

func (s SocketLabels) Keys() []string {
	return append(s.ProcessLabels.Keys(), "dstnamespace", "dstworkload", "dstpod", "dstdns", "dstip")
}

func (s SocketLabels) Values() []string {
	return append(s.ProcessLabels.Values(), s.DstNs, s.DstWorkload, s.DstPod, s.DstDNS, s.DstIp)
}

func NewSocketLabels(ns, workload, pod, binary, dstns, dstworkload, dstpod, dstdns, dstip string) *SocketLabels {
	return &SocketLabels{
		ProcessLabels: *metrics.NewProcessLabels(ns, workload, pod, binary, ""),
		DstNs:         dstns,
		DstWorkload:   dstworkload,
		DstPod:        dstpod,
		DstDNS:        dstdns,
		DstIp:         dstip,
	}
}

type MulticastSocketLabels struct {
	metrics.ProcessLabels
	SrcMcast    string
	DstNs       string
	DstWorkload string
	DstPod      string
	DstMcast    string
}

func NewMulticastSocketLabels(ns, workload, pod, binary, srcmcast, dstns, dstworkload, dstpod, dstmcast string) *MulticastSocketLabels {
	return &MulticastSocketLabels{
		ProcessLabels: *metrics.NewProcessLabels(ns, workload, pod, binary, ""),
		SrcMcast:      srcmcast,
		DstNs:         dstns,
		DstWorkload:   dstworkload,
		DstPod:        dstpod,
		DstMcast:      dstmcast,
	}
}

func (s MulticastSocketLabels) Keys() []string {
	return append(s.ProcessLabels.Keys(), "srcmcast", "dstnamespace", "dstworkload", "dstpod", "dstmcast")
}

func (s MulticastSocketLabels) Values() []string {
	return append(s.ProcessLabels.Values(), s.SrcMcast, s.DstNs, s.DstWorkload, s.DstPod, s.DstMcast)
}

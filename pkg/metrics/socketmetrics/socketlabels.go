//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package socketmetrics

import "github.com/cilium/tetragon/pkg/metrics"

type SocketLabels struct {
	metrics.ProcessLabels
	dstNs       string
	dstWorkload string
	dstPod      string
	dstDNS      string
	dstIp       string
}

func (s SocketLabels) Keys() []string {
	return append(s.ProcessLabels.Keys(), "dstnamespace", "dstworkload", "dstpod", "dstdns", "dstip")
}

func (s SocketLabels) Values() []string {
	return append(s.ProcessLabels.Values(), s.dstNs, s.dstWorkload, s.dstPod, s.dstDNS, s.dstIp)
}

func NewSocketLabels(ns, workload, pod, binary, dstns, dstworkload, dstpod, dstdns, dstip string) *SocketLabels {
	return &SocketLabels{
		ProcessLabels: *metrics.NewProcessLabels(ns, workload, pod, binary),
		dstNs:         dstns,
		dstWorkload:   dstworkload,
		dstPod:        dstpod,
		dstDNS:        dstdns,
		dstIp:         dstip,
	}
}

type MulticastSocketLabels struct {
	metrics.ProcessLabels
	SrcMcast    string
	dstNs       string
	dstWorkload string
	dstPod      string
	DstMcast    string
}

func NewMulticastSocketLabels(ns, workload, pod, binary, srcmcast, dstns, dstworkload, dstpod, dstmcast string) *MulticastSocketLabels {
	return &MulticastSocketLabels{
		ProcessLabels: *metrics.NewProcessLabels(ns, workload, pod, binary),
		SrcMcast:      srcmcast,
		dstNs:         dstns,
		dstWorkload:   dstworkload,
		dstPod:        dstpod,
		DstMcast:      dstmcast,
	}
}

func (s MulticastSocketLabels) Keys() []string {
	return append(s.ProcessLabels.Keys(), "srcmcast", "dstnamespace", "dstworkload", "dstpod", "dstmcast")
}

func (s MulticastSocketLabels) Values() []string {
	return append(s.ProcessLabels.Values(), s.SrcMcast, s.dstNs, s.dstWorkload, s.dstPod, s.DstMcast)
}

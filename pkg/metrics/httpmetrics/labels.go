//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package httpmetrics

import (
	"github.com/cilium/tetragon/pkg/metrics"
)

type HTTPLabels struct {
	metrics.ProcessLabels
	DstNamespace string
	DstWorkload  string
	DstPod       string
	DstDNS       string
	Host         string
}

func (s HTTPLabels) Keys() []string {
	return append(s.ProcessLabels.Keys(), "dstnamespace", "dstworkload", "dstpod", "dstdns", "host")
}

func (s HTTPLabels) Values() []string {
	return append(s.ProcessLabels.Values(), s.DstNamespace, s.DstWorkload, s.DstPod, s.DstDNS, s.Host)
}

func NewHTTPLabels(ns, workload, pod, binary, dstnamespace, dstworkload, dstpod, dstdns, host string) *HTTPLabels {
	return &HTTPLabels{
		ProcessLabels: *metrics.NewProcessLabels(ns, workload, pod, binary),
		DstNamespace:  dstnamespace,
		DstWorkload:   dstworkload,
		DstPod:        dstpod,
		DstDNS:        dstdns,
		Host:          host,
	}
}

//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package eventmetrics

import (
	"fmt"
	"strings"

	"github.com/cilium/tetragon/api/v1/tetragon"
	oss "github.com/cilium/tetragon/pkg/metrics/eventmetrics"
	"github.com/isovalent/hubble-fgs/pkg/metrics/httpmetrics"
)

func postHttpStats(res *tetragon.ProcessHttp) {
	binary, pod, workload, ns := oss.GetProcessInfo(res.Process)
	dstPod := res.Socket.GetDestinationPod()
	dstpod, dstworkload, dstns := GetDstPodInfo(dstPod)
	dstLabels := strings.Join(res.Socket.DestinationNames, ",")

	http := res.Http
	code := fmt.Sprintf("%d", http.Response.Code)
	host := http.Request.Host

	// We may consider adding URI here as well, but without a configuration mechanism
	// to enable/disable it this could have poor scaling properties. Imagine a user
	// scanning for URIs behind a host.
	httpmetrics.HttpResponseTotal.WithLabelValues(ns, workload, pod, binary, dstns, dstworkload, dstpod, dstLabels, host, code).Inc()

	c := float64(http.Latency.AsDuration().Seconds())
	httpmetrics.HttpRequestDurationSeconds.WithLabelValues(ns, workload, pod, binary, dstns, dstworkload, dstpod, dstLabels, host).Observe(c)
}

func HandleHttpEvent(res *tetragon.ProcessHttp) {
	postHttpStats(res)
}

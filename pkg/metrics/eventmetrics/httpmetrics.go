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

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/isovalent/hubble-fgs/pkg/metrics/httpmetrics"
)

func postHttpStats(res *tetragon.ProcessHttp) {
	httpLabels := createHTTPLabels(res)
	var code string
	var latency float64
	if res.Http != nil {
		if res.Http.Response != nil {
			code = fmt.Sprintf("%d", res.Http.Response.Code)
		}
		if res.Http.Latency != nil {
			latency = float64(res.Http.Latency.AsDuration().Seconds())
		}
	}

	// We may consider adding URI here as well, but without a configuration mechanism
	// to enable/disable it this could have poor scaling properties. Imagine a user
	// scanning for URIs behind a host.
	httpmetrics.HttpResponseTotal.WithLabelValues(httpLabels, code).Inc()

	httpmetrics.HttpRequestDurationSeconds.WithLabelValues(httpLabels).Observe(latency)
}

func HandleHttpEvent(res *tetragon.ProcessHttp) {
	postHttpStats(res)
}

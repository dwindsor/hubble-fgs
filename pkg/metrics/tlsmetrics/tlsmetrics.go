//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package tlsmetrics

import (
	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	TlsHandshakeTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: consts.MetricNamePrefix + "tls_handshakes_total",
		Help: "TLS handshake statistics",
	}, []string{"namespace", "pod", "binaray", "version", "cipher", "sni_name"})
)

func GetNegotiatedVersion(tls *tetragon.Tls) string {
	// NegotiatedVersion field should always be set since for TLS <1.3 we are using
	// readertls.GetNegotiatedVersion to set the negotiated version field through version
	// discovery.
	return tls.NegotiatedVersion
}

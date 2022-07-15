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
	"strings"

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
	if tls.NegotiatedVersion != "" {
		// For TLS 1.3 the negotiated version field is set. Use it.
		return tls.NegotiatedVersion
	}
	// For <TLS 1.3 do version discovery
	return getNegotiatedVersion12(tls)
}

var (
	tlsVersion1_0 = "TLS1.0"
	tlsVersion1_1 = "TLS1.1"
	tlsVersion1_2 = "TLS1.2"
)

func getNegotiatedVersion12(tls *tetragon.Tls) string {
	c := tls.ClientVersion
	s := tls.ServerVersion

	// TLS version degrade to lowest common protocol support, so
	// walk through TLS versions starting at lowest and working
	// up checking if either client or server indicate the version.
	// If c or s have an unknown protocol we report that to ensure
	// we don't make an incorrect assumption.
	if strings.Contains(c, "unknown") {
		return c
	} else if strings.Contains(s, "unknown") {
		return s
	} else if c == tlsVersion1_0 || s == tlsVersion1_0 {
		return tlsVersion1_0
	} else if c == tlsVersion1_1 || s == tlsVersion1_1 {
		return tlsVersion1_1
	} else if c == tlsVersion1_2 || s == tlsVersion1_2 {
		return tlsVersion1_2
	} else {
		// We should never get here if we do lets use the
		// code below and we can count it in metrics because
		// it is unique from grpc layers unknown(#) syntax.
		return "unknown(c|s)"
	}
}

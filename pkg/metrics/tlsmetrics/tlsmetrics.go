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
	"fmt"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/cilium/tetragon/pkg/metrics/consts"
	oss "github.com/cilium/tetragon/pkg/metrics/eventmetrics"
	"github.com/isovalent/hubble-fgs/pkg/api/tlsapi"
	enterpriseMetrics "github.com/isovalent/hubble-fgs/pkg/metrics"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	tlsErrorsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:      "tls_errors_total",
		Namespace: consts.MetricsNamespace,
		Help:      "Errors encountered while processing TLS events. For internal use only.",
	}, []string{"error", "continuation"})

	tlsExpectedContinuationTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name:      "tls_expected_continutation_events_total",
		Namespace: consts.MetricsNamespace,
		Help:      "Expected number of TLS continuation events. For internal use only.",
	})

	tlsActualContinuationTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name:      "tls_actual_continutation_events_total",
		Namespace: consts.MetricsNamespace,
		Help:      "Actual number of TLS continuation events. For internal use only.",
	})

	tlsHandshakeTotal = metrics.MustNewGranularCounter[metrics.ProcessLabels](prometheus.CounterOpts{
		Name:      "tls_handshakes_total",
		Namespace: consts.MetricsNamespace,
		Help:      "TLS handshake statistics",
	}, []string{"version", "cipher", "sni_name"})
)

func InitHealthMetrics(registry *prometheus.Registry) {
	registry.MustRegister(tlsErrorsTotal)
	registry.MustRegister(tlsExpectedContinuationTotal)
	registry.MustRegister(tlsActualContinuationTotal)

	for er := range tlsErrorString {
		TlsErrorsTotal(er, false).Add(0)
		TlsErrorsTotal(er, true).Add(0)
	}
}

func InitEventsMetrics(registry *prometheus.Registry) {
	registry.MustRegister(tlsHandshakeTotal)
}

func InitEventsMetricsForDocs(registry *prometheus.Registry) {
	InitEventsMetrics(registry)

	for _, v := range tlsapi.KnownTLSVersions {
		// We could iterate over all known ciphers here, but that's a lot of ciphers.
		// Let's initialize only with one example cipher.
		processLabels := metrics.NewProcessLabels(consts.ExampleNamespace, consts.ExampleWorkload, consts.ExamplePod, consts.ExampleBinary)
		tlsHandshakeTotal.WithLabelValues(processLabels, v, "TLS_EXAMPLE_CIPHER", enterpriseMetrics.ExampleDomain).Add(0)
	}
}

// Maps TLS error codes to strings for display in metrics
var tlsErrorString = map[int]string{
	// The following codes are taken from pkg/api/tlsapi/tlsapi.go
	// TlsCertificateErrorBadHeader
	0x0001: "bad header",
	// TlsCertificateErrorLengthRead
	0x0100: "bad length read",
	// TlsCertificateErrorMissingError
	0x0200: "missing certificate",
	// TlsCertificateErrorCertRead
	0x0400: "failed to read certificate",
	// TlsCertificateErrorCertPartial
	0x0800: "partial certificate",
	// TlsCertificateErrorParseX509
	0x1000: "failed to parse X509 certificate",
	// TlsCertificateErrorSpuriousCerts
	0x2000: "unmatched continuation event",
}

func TlsHandshakeTotal(res *tetragon.Tls) prometheus.Counter {
	binary, pod, workload, ns := oss.GetProcessInfo(res.Process)
	processLabels := metrics.NewProcessLabels(ns, workload, pod, binary)
	version := getNegotiatedVersion(res)
	return tlsHandshakeTotal.WithLabelValues(processLabels, version, res.Cipher, res.SniName)
}

func TlsErrorsTotal(err int, continuation bool) prometheus.Counter {
	s, ok := tlsErrorString[err]
	if !ok {
		s = "unknown"
		logger.GetLogger().WithField("code", err).Warn("unknown TLS error")
	}
	return tlsErrorsTotal.WithLabelValues(s, fmt.Sprint(continuation))
}

func TlsExpectedContinuationTotal() prometheus.Counter {
	return tlsExpectedContinuationTotal
}

func TlsActualContinuationTotal() prometheus.Counter {
	return tlsActualContinuationTotal
}

func getNegotiatedVersion(tls *tetragon.Tls) string {
	// NegotiatedVersion field should always be set since for TLS <1.3 we are using
	// readertls.GetNegotiatedVersion to set the negotiated version field through version
	// discovery.
	return tls.NegotiatedVersion
}

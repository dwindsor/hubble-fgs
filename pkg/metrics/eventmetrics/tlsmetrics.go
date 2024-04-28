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
	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/metrics"
	oss "github.com/cilium/tetragon/pkg/metrics/eventmetrics"
	"github.com/isovalent/hubble-fgs/pkg/metrics/tlsmetrics"
)

func HandleTlsEvent(res *tetragon.Tls) {
	binary, pod, workload, ns := oss.GetProcessInfo(res.Process)
	processLabels := metrics.NewProcessLabels(ns, workload, pod, binary)
	version := getNegotiatedVersion(res)
	tlsmetrics.TlsHandshakeTotal.WithLabelValues(processLabels, version, res.Cipher, res.SniName)
}

func getNegotiatedVersion(tls *tetragon.Tls) string {
	// NegotiatedVersion field should always be set since for TLS <1.3 we are using
	// readertls.GetNegotiatedVersion to set the negotiated version field through version
	// discovery.
	return tls.NegotiatedVersion
}

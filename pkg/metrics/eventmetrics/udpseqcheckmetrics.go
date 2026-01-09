// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package eventmetrics

import (
	oss "github.com/cilium/tetragon/pkg/metrics/eventmetrics"

	"github.com/cilium/tetragon/api/v1/tetragon"

	"github.com/isovalent/hubble-fgs/pkg/metrics/socketmetrics"
)

func postProcessUdpSeqCheckErrors(res *tetragon.ProcessUdpSeqCheckError) {
	binary, pod, workload, ns := oss.GetProcessInfo(res.Process)
	socketmetrics.SocketStatsUDPSeqCheckErrors.WithLabelValues(ns, workload, pod, binary).Inc()
}

func HandleProcessUdpSeqCheckError(res *tetragon.ProcessUdpSeqCheckError) {
	postProcessUdpSeqCheckErrors(res)
}

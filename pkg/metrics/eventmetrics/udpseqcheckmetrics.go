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
	"github.com/cilium/tetragon/api/v1/tetragon"

	"github.com/isovalent/hubble-fgs/pkg/metrics/socketmetrics"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3/udpconfig"
)

func postProcessUdpSeqCheckErrors(res *tetragon.ProcessUdpSeqCheckError) {
	l := createProcessLabels(udpconfig.CurrentLabels, res.Process)
	socketmetrics.SocketStatsUDPSeqCheckErrors.WithLabelValues(l).Inc()
}

func HandleProcessUdpSeqCheckError(res *tetragon.ProcessUdpSeqCheckError) {
	postProcessUdpSeqCheckErrors(res)
}

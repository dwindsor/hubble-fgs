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
	"github.com/isovalent/hubble-fgs/pkg/metrics/socketmetrics"
	"github.com/isovalent/hubble-fgs/pkg/sensors/rawsock/rawsockconfig"
	"github.com/isovalent/hubble-fgs/pkg/sensors/tcp/tcpconfig"
	"github.com/isovalent/hubble-fgs/pkg/sensors/udp/udpconfig"
)

func postStatsEventSocketStats(res *tetragon.ProcessSockStats) {
	if res.Socket.Protocol == tetragon.SocketProtocol_TCP {
		l := createSocketLabels(tcpconfig.CurrentLabels, res)
		if tcpconfig.MetricsEnabled {
			postTCPSocketStats(l, res.Stats)
		}
	} else if res.Socket.Protocol == tetragon.SocketProtocol_UDP {
		l := createSocketLabels(udpconfig.CurrentLabels, res)
		if udpconfig.MetricsEnabled {
			postUDPSocketStats(l, res.Stats)
			postUDPMulticastSocketStats(res)
		}
	}
}

func HandleSocketEvent(res *tetragon.ProcessSockStats) {
	postStatsEventSocketStats(res)
}

func HandleRawsockCreateEvent(res *tetragon.ProcessRawsockCreate) {
	if !rawsockconfig.MetricsEnabled {
		return
	}
	l := createProcessLabels(rawsockconfig.CurrentLabels, res.Process)
	socketmetrics.RawsockCreateVol.WithLabelValues(l).Inc()
}

func HandleRawsockCloseEvent(res *tetragon.ProcessRawsockClose) {
	if !rawsockconfig.MetricsEnabled {
		return
	}
	l := createProcessLabels(rawsockconfig.CurrentLabels, res.Process)
	socketmetrics.RawsockCloseVol.WithLabelValues(l).Inc()
}

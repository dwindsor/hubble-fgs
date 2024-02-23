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
	"github.com/isovalent/hubble-fgs/pkg/sensors/tcp/tcpconfig"
	"github.com/isovalent/hubble-fgs/pkg/sensors/udp/udpconfig"
)

func postUDPBurstStats(l *srcSocketLabels, s *tetragon.ProcessNetworkBurst) {
	labelStrings := l.labelString()

	if s.Direction == "egress" {
		if s.BurstState == "start" {
			socketmetrics.SocketStatsUDPTxBursts.WithLabelValues(labelStrings...).Inc()
			socketmetrics.SocketStatsUDPTxWatermarksState.WithLabelValues(labelStrings...).Set(1)
		} else {
			socketmetrics.SocketStatsUDPTxWatermarksState.WithLabelValues(labelStrings...).Set(0)
		}
	} else {
		if s.BurstState == "start" {
			socketmetrics.SocketStatsUDPRxBursts.WithLabelValues(labelStrings...).Inc()
			socketmetrics.SocketStatsUDPRxWatermarksState.WithLabelValues(labelStrings...).Set(1)
		} else {
			socketmetrics.SocketStatsUDPRxWatermarksState.WithLabelValues(labelStrings...).Set(0)
		}
	}
}

func postTCPBurstStats(l *srcSocketLabels, s *tetragon.ProcessNetworkBurst) {
	labelStrings := l.labelString()

	if s.Direction == "egress" {
		if s.BurstState == "start" {
			socketmetrics.SocketStatsTxBursts.WithLabelValues(labelStrings...).Inc()
			socketmetrics.SocketStatsTxWatermarksState.WithLabelValues(labelStrings...).Set(1)
		} else {
			socketmetrics.SocketStatsTxWatermarksState.WithLabelValues(labelStrings...).Set(0)
		}
	} else {
		if s.BurstState == "start" {
			socketmetrics.SocketStatsRxBursts.WithLabelValues(labelStrings...).Inc()
			socketmetrics.SocketStatsTxWatermarksState.WithLabelValues(labelStrings...).Set(1)
		} else {
			socketmetrics.SocketStatsTxWatermarksState.WithLabelValues(labelStrings...).Set(0)
		}
	}
}

func postProcessNetworkBurstEventStats(res *tetragon.ProcessNetworkBurst) {
	switch res.Protocol {
	case tetragon.SocketProtocol_UDP.String():
		l := createSrcSocketLabels(res.Process)
		if udpconfig.MetricsEnabled {
			postUDPBurstStats(l, res)
		}
	case tetragon.SocketProtocol_TCP.String():
		l := createTCPSrcSocketLabels(res.Process)
		if tcpconfig.MetricsEnabled {
			postTCPBurstStats(l, res)
		}
	}
}

func HandleProcessBurstEvent(res *tetragon.ProcessNetworkBurst) {
	postProcessNetworkBurstEventStats(res)
}

func postUDPWatermarksBurstStats(l *srcSocketLabels, s *tetragon.ProcessNetworkWatermark) {
	labelStrings := l.labelString()

	if s.Direction == "egress" {
		if s.WatermarksState == "start" {
			socketmetrics.SocketStatsUDPTxBursts.WithLabelValues(labelStrings...).Inc()
			socketmetrics.SocketStatsUDPTxWatermarksState.WithLabelValues(labelStrings...).Set(1)
		} else {
			socketmetrics.SocketStatsUDPTxWatermarksState.WithLabelValues(labelStrings...).Set(0)
		}
	} else {
		if s.WatermarksState == "start" {
			socketmetrics.SocketStatsUDPRxBursts.WithLabelValues(labelStrings...).Inc()
			socketmetrics.SocketStatsUDPRxWatermarksState.WithLabelValues(labelStrings...).Set(1)
		} else {
			socketmetrics.SocketStatsUDPRxWatermarksState.WithLabelValues(labelStrings...).Set(0)
		}
	}
}

func postUDPWatermarksDipStats(l *srcSocketLabels, s *tetragon.ProcessNetworkWatermark) {
	labelStrings := l.labelString()

	if s.Direction == "egress" {
		if s.WatermarksState == "start" {
			socketmetrics.SocketStatsUDPTxDips.WithLabelValues(labelStrings...).Inc()
			socketmetrics.SocketStatsUDPTxWatermarksState.WithLabelValues(labelStrings...).Set(-1)
		} else {
			socketmetrics.SocketStatsUDPTxWatermarksState.WithLabelValues(labelStrings...).Set(0)
		}
	} else {
		if s.WatermarksState == "start" {
			socketmetrics.SocketStatsUDPRxDips.WithLabelValues(labelStrings...).Inc()
			socketmetrics.SocketStatsUDPRxWatermarksState.WithLabelValues(labelStrings...).Set(-1)
		} else {
			socketmetrics.SocketStatsUDPRxWatermarksState.WithLabelValues(labelStrings...).Set(0)
		}
	}
}

func postTCPWatermarksBurstStats(l *srcSocketLabels, s *tetragon.ProcessNetworkWatermark) {
	labelStrings := l.labelString()

	if s.Direction == "egress" {
		if s.WatermarksState == "start" {
			socketmetrics.SocketStatsTxBursts.WithLabelValues(labelStrings...).Inc()
			socketmetrics.SocketStatsTxWatermarksState.WithLabelValues(labelStrings...).Set(1)
		} else {
			socketmetrics.SocketStatsTxWatermarksState.WithLabelValues(labelStrings...).Set(0)
		}
	} else {
		if s.WatermarksState == "start" {
			socketmetrics.SocketStatsRxBursts.WithLabelValues(labelStrings...).Inc()
			socketmetrics.SocketStatsRxWatermarksState.WithLabelValues(labelStrings...).Set(1)
		} else {
			socketmetrics.SocketStatsRxWatermarksState.WithLabelValues(labelStrings...).Set(0)
		}
	}
}

func postTCPWatermarksDipStats(l *srcSocketLabels, s *tetragon.ProcessNetworkWatermark) {
	labelStrings := l.labelString()

	if s.Direction == "egress" {
		if s.WatermarksState == "start" {
			socketmetrics.SocketStatsTxDips.WithLabelValues(labelStrings...).Inc()
			socketmetrics.SocketStatsTxWatermarksState.WithLabelValues(labelStrings...).Set(-1)
		} else {
			socketmetrics.SocketStatsTxWatermarksState.WithLabelValues(labelStrings...).Set(0)
		}
	} else {
		if s.WatermarksState == "start" {
			socketmetrics.SocketStatsRxDips.WithLabelValues(labelStrings...).Inc()
			socketmetrics.SocketStatsRxWatermarksState.WithLabelValues(labelStrings...).Set(-1)
		} else {
			socketmetrics.SocketStatsRxWatermarksState.WithLabelValues(labelStrings...).Set(0)
		}
	}
}

func postProcessNetworkWatermarksEventStats(res *tetragon.ProcessNetworkWatermark) {
	switch res.Protocol {
	case tetragon.SocketProtocol_UDP.String():
		l := createSrcSocketLabels(res.Process)

		if !udpconfig.MetricsEnabled {
			break
		}
		if res.WatermarksType == "burst" {
			postUDPWatermarksBurstStats(l, res)
		} else {
			postUDPWatermarksDipStats(l, res)
		}

	case tetragon.SocketProtocol_TCP.String():
		l := createTCPSrcSocketLabels(res.Process)

		if !tcpconfig.MetricsEnabled {
			break
		}
		if res.WatermarksType == "burst" {
			postTCPWatermarksBurstStats(l, res)
		} else {
			postTCPWatermarksDipStats(l, res)
		}
	}
}

func HandleProcessWatermarksEvent(res *tetragon.ProcessNetworkWatermark) {
	postProcessNetworkWatermarksEventStats(res)
}

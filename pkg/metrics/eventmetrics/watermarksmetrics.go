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
	"github.com/isovalent/hubble-fgs/pkg/metrics/socketmetrics"
	"github.com/isovalent/hubble-fgs/pkg/sensors/tcp/tcpconfig"
	"github.com/isovalent/hubble-fgs/pkg/sensors/udp/udpconfig"
)

func createTCPSrcSocketLabels(res *tetragon.Process) *metrics.ProcessLabels {
	b, p, w, ns := oss.GetProcessInfo(res)

	if !tcpconfig.CurrentLabels["namespace"] {
		ns = ""
	}
	if !tcpconfig.CurrentLabels["workload"] {
		w = ""
	}
	if !tcpconfig.CurrentLabels["pod"] {
		p = ""
	}
	if !tcpconfig.CurrentLabels["binary"] {
		b = ""
	}

	return metrics.NewProcessLabels(ns, w, p, b)
}

func createUDPSrcSocketLabels(res *tetragon.Process) *metrics.ProcessLabels {
	b, p, w, ns := oss.GetProcessInfo(res)

	if !udpconfig.CurrentLabels["namespace"] {
		ns = ""
	}
	if !udpconfig.CurrentLabels["workload"] {
		w = ""
	}
	if !udpconfig.CurrentLabels["pod"] {
		p = ""
	}
	if !udpconfig.CurrentLabels["binary"] {
		b = ""
	}

	return metrics.NewProcessLabels(ns, w, p, b)
}

func postUDPBurstStats(l *metrics.ProcessLabels, s *tetragon.ProcessNetworkBurst) {
	if s.Direction == "egress" {
		if s.BurstState == "start" {
			socketmetrics.SocketStatsUDPTxBursts.WithLabelValues(l).Inc()
			socketmetrics.SocketStatsUDPTxWatermarksState.WithLabelValues(l).Set(1)
		} else {
			socketmetrics.SocketStatsUDPTxWatermarksState.WithLabelValues(l).Set(0)
		}
	} else {
		if s.BurstState == "start" {
			socketmetrics.SocketStatsUDPRxBursts.WithLabelValues(l).Inc()
			socketmetrics.SocketStatsUDPRxWatermarksState.WithLabelValues(l).Set(1)
		} else {
			socketmetrics.SocketStatsUDPRxWatermarksState.WithLabelValues(l).Set(0)
		}
	}
}

func postTCPBurstStats(l *metrics.ProcessLabels, s *tetragon.ProcessNetworkBurst) {
	if s.Direction == "egress" {
		if s.BurstState == "start" {
			socketmetrics.SocketStatsTxBursts.WithLabelValues(l).Inc()
			socketmetrics.SocketStatsTxWatermarksState.WithLabelValues(l).Set(1)
		} else {
			socketmetrics.SocketStatsTxWatermarksState.WithLabelValues(l).Set(0)
		}
	} else {
		if s.BurstState == "start" {
			socketmetrics.SocketStatsRxBursts.WithLabelValues(l).Inc()
			socketmetrics.SocketStatsTxWatermarksState.WithLabelValues(l).Set(1)
		} else {
			socketmetrics.SocketStatsTxWatermarksState.WithLabelValues(l).Set(0)
		}
	}
}

func postProcessNetworkBurstEventStats(res *tetragon.ProcessNetworkBurst) {
	switch res.Protocol {
	case tetragon.SocketProtocol_UDP.String():
		l := createUDPSrcSocketLabels(res.Process)
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

func postUDPWatermarksBurstStats(l *metrics.ProcessLabels, s *tetragon.ProcessNetworkWatermark) {
	if s.Direction == "egress" {
		if s.WatermarksState == "start" {
			socketmetrics.SocketStatsUDPTxBursts.WithLabelValues(l).Inc()
			socketmetrics.SocketStatsUDPTxWatermarksState.WithLabelValues(l).Set(1)
		} else {
			socketmetrics.SocketStatsUDPTxWatermarksState.WithLabelValues(l).Set(0)
		}
	} else {
		if s.WatermarksState == "start" {
			socketmetrics.SocketStatsUDPRxBursts.WithLabelValues(l).Inc()
			socketmetrics.SocketStatsUDPRxWatermarksState.WithLabelValues(l).Set(1)
		} else {
			socketmetrics.SocketStatsUDPRxWatermarksState.WithLabelValues(l).Set(0)
		}
	}
}

func postUDPWatermarksDipStats(l *metrics.ProcessLabels, s *tetragon.ProcessNetworkWatermark) {
	if s.Direction == "egress" {
		if s.WatermarksState == "start" {
			socketmetrics.SocketStatsUDPTxDips.WithLabelValues(l).Inc()
			socketmetrics.SocketStatsUDPTxWatermarksState.WithLabelValues(l).Set(-1)
		} else {
			socketmetrics.SocketStatsUDPTxWatermarksState.WithLabelValues(l).Set(0)
		}
	} else {
		if s.WatermarksState == "start" {
			socketmetrics.SocketStatsUDPRxDips.WithLabelValues(l).Inc()
			socketmetrics.SocketStatsUDPRxWatermarksState.WithLabelValues(l).Set(-1)
		} else {
			socketmetrics.SocketStatsUDPRxWatermarksState.WithLabelValues(l).Set(0)
		}
	}
}

func postTCPWatermarksBurstStats(l *metrics.ProcessLabels, s *tetragon.ProcessNetworkWatermark) {
	if s.Direction == "egress" {
		if s.WatermarksState == "start" {
			socketmetrics.SocketStatsTxBursts.WithLabelValues(l).Inc()
			socketmetrics.SocketStatsTxWatermarksState.WithLabelValues(l).Set(1)
		} else {
			socketmetrics.SocketStatsTxWatermarksState.WithLabelValues(l).Set(0)
		}
	} else {
		if s.WatermarksState == "start" {
			socketmetrics.SocketStatsRxBursts.WithLabelValues(l).Inc()
			socketmetrics.SocketStatsRxWatermarksState.WithLabelValues(l).Set(1)
		} else {
			socketmetrics.SocketStatsRxWatermarksState.WithLabelValues(l).Set(0)
		}
	}
}

func postTCPWatermarksDipStats(l *metrics.ProcessLabels, s *tetragon.ProcessNetworkWatermark) {
	if s.Direction == "egress" {
		if s.WatermarksState == "start" {
			socketmetrics.SocketStatsTxDips.WithLabelValues(l).Inc()
			socketmetrics.SocketStatsTxWatermarksState.WithLabelValues(l).Set(-1)
		} else {
			socketmetrics.SocketStatsTxWatermarksState.WithLabelValues(l).Set(0)
		}
	} else {
		if s.WatermarksState == "start" {
			socketmetrics.SocketStatsRxDips.WithLabelValues(l).Inc()
			socketmetrics.SocketStatsRxWatermarksState.WithLabelValues(l).Set(-1)
		} else {
			socketmetrics.SocketStatsRxWatermarksState.WithLabelValues(l).Set(0)
		}
	}
}

func postProcessNetworkWatermarksEventStats(res *tetragon.ProcessNetworkWatermark) {
	switch res.Protocol {
	case tetragon.SocketProtocol_UDP.String():
		l := createUDPSrcSocketLabels(res.Process)

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

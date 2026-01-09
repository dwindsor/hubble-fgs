// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package network

import (
	"github.com/cilium/tetragon/api/v1/tetragon"

	api "github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	"github.com/isovalent/hubble-fgs/pkg/api/ops"
)

func GetSocketStats(stats *api.MsgSocketStats) *tetragon.SocketStats {
	rttHist := &tetragon.Histogram{
		Sum: stats.Rtt.Sum,
	}

	if stats.Rtt.B99 > 0 ||
		stats.Rtt.B90 > 0 ||
		stats.Rtt.B75 > 0 ||
		stats.Rtt.B50 > 0 ||
		stats.Rtt.B25 > 0 ||
		stats.Rtt.B10 > 0 ||
		stats.Rtt.B01 > 0 ||
		stats.Rtt.B00 > 0 {
		bucket99 := &tetragon.HistogramBucket{
			Percentile: 99,
			Size:       1,
			Count:      stats.Rtt.B99,
		}
		bucket90 := &tetragon.HistogramBucket{
			Percentile: 90,
			Size:       9,
			Count:      stats.Rtt.B90,
		}
		bucket75 := &tetragon.HistogramBucket{
			Percentile: 75,
			Size:       15,
			Count:      stats.Rtt.B75,
		}
		bucket50 := &tetragon.HistogramBucket{
			Percentile: 50,
			Size:       25,
			Count:      stats.Rtt.B50,
		}
		bucket25 := &tetragon.HistogramBucket{
			Percentile: 25,
			Size:       25,
			Count:      stats.Rtt.B25,
		}
		bucket10 := &tetragon.HistogramBucket{
			Percentile: 10,
			Size:       15,
			Count:      stats.Rtt.B10,
		}
		bucket01 := &tetragon.HistogramBucket{
			Percentile: 1,
			Size:       9,
			Count:      stats.Rtt.B01,
		}
		bucket00 := &tetragon.HistogramBucket{
			Percentile: 0,
			Size:       1,
			Count:      stats.Rtt.B00,
		}

		rttHist.Buckets = []*tetragon.HistogramBucket{
			bucket00,
			bucket01,
			bucket10,
			bucket25,
			bucket50,
			bucket75,
			bucket90,
			bucket99,
		}
	}

	latencyHist := &tetragon.Histogram{
		Sum: stats.Latency.Sum,
	}

	if stats.Latency.B99 > 0 ||
		stats.Latency.B90 > 0 ||
		stats.Latency.B75 > 0 ||
		stats.Latency.B50 > 0 ||
		stats.Latency.B25 > 0 ||
		stats.Latency.B10 > 0 ||
		stats.Latency.B01 > 0 ||
		stats.Latency.B00 > 0 {
		bucket99 := &tetragon.HistogramBucket{
			Percentile: 99,
			Size:       1,
			Count:      stats.Latency.B99,
		}
		bucket90 := &tetragon.HistogramBucket{
			Percentile: 90,
			Size:       9,
			Count:      stats.Latency.B90,
		}
		bucket75 := &tetragon.HistogramBucket{
			Percentile: 75,
			Size:       15,
			Count:      stats.Latency.B75,
		}
		bucket50 := &tetragon.HistogramBucket{
			Percentile: 50,
			Size:       25,
			Count:      stats.Latency.B50,
		}
		bucket25 := &tetragon.HistogramBucket{
			Percentile: 25,
			Size:       25,
			Count:      stats.Latency.B25,
		}
		bucket10 := &tetragon.HistogramBucket{
			Percentile: 10,
			Size:       15,
			Count:      stats.Latency.B10,
		}
		bucket01 := &tetragon.HistogramBucket{
			Percentile: 1,
			Size:       9,
			Count:      stats.Latency.B01,
		}
		bucket00 := &tetragon.HistogramBucket{
			Percentile: 0,
			Size:       1,
			Count:      stats.Latency.B00,
		}

		latencyHist.Buckets = []*tetragon.HistogramBucket{
			bucket00,
			bucket01,
			bucket10,
			bucket25,
			bucket50,
			bucket75,
			bucket90,
			bucket99,
		}
	}

	return &tetragon.SocketStats{
		BytesSubmitted:   stats.BytesSent,
		BytesConsumed:    stats.BytesReceived,
		BytesSent:        stats.BytesSent,
		BytesReceived:    stats.BytesReceived,
		SegsConsumed:     stats.SegsIn,
		SegsIn:           stats.SegsIn,
		SegsSubmitted:    stats.SegsOut,
		SegsOut:          stats.SegsOut,
		Srtt:             stats.Srtt,
		RetransmitsBytes: stats.RetransmitBytes,
		RetransmitsSegs:  stats.RetransmitSegs,
		ToZeroWindow:     stats.ZeroWindow,
		SkDrop:           stats.SkDrops,
		Rtt:              rttHist,
		Latency:          latencyHist,
	}
}

func MsgOpToProtocol(op uint8) tetragon.SocketProtocol {
	switch op {
	case ops.MSG_OP_TCPCONNECT,
		ops.MSG_OP_TCPCONNECTRET,
		ops.MSG_OP_TCPCLOSE,
		ops.MSG_OP_BIND,
		ops.MSG_OP_LISTEN,
		ops.MSG_OP_ACCEPT,
		ops.MSG_OP_TCPSTATS:
		return tetragon.SocketProtocol_TCP
	case ops.MSG_OP_UDPCONNECT,
		ops.MSG_OP_UDPCLOSE,
		ops.MSG_OP_UDPSTATS,
		ops.MSG_OP_UDPLISTEN:
		return tetragon.SocketProtocol_UDP
	case ops.MSG_OP_ICMP:
		return tetragon.SocketProtocol_ICMP
	case ops.MSG_OP_ICMPV6:
		return tetragon.SocketProtocol_ICMPV6
	default:
		return tetragon.SocketProtocol_UNKNOWN
	}
}

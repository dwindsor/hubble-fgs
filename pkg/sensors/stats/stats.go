package stats

import (
	api "github.com/isovalent/hubble-fgs/pkg/api/networkapi"
)

func MsgToSocketStatsUnix(m *api.MsgSocketStats, rtt bool) api.MsgSocketStatsUnix {
	var rttHistogram api.Histogram

	if rtt {
		rttHistogram = api.Histogram{
			B00: m.Buckets[0],
			B01: m.Buckets[1],
			B10: m.Buckets[2],
			B25: m.Buckets[3],
			B50: m.Buckets[4],
			B75: m.Buckets[5],
			B90: m.Buckets[6],
			B99: m.Buckets[7],
		}
	}

	return api.MsgSocketStatsUnix{
		BytesSubmitted:   0,
		BytesSent:        m.BytesSent,
		BytesConsumed:    0,
		BytesReceived:    m.BytesReceived,
		ConsumedSegs:     0,
		SegsIn:           m.SegsIn,
		SubmittedSegs:    0,
		SegsOut:          m.SegsOut,
		SRtt:             m.SRtt / 8, // TCP srtt_us is reported <<3 in usecs
		RetransmitSegs:   m.RetransmitSegs,
		RetransmitBytes:  m.RetransmitBytes,
		ToZeroWindow:     m.ToZeroWindow,
		SkDrop:           m.SkDrop,
		SkbConsumeMisses: m.SkbConsumeMisses,
		Rtt:              rttHistogram,
	}
}

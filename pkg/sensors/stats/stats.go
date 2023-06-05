package stats

import (
	api "github.com/isovalent/hubble-fgs/pkg/api/networkapi"
)

func MsgToSocketStatsUnix(m *api.MsgSocketStats, rtt bool, latency bool) api.MsgSocketStatsUnix {
	message := api.MsgSocketStatsUnix{
		BytesSubmitted:   m.BytesSubmitted,
		BytesSent:        m.BytesSent,
		BytesConsumed:    m.BytesConsumed,
		BytesReceived:    m.BytesReceived,
		ConsumedSegs:     m.SegsConsumed,
		SegsIn:           m.SegsIn,
		SubmittedSegs:    m.SegsSubmitted,
		SegsOut:          m.SegsOut,
		SRtt:             m.SRtt / 8, // TCP srtt_us is reported <<3 in usecs
		RetransmitSegs:   m.RetransmitSegs,
		RetransmitBytes:  m.RetransmitBytes,
		ToZeroWindow:     m.ToZeroWindow,
		SkDrop:           m.SkDrop,
		SkbConsumeMisses: m.SkbConsumeMisses,
		Ktime:            m.Ktime,
	}

	if rtt {
		histogram := api.Histogram{
			B00: m.RttBuckets[0],
			B01: m.RttBuckets[1],
			B10: m.RttBuckets[2],
			B25: m.RttBuckets[3],
			B50: m.RttBuckets[4],
			B75: m.RttBuckets[5],
			B90: m.RttBuckets[6],
			B99: m.RttBuckets[7],
			Sum: m.RttSum,
		}
		message.Rtt = histogram
	}
	if latency {
		histogram := api.Histogram{
			B00: m.LatencyBuckets[0],
			B01: m.LatencyBuckets[1],
			B10: m.LatencyBuckets[2],
			B25: m.LatencyBuckets[3],
			B50: m.LatencyBuckets[4],
			B75: m.LatencyBuckets[5],
			B90: m.LatencyBuckets[6],
			B99: m.LatencyBuckets[7],
			Sum: m.LatencySum,
		}
		message.Latency = histogram
	}

	return message
}

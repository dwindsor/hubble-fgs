package stats

import (
	api "github.com/isovalent/hubble-fgs/pkg/api/networkapi"
)

func MsgToSocketStatsUnix(m *api.MsgSocketStats, rtt bool, udpLatency bool) api.MsgSocketStatsUnix {
	var histogram api.Histogram

	if rtt || udpLatency {
		histogram = api.Histogram{
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
		message.Rtt = histogram
	} else if udpLatency {
		message.UdpLatency = histogram
	}

	return message
}

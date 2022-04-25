package stats

import "github.com/isovalent/hubble-fgs/pkg/api"

func MsgToSocketStatsUnix(m *api.MsgSocketStats) api.MsgSocketStatsUnix {
	return api.MsgSocketStatsUnix{
		BytesSubmitted:  0,
		BytesSent:       m.BytesSent,
		BytesConsumed:   0,
		BytesReceived:   m.BytesReceived,
		ConsumedSegs:    0,
		SegsIn:          m.SegsIn,
		SubmittedSegs:   0,
		SegsOut:         m.SegsOut,
		SRtt:            m.SRtt,
		RetransmitSegs:  m.RetransmitSegs,
		RetransmitBytes: m.RetransmitBytes,
		ToZeroWindow:    m.ToZeroWindow,
		SkDrop:          m.SkDrop,
	}
}

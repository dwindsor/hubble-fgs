package grpc

import (
	"github.com/isovalent/hubble-fgs/api/v1/fgs"
	"github.com/isovalent/hubble-fgs/pkg/api"
)

func (pm *ProcessManager) handleKfreeSkbMessage(msg *api.MsgKfreeSkbUnix) *fgs.GetEventsResponse {
	var res *fgs.GetEventsResponse
	switch msg.Common.Op {
	case api.MSG_OP_KFREE_SKB:
		pm.log.Warn("TODO: handle kfree_skb message")
	default:
		pm.log.WithField("message", msg).Warn("Unhandled event")
	}
	return res
}

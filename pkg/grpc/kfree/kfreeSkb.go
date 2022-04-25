package kfree

import (
	"github.com/isovalent/hubble-fgs/api/v1/fgs"
	"github.com/isovalent/hubble-fgs/pkg/api"
	"github.com/isovalent/hubble-fgs/pkg/api/ops"
	"github.com/isovalent/hubble-fgs/pkg/logger"
)

func HandleKfreeSkbMessage(msg *api.MsgKfreeSkbUnix) *fgs.GetEventsResponse {
	var res *fgs.GetEventsResponse
	switch msg.Common.Op {
	case ops.MSG_OP_KFREE_SKB:
		logger.GetLogger().Warn("TODO: handle kfree_skb message")
	default:
		logger.GetLogger().WithField("message", msg).Warn("Unhandled event")
	}
	return res
}

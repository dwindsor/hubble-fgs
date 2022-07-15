package kfree

import (
	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/logger"
	api "github.com/isovalent/hubble-fgs/pkg/api/kfreeapi"
	"github.com/isovalent/hubble-fgs/pkg/api/ops"
)

func HandleKfreeSkbMessage(msg *api.MsgKfreeSkbUnix) *tetragon.GetEventsResponse {
	var res *tetragon.GetEventsResponse
	switch msg.Common.Op {
	case ops.MSG_OP_KFREE_SKB:
		logger.GetLogger().Warn("TODO: handle kfree_skb message")
	default:
		logger.GetLogger().WithField("message", msg).Warn("HandleKfreeSkbMessage: Unhandled event")
	}
	return res
}

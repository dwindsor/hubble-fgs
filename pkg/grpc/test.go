package grpc

import (
	"github.com/isovalent/hubble-fgs/api/v1/fgs"
	"github.com/isovalent/hubble-fgs/pkg/api"
	"github.com/isovalent/hubble-fgs/pkg/ktime"
	"github.com/isovalent/hubble-fgs/pkg/logger"
)

func (pm *ProcessManager) handleTestMessage(msg *api.MsgTestEventUnix) *fgs.GetEventsResponse {
	var res *fgs.GetEventsResponse
	switch msg.Common.Op {
	case api.MSG_OP_TEST:
		res = &fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_Test{Test: &fgs.Test{
				Arg0: msg.Arg0,
				Arg1: msg.Arg1,
				Arg2: msg.Arg2,
				Arg3: msg.Arg3,
			}},
			NodeName: pm.nodeName,
			Time:     ktime.ToProto(msg.Common.Ktime),
		}
	default:
		logger.GetLogger().WithField("message", msg).Warn("Unhandled event")
	}
	return res
}

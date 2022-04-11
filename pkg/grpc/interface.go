package grpc

import (
	"github.com/isovalent/hubble-fgs/api/v1/fgs"
	"github.com/isovalent/hubble-fgs/pkg/api"
	"github.com/isovalent/hubble-fgs/pkg/ktime"
)

func (pm *ProcessManager) GetInterfaceStats(msg *api.MsgInterfaceEventUnix) *fgs.InterfaceStats {
	fgsEvent := &fgs.InterfaceStats{
		InterfaceName:    msg.Iface.Name,
		InterfaceIfindex: uint32(msg.Iface.Index),
		Netns:            msg.Iface.Netns,
		ContainerName:    msg.Iface.ContainerName,
		BytesSent:        msg.Stats.BytesSent,
		BytesReceived:    msg.Stats.BytesReceived,
		PacketsSent:      msg.Stats.PacketsSent,
		PacketsReceived:  msg.Stats.PacketsReceived,
		TxErrors:         msg.Stats.TxErrors,
		RxErrors:         msg.Stats.RxErrors,
		TxDrops:          msg.Stats.TxDrops,
		RxDrops:          msg.Stats.RxDrops,
	}
	return fgsEvent
}

func (pm *ProcessManager) handleInterfaceMessage(msg *api.MsgInterfaceEventUnix) *fgs.GetEventsResponse {
	var res *fgs.GetEventsResponse
	switch msg.Common.Op {
	case api.MSG_OP_INTERFACE_STATS:
		stats := pm.GetInterfaceStats(msg)
		if stats != nil {
			res = &fgs.GetEventsResponse{
				Event:    &fgs.GetEventsResponse_InterfaceStats{InterfaceStats: stats},
				NodeName: pm.nodeName,
				Time:     ktime.ToProto(msg.Common.Ktime),
			}
		}
	default:
		pm.log.WithField("message", msg).Warn("Unhandled event")
	}
	return res
}

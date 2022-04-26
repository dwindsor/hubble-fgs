package iface

import (
	"github.com/isovalent/hubble-fgs/api/v1/fgs"
	api "github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	"github.com/isovalent/hubble-fgs/pkg/api/ops"
	"github.com/isovalent/hubble-fgs/pkg/ktime"
	"github.com/isovalent/hubble-fgs/pkg/logger"
	"github.com/isovalent/hubble-fgs/pkg/reader"
)

var (
	nodeName = reader.GetNodeNameForExport()
)

func getInterfaceStats(msg *api.MsgInterfaceEventUnix) *fgs.InterfaceStats {
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

func HandleInterfaceMessage(msg *api.MsgInterfaceEventUnix) *fgs.GetEventsResponse {
	var res *fgs.GetEventsResponse
	switch msg.Common.Op {
	case ops.MSG_OP_INTERFACE_STATS:
		stats := getInterfaceStats(msg)
		if stats != nil {
			res = &fgs.GetEventsResponse{
				Event:    &fgs.GetEventsResponse_InterfaceStats{InterfaceStats: stats},
				NodeName: nodeName,
				Time:     ktime.ToProto(msg.Common.Ktime),
			}
		}
	default:
		logger.GetLogger().WithField("message", msg).Warn("Unhandled event")
	}
	return res
}

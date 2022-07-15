package iface

import (
	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/ktime"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/reader/node"
	api "github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	"github.com/isovalent/hubble-fgs/pkg/api/ops"
)

var (
	nodeName = node.GetNodeNameForExport()
)

func (msg *MsgInterfaceEventUnix) getInterfaceStats() *tetragon.InterfaceStats {
	fgsEvent := &tetragon.InterfaceStats{
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

type MsgInterfaceEventUnix struct {
	Common processapi.MsgCommon
	Kube   processapi.MsgK8sUnix
	Iface  api.MsgInterface
	Stats  api.MsgInterfaceStats
}

func (msg *MsgInterfaceEventUnix) HandleMessage() *tetragon.GetEventsResponse {
	var res *tetragon.GetEventsResponse
	switch msg.Common.Op {
	case ops.MSG_OP_INTERFACE_STATS:
		stats := msg.getInterfaceStats()
		if stats != nil {
			res = &tetragon.GetEventsResponse{
				Event:    &tetragon.GetEventsResponse_InterfaceStats{InterfaceStats: stats},
				NodeName: nodeName,
				Time:     ktime.ToProto(msg.Common.Ktime),
			}
		}
	default:
		logger.GetLogger().WithField("message", msg).Warn("HandleInterfaceMessage: Unhandled event")
	}
	return res
}

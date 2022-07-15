package burst

import (
	"syscall"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/ktime"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/process"
	"github.com/cilium/tetragon/pkg/reader/node"
	"github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	"github.com/isovalent/hubble-fgs/pkg/api/ops"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var (
	nodeName = node.GetNodeNameForExport()
)

type MsgProcessNetworkBurstEventUnix struct {
	networkapi.MsgProcessNetworkBurstEvent
}

func (msg *MsgProcessNetworkBurstEventUnix) HandleMessage() *tetragon.GetEventsResponse {
	var res *tetragon.GetEventsResponse
	switch msg.Common.Op {
	case ops.MSG_OP_PROCESS_NETWORK_BURST:
		b := getProcessNetworkBurst(msg)
		if b != nil {
			res = &tetragon.GetEventsResponse{
				Event:    &tetragon.GetEventsResponse_ProcessNetworkBurst{ProcessNetworkBurst: b},
				NodeName: nodeName,
				Time:     ktime.ToProto(msg.Common.Ktime),
			}
		}

	default:
		logger.GetLogger().WithField("message", msg).Warn("HandleProcessNetworkBurstMessage: Unhandled event")
	}
	return res
}

// getProcessNetworkBurst returns ProcessNetworkBurst protobuf message for a given process.
func getProcessNetworkBurst(
	event *MsgProcessNetworkBurstEventUnix,
) *tetragon.ProcessNetworkBurst {
	var fgsProcess, fgsParent *tetragon.Process

	process, parent := process.GetParentProcessInternal(event.ProcessKey.Pid, event.ProcessKey.Ktime)
	if process != nil {
		fgsProcess = process.GetProcessCopy()
	} else {
		fgsProcess = &tetragon.Process{
			Pid:       &wrapperspb.UInt32Value{Value: event.ProcessKey.Pid},
			StartTime: ktime.ToProto(event.ProcessKey.Ktime),
		}
	}
	if parent != nil {
		fgsParent = parent.GetProcessCopy()
	}
	fgsEvent := &tetragon.ProcessNetworkBurst{
		Process: fgsProcess,
		Parent:  fgsParent,
	}

	switch event.Protocol {
	case syscall.IPPROTO_UDP:
		fgsEvent.Protocol = "UDP"
	case syscall.IPPROTO_TCP:
		fgsEvent.Protocol = "TCP"
	default:
		fgsEvent.Protocol = "unknown"
	}
	if (event.BurstStartDir >> 16) == 0 {
		fgsEvent.Direction = "ingress"
	} else {
		fgsEvent.Direction = "egress"
	}
	if (event.BurstStartDir & 1) != 0 {
		fgsEvent.BurstState = "start"
	} else {
		fgsEvent.BurstState = "end"
	}
	fgsEvent.WindowSize = event.WindowSize
	fgsEvent.HistAvg = event.HistAvg
	fgsEvent.HistTrigger = event.HistTrigger
	fgsEvent.WindowAvg = event.WindowAvg

	return fgsEvent
}

package grpc

import (
	"syscall"

	"github.com/isovalent/hubble-fgs/api/v1/fgs"
	"github.com/isovalent/hubble-fgs/pkg/api"
	fgsAPI "github.com/isovalent/hubble-fgs/pkg/api"
	"github.com/isovalent/hubble-fgs/pkg/ktime"
	"github.com/isovalent/hubble-fgs/pkg/logger"
	"github.com/isovalent/hubble-fgs/pkg/process"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func (pm *ProcessManager) handleProcessNetworkBurstMessage(msg *api.MsgProcessNetworkBurstEventUnix) *fgs.GetEventsResponse {
	var res *fgs.GetEventsResponse
	switch msg.Common.Op {
	case api.MSG_OP_IPV4_PROCESS_BURST:
		b := pm.GetProcessNetworkBurst(msg)
		if b != nil {
			res = &fgs.GetEventsResponse{
				Event:    &fgs.GetEventsResponse_ProcessNetworkBurst{ProcessNetworkBurst: b},
				NodeName: pm.nodeName,
				Time:     ktime.ToProto(msg.Common.Ktime),
			}
		}

	default:
		logger.GetLogger().WithField("message", msg).Warn("Unhandled event")
	}
	return res
}

// GetProcessNetworkBurst returns ProcessNetworkBurst protobuf message for a given process.
func (pm *ProcessManager) GetProcessNetworkBurst(
	event *fgsAPI.MsgProcessNetworkBurstEventUnix,
) *fgs.ProcessNetworkBurst {
	var fgsProcess, fgsParent *fgs.Process

	process, parent := process.GetParentProcessInternal(event.ProcessKey.Pid, event.ProcessKey.Ktime)
	if process != nil {
		fgsProcess = process.GetProcessCopy()
	} else {
		fgsProcess = &fgs.Process{
			Pid:       &wrapperspb.UInt32Value{Value: event.ProcessKey.Pid},
			StartTime: ktime.ToProto(event.ProcessKey.Ktime),
		}
	}
	if parent != nil {
		fgsParent = parent.GetProcessCopy()
	}
	fgsEvent := &fgs.ProcessNetworkBurst{
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

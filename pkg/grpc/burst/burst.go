package burst

import (
	"syscall"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/eventcache"
	"github.com/cilium/tetragon/pkg/ktime"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/metrics/errormetrics"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/process"
	"github.com/cilium/tetragon/pkg/reader/node"
	"github.com/cilium/tetragon/pkg/reader/notify"
	"github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	"github.com/isovalent/hubble-fgs/pkg/api/ops"
	"github.com/isovalent/hubble-fgs/pkg/metrics/eventmetrics"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var (
	nodeName = node.GetNodeNameForExport()
)

type MsgProcessNetworkBurstEventUnix struct {
	networkapi.MsgProcessNetworkBurstEvent
}

func (msg *MsgProcessNetworkBurstEventUnix) RetryInternal(ev notify.Event, timestamp uint64) (*process.ProcessInternal, error) {
	p := ev.GetProcess()
	return eventcache.HandleGenericInternal(ev, p.Pid.Value, timestamp)
}

func (msg *MsgProcessNetworkBurstEventUnix) Retry(internal *process.ProcessInternal, ev notify.Event) error {
	p := internal.UnsafeGetProcess()
	if option.Config.EnableK8s && p.Pod == nil {
		errormetrics.ErrorTotalInc(errormetrics.EventCachePodInfoRetryFailed)
		return eventcache.ErrFailedToGetPodInfo
	}

	ev.SetProcess(internal.GetProcessCopy())

	// For burst events we need to account for metrics skipped
	// by original handling of event
	switch msg.Common.Op {
	case ops.MSG_OP_PROCESS_NETWORK_BURST:
		createProcessNetworkBurst(msg, false)
	}

	return nil
}

func (msg *MsgProcessNetworkBurstEventUnix) Notify() bool {
	return true
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

func (msg *MsgProcessNetworkBurstEventUnix) Cast(o interface{}) notify.Message {
	return &MsgProcessNetworkBurstEventUnix{}
}

// getProcessNetworkBurst returns ProcessNetworkBurst protobuf message for a given process.
func createProcessNetworkBurst(
	event *MsgProcessNetworkBurstEventUnix, cache bool,
) *tetragon.ProcessNetworkBurst {
	var fgsProcess, fgsParent *tetragon.Process

	process, parent := process.GetParentProcessInternal(event.ProcessKey.Pid, event.ProcessKey.Ktime)
	if process == nil {
		fgsProcess = &tetragon.Process{
			Pid:       &wrapperspb.UInt32Value{Value: event.ProcessKey.Pid},
			StartTime: ktime.ToProto(event.ProcessKey.Ktime),
		}
	} else {
		fgsProcess = process.UnsafeGetProcess()
	}
	if parent != nil {
		fgsParent = parent.UnsafeGetProcess()
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

	ec := eventcache.Get()
	if cache && ec != nil && (ec.Needed(fgsProcess) || (fgsProcess.Pid.Value > 1 && ec.Needed(fgsParent))) {
		ec.Add(nil, fgsEvent, event.ProcessKey.Ktime, event)
		return nil
	}
	if process != nil {
		fgsEvent.Process = process.GetProcessCopy()
	}
	if parent != nil {
		fgsEvent.Parent = parent.GetProcessCopy()
	}

	eventmetrics.HandleProcessBurstEvent(fgsEvent)
	return fgsEvent
}

func getProcessNetworkBurst(
	event *MsgProcessNetworkBurstEventUnix,
) *tetragon.ProcessNetworkBurst {
	return createProcessNetworkBurst(event, true)
}

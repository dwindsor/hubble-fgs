package networkWatermarks

import (
	"syscall"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/eventcache"
	"github.com/cilium/tetragon/pkg/ktime"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/process"
	"github.com/cilium/tetragon/pkg/reader/notify"
	"github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	"github.com/isovalent/hubble-fgs/pkg/api/ops"
	"github.com/isovalent/hubble-fgs/pkg/metrics/eventmetrics"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const (
	WATERMARKS_INGRESS = 0
	WATERMARKS_EGRESS  = 1
	WATERMARKS_END     = 0
	WATERMARKS_START   = 1
	WATERMARKS_BURST   = 0
	WATERMARKS_DIP     = 1
)

type MsgProcessNetworkWatermarksEventUnix struct {
	Msg *networkapi.MsgProcessNetworkWatermarkEvent
}

func (msg *MsgProcessNetworkWatermarksEventUnix) RetryInternal(ev notify.Event, timestamp uint64) (*process.ProcessInternal, error) {
	p := ev.GetProcess()
	return eventcache.HandleGenericInternal(ev, p.Pid.Value, nil, timestamp)
}

func (msg *MsgProcessNetworkWatermarksEventUnix) Retry(internal *process.ProcessInternal, ev notify.Event) error {
	p := internal.UnsafeGetProcess()
	if option.Config.EnableK8s && p.Pod == nil {
		eventcache.CacheRetries(eventcache.PodInfo).Inc()
		return eventcache.ErrFailedToGetPodInfo
	}

	ev.SetProcess(internal.UnsafeGetProcess())

	// For burst events we need to account for metrics skipped
	// by original handling of event
	switch msg.Msg.Common.Op {
	case ops.MSG_OP_PROCESS_NETWORK_WATERMARK:
		createProcessNetworkWatermarks(msg, false)
	case ops.MSG_OP_PROCESS_NETWORK_BURST:
		createProcessNetworkBurst(msg, false)
	}

	return nil
}

func (msg *MsgProcessNetworkWatermarksEventUnix) Notify() bool {
	return true
}

func (msg *MsgProcessNetworkWatermarksEventUnix) HandleMessage() *tetragon.GetEventsResponse {
	var res *tetragon.GetEventsResponse
	switch msg.Msg.Common.Op {
	case ops.MSG_OP_PROCESS_NETWORK_WATERMARK:
		b := getProcessNetworkWatermarks(msg)
		if b != nil {
			res = &tetragon.GetEventsResponse{
				Event: &tetragon.GetEventsResponse_ProcessNetworkWatermark{ProcessNetworkWatermark: b},
				Time:  ktime.ToProto(msg.Msg.Common.Ktime),
			}
		}
	case ops.MSG_OP_PROCESS_NETWORK_BURST:
		b := getProcessNetworkBurst(msg)
		if b != nil {
			res = &tetragon.GetEventsResponse{
				Event: &tetragon.GetEventsResponse_ProcessNetworkBurst{ProcessNetworkBurst: b},
				Time:  ktime.ToProto(msg.Msg.Common.Ktime),
			}
		}

	default:
		logger.GetLogger().Warn("HandleProcessNetworkWatermarksMessage: Unhandled event", "message", msg)
	}
	return res
}

func (msg *MsgProcessNetworkWatermarksEventUnix) Cast(_ interface{}) notify.Message {
	return &MsgProcessNetworkWatermarksEventUnix{}
}

// getProcessNetworkWatermarks returns ProcessNetworkWatermarks protobuf message for a given process.
func createProcessNetworkWatermarks(
	event *MsgProcessNetworkWatermarksEventUnix, cache bool,
) *tetragon.ProcessNetworkWatermark {
	var fgsProcess, fgsParent *tetragon.Process

	process, parent := process.GetParentProcessInternal(event.Msg.ProcessKey.Pid, event.Msg.ProcessKey.Ktime)
	if process == nil {
		fgsProcess = &tetragon.Process{
			Pid:       &wrapperspb.UInt32Value{Value: event.Msg.ProcessKey.Pid},
			StartTime: ktime.ToProto(event.Msg.ProcessKey.Ktime),
		}
	} else {
		fgsProcess = process.UnsafeGetProcess()
	}
	if parent != nil {
		fgsParent = parent.UnsafeGetProcess()
	}
	fgsEvent := &tetragon.ProcessNetworkWatermark{
		Process: fgsProcess,
		Parent:  fgsParent,
	}

	switch event.Msg.Protocol {
	case syscall.IPPROTO_UDP:
		fgsEvent.Protocol = "UDP"
	case syscall.IPPROTO_TCP:
		fgsEvent.Protocol = "TCP"
	default:
		fgsEvent.Protocol = "unknown"
	}
	if event.Msg.Direction == WATERMARKS_INGRESS {
		fgsEvent.Direction = "ingress"
	} else {
		fgsEvent.Direction = "egress"
	}
	if event.Msg.State == WATERMARKS_START {
		fgsEvent.WatermarksState = "start"
	} else {
		fgsEvent.WatermarksState = "end"
	}
	if event.Msg.Type == WATERMARKS_BURST {
		fgsEvent.WatermarksType = "burst"
	} else {
		fgsEvent.WatermarksType = "dip"
	}
	fgsEvent.WindowSize = event.Msg.WindowSize
	fgsEvent.HistAvg = event.Msg.HistAvg
	fgsEvent.HistBurstTrigger = event.Msg.HistBurstTrigger
	fgsEvent.HistDipTrigger = event.Msg.HistDipTrigger
	fgsEvent.WindowAvg = event.Msg.WindowAvg

	ec := eventcache.Get()
	if cache && ec != nil && (ec.Needed(fgsProcess) || (fgsProcess.Pid.Value > 1 && ec.Needed(fgsParent))) {
		ec.Add(nil, fgsEvent, event.Msg.Common.Ktime, event.Msg.ProcessKey.Ktime, event)
		return nil
	}

	eventmetrics.HandleProcessWatermarksEvent(fgsEvent)
	return fgsEvent
}

func getProcessNetworkWatermarks(
	event *MsgProcessNetworkWatermarksEventUnix,
) *tetragon.ProcessNetworkWatermark {
	return createProcessNetworkWatermarks(event, true)
}

// getProcessNetworkBurst returns ProcessNetworkBurst protobuf message for a given process.
func createProcessNetworkBurst(
	event *MsgProcessNetworkWatermarksEventUnix, cache bool,
) *tetragon.ProcessNetworkBurst {
	var fgsProcess, fgsParent *tetragon.Process

	process, parent := process.GetParentProcessInternal(event.Msg.ProcessKey.Pid, event.Msg.ProcessKey.Ktime)
	if process == nil {
		fgsProcess = &tetragon.Process{
			Pid:       &wrapperspb.UInt32Value{Value: event.Msg.ProcessKey.Pid},
			StartTime: ktime.ToProto(event.Msg.ProcessKey.Ktime),
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

	switch event.Msg.Protocol {
	case syscall.IPPROTO_UDP:
		fgsEvent.Protocol = "UDP"
	case syscall.IPPROTO_TCP:
		fgsEvent.Protocol = "TCP"
	default:
		fgsEvent.Protocol = "unknown"
	}
	if event.Msg.Direction == WATERMARKS_INGRESS {
		fgsEvent.Direction = "ingress"
	} else {
		fgsEvent.Direction = "egress"
	}
	if event.Msg.State == WATERMARKS_START {
		fgsEvent.BurstState = "start"
	} else {
		fgsEvent.BurstState = "end"
	}
	fgsEvent.WindowSize = event.Msg.WindowSize
	fgsEvent.HistAvg = event.Msg.HistAvg
	fgsEvent.HistTrigger = event.Msg.HistBurstTrigger
	fgsEvent.WindowAvg = event.Msg.WindowAvg

	ec := eventcache.Get()
	if cache && ec != nil && (ec.Needed(fgsProcess) || (fgsProcess.Pid.Value > 1 && ec.Needed(fgsParent))) {
		ec.Add(nil, fgsEvent, event.Msg.Common.Ktime, event.Msg.ProcessKey.Ktime, event)
		return nil
	}

	eventmetrics.HandleProcessBurstEvent(fgsEvent)
	return fgsEvent
}

func getProcessNetworkBurst(
	event *MsgProcessNetworkWatermarksEventUnix,
) *tetragon.ProcessNetworkBurst {
	return createProcessNetworkBurst(event, true)
}

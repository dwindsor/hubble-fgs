package udp_seq_check_error

import (
	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/cilium"
	"github.com/cilium/tetragon/pkg/eventcache"
	"github.com/cilium/tetragon/pkg/ktime"
	"github.com/cilium/tetragon/pkg/metrics/errormetrics"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/process"
	"github.com/cilium/tetragon/pkg/reader/node"
	"github.com/cilium/tetragon/pkg/reader/notify"
	"github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	"github.com/isovalent/hubble-fgs/pkg/api/ops"
	"github.com/isovalent/hubble-fgs/pkg/dns"
	"github.com/isovalent/hubble-fgs/pkg/grpc/sockinfo"
	"github.com/isovalent/hubble-fgs/pkg/metrics/eventmetrics"
	"github.com/isovalent/hubble-fgs/pkg/podinfo"
	reader "github.com/isovalent/hubble-fgs/pkg/reader/network"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const ()

var (
	nodeName = node.GetNodeNameForExport()
)

type MsgUdpSeqCheckErrorEventUnix struct {
	networkapi.MsgUdpSeqCheckErrorEvent
}

func (msg *MsgUdpSeqCheckErrorEventUnix) RetryInternal(ev notify.Event, timestamp uint64) (*process.ProcessInternal, error) {
	p := ev.GetProcess()
	return eventcache.HandleGenericInternal(ev, p.Pid.Value, nil, timestamp)
}

func (msg *MsgUdpSeqCheckErrorEventUnix) Retry(internal *process.ProcessInternal, ev notify.Event) error {
	p := internal.UnsafeGetProcess()
	if option.Config.EnableK8s && p.Pod == nil {
		errormetrics.ErrorTotalInc(errormetrics.EventCachePodInfoRetryFailed)
		return eventcache.ErrFailedToGetPodInfo
	}

	ev.SetProcess(internal.GetProcessCopy())

	createProcessUdpSeqCheckError(msg, false)

	return nil
}

func (msg *MsgUdpSeqCheckErrorEventUnix) Notify() bool {
	return true
}

func (msg *MsgUdpSeqCheckErrorEventUnix) HandleMessage() *tetragon.GetEventsResponse {
	var res *tetragon.GetEventsResponse
	b := getProcessUdpSeqCheckError(msg)
	if b != nil {
		res = &tetragon.GetEventsResponse{
			Event:    &tetragon.GetEventsResponse_ProcessUdpSeqCheckError{ProcessUdpSeqCheckError: b},
			NodeName: nodeName,
			Time:     ktime.ToProto(msg.Common.Ktime),
		}
	}
	return res
}

func (msg *MsgUdpSeqCheckErrorEventUnix) Cast(_ interface{}) notify.Message {
	return &MsgUdpSeqCheckErrorEventUnix{}
}

func createProcessUdpSeqCheckError(
	event *MsgUdpSeqCheckErrorEventUnix, _ bool,
) *tetragon.ProcessUdpSeqCheckError {
	var fgsProcess, fgsParent *tetragon.Process
	var sourcePort, destinationPort *wrapperspb.UInt32Value

	if event.Tuple.SPort != 0 {
		sourcePort = &wrapperspb.UInt32Value{
			Value: uint32(reader.GetSport(event.Tuple.SPort)),
		}
	}
	if event.Tuple.DPort != 0 {
		destinationPort = &wrapperspb.UInt32Value{
			Value: uint32(reader.SwapByte(event.Tuple.DPort)),
		}
	}

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

	destinationIP := reader.GetIP(event.Tuple.DAddr, event.Common.Op, event.Tuple.IPv6 != 0)

	socket := &tetragon.SockInfo{
		SourceIp:        reader.GetIP(event.Tuple.SAddr, event.Common.Op, event.Tuple.IPv6 != 0).String(),
		SourcePort:      sourcePort,
		DestinationIp:   destinationIP.String(),
		DestinationPort: destinationPort,
		SockCookie:      event.SockCookie,
	}

	ec := eventcache.Get()
	socket.DestinationNames, _ = sockinfo.GetProcessIp(fgsProcess, destinationIP.String(), dns.Get(), cilium.GetCiliumState())

	// When CiliumAPI is enable annotate data with Cilium info. If the data
	// is missing and enableEventCache is enabled we push event into the
	// cache where a retry will happen.
	if option.Config.EnableCilium && fgsProcess != nil {
		destinationIP := reader.GetIP(event.Tuple.DAddr, ops.MSG_OP_HTTP, event.Tuple.IPv6 != 0)
		socket.DestinationPod = podinfo.GetPodInfoOfIp(destinationIP)
	}

	fgsEvent := &tetragon.ProcessUdpSeqCheckError{
		Process:        fgsProcess,
		Parent:         fgsParent,
		Socket:         socket,
		ApplicationId:  event.ApplicationId,
		AppSpecificId:  event.AppSpecificId,
		SeqNumExpected: event.SeqNumExpected,
		SeqNumReceived: event.SeqNumReceived,
	}

	if ec != nil && (ec.Needed(fgsProcess) || (fgsProcess.Pid.Value > 1 && ec.Needed(fgsParent))) {
		ec.Add(nil, fgsEvent, event.Common.Ktime, event.ProcessKey.Ktime, event)
		return nil
	}
	if process != nil {
		fgsEvent.Process = process.GetProcessCopy()
	}
	if parent != nil {
		fgsEvent.Parent = parent.GetProcessCopy()
	}

	eventmetrics.HandleProcessUdpSeqCheckError(fgsEvent)
	return fgsEvent
}

func getProcessUdpSeqCheckError(
	event *MsgUdpSeqCheckErrorEventUnix,
) *tetragon.ProcessUdpSeqCheckError {
	return createProcessUdpSeqCheckError(event, true)
}

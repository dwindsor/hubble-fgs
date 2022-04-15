package grpc

import (
	"github.com/isovalent/hubble-fgs/api/v1/fgs"
	"github.com/isovalent/hubble-fgs/pkg/api"
	fgsAPI "github.com/isovalent/hubble-fgs/pkg/api"
	"github.com/isovalent/hubble-fgs/pkg/ktime"
	"github.com/isovalent/hubble-fgs/pkg/process"
	"github.com/isovalent/hubble-fgs/pkg/reader"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// GetProcessCred returns Cred protobuf message for a given process.
func (pm *ProcessManager) GetProcessCred(event *fgsAPI.MsgCredEventUnix) *fgs.ProcessCred {
	processInt, parentInt := process.GetParentProcessInternal(event.ProcessKey.Pid, event.ProcessKey.Ktime)
	var process, parent *fgs.Process
	if processInt == nil {
		process = &fgs.Process{
			Pid:       &wrapperspb.UInt32Value{Value: event.ProcessKey.Pid},
			StartTime: ktime.ToProto(event.ProcessKey.Ktime),
		}
	} else {
		process = processInt.UnsafeGetProcess()
		process.Cap = processInt.UnsafeGetProcessCap()
	}
	if parentInt != nil {
		parent = parentInt.UnsafeGetProcess()
		parent.Cap = parentInt.UnsafeGetProcessCap()
	}
	fgsEvent := &fgs.ProcessCred{
		Process: process,
		Parent:  parent,
		Cap:     reader.GetMsgCapabilities(event.Capabilities),
	}
	if pm.processCacheNeeded(process) {
		pm.eventCache.Add(processInt, fgsEvent, ktime.ToProto(event.Common.Ktime), event)
		return nil
	}
	if processInt != nil {
		fgsEvent.Process = processInt.GetProcessCopy()
	}
	return fgsEvent
}

func (pm *ProcessManager) handleCredMessage(msg *api.MsgCredEventUnix) *fgs.GetEventsResponse {
	if !pm.enableProcessCred {
		return nil
	}
	var res *fgs.GetEventsResponse
	switch msg.Common.Op {
	case api.MSG_OP_CRED:
		event := pm.GetProcessCred(msg)
		if event != nil {
			res = &fgs.GetEventsResponse{
				Event:    &fgs.GetEventsResponse_ProcessCred{ProcessCred: event},
				NodeName: pm.nodeName,
				Time:     ktime.ToProto(msg.Common.Ktime),
			}
		}
	default:
		pm.log.WithField("message", msg).Warn("Unhandled event")
	}
	return res
}

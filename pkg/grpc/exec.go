package grpc

import (
	"strings"

	"github.com/isovalent/hubble-fgs/api/v1/fgs"
	"github.com/isovalent/hubble-fgs/pkg/api"
	fgsAPI "github.com/isovalent/hubble-fgs/pkg/api"
	"github.com/isovalent/hubble-fgs/pkg/ktime"
	"github.com/isovalent/hubble-fgs/pkg/process"
	"github.com/isovalent/hubble-fgs/pkg/reader"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// GetProcessExec returns Exec protobuf message for a given process, including the ancestor list.
func (pm *ProcessManager) GetProcessExec(
	proc *process.ProcessInternal,
) *fgs.ProcessExec {
	var parent *process.ProcessInternal
	var fgsAncestors []*fgs.Process

	ancestors := pm.getAncestors(proc.UnsafeGetProcess())
	if len(ancestors) >= 1 {
		parent = ancestors[0]
		ancestors = ancestors[1:]
		parent.RefInc()
		for _, a := range ancestors {
			a.RefInc()
		}
	}
	var fgsParent, fgsProcess *fgs.Process

	// Set the cap field only if --enable-process-cred flag is set.
	proc.AnnotateProcess(pm.enableProcessCred, pm.enableProcessNs)
	fgsProcess = proc.UnsafeGetProcess()
	if parent != nil {
		fgsParent = parent.GetProcessCopy()
	}

	for _, a := range ancestors {
		// If we have a docker link, but the pod info lookup
		// failed then this is a nested docker environment. In
		// this case inherit the pod-info from our ancestors.
		if fgsProcess.Docker != "" &&
			fgsProcess.Pod == nil &&
			a.UnsafeGetProcess().Pod != nil {
			pod := proto.Clone(a.UnsafeGetProcess().Pod).(*fgs.Pod)
			proc.AddPodInfo(pod)
		}
		fgsAncestors = append(fgsAncestors, a.UnsafeGetProcess())
	}
	// If this is not a clone we need to decrement parent refcnt because
	// the parent has been replaced and will not get its own exit event.
	// The new process will hold needed refcnts until it is destroyed.
	if strings.Contains(fgsProcess.Flags, "clone") == false &&
		strings.Contains(fgsProcess.Flags, "procFS") == false &&
		parent != nil {
		parent.RefDec()
		ancestors := pm.getAncestors(fgsParent)
		if len(ancestors) >= 1 {
			ancestors = ancestors[0:]
			for _, a := range ancestors {
				a.RefDec()
			}
		}
	}
	if !pm.enableProcessAncestors {
		fgsAncestors = nil
	}
	return &fgs.ProcessExec{
		Process:   fgsProcess,
		Parent:    fgsParent,
		Ancestors: fgsAncestors,
	}
}

func (pm *ProcessManager) handleExecveMessage(msg *api.MsgExecveEventUnix) *fgs.GetEventsResponse {
	var res *fgs.GetEventsResponse
	switch msg.Common.Op {
	case api.MSG_OP_EXECVE:
		proc := process.Add(msg)
		procEvent := pm.GetProcessExec(proc)
		if pm.processCacheNeeded(procEvent.Process) {
			pm.execCache.Add(proc, procEvent, ktime.ToProto(msg.Common.Ktime), msg)
		} else {
			procEvent.Process = proc.GetProcessCopy()
			res = &fgs.GetEventsResponse{
				Event:    &fgs.GetEventsResponse_ProcessExec{ProcessExec: procEvent},
				NodeName: pm.nodeName,
				Time:     ktime.ToProto(msg.Common.Ktime),
			}
		}
	default:
		pm.log.WithField("message", msg).Warn("Unhandled event")
	}
	return res
}

// GetProcessExit returns Exit protobuf message for a given process.
func (pm *ProcessManager) GetProcessExit(event *fgsAPI.MsgExitEventUnix) *fgs.ProcessExit {
	var fgsProcess, fgsParent *fgs.Process

	process, parent := process.GetParentProcessInternal(event.ProcessKey.Pid, event.ProcessKey.Ktime)
	if process != nil {
		process.RefDec()
		fgsProcess = process.UnsafeGetProcess()
	} else {
		fgsProcess = &fgs.Process{
			Pid:       &wrapperspb.UInt32Value{Value: event.ProcessKey.Pid},
			StartTime: ktime.ToProto(event.ProcessKey.Ktime),
		}
	}
	if parent != nil {
		parent.RefDec()
		fgsParent = parent.GetProcessCopy()
	}

	ancestors := pm.getAncestors(fgsProcess)
	if len(ancestors) >= 2 {
		ancestors = ancestors[1:]
		for _, a := range ancestors {
			a.RefDec()
		}
	}

	code := event.Info.Code >> 8
	signal := reader.Signal(event.Info.Code & 0xFF)

	fgsEvent := &fgs.ProcessExit{
		Process: fgsProcess,
		Parent:  fgsParent,
		Signal:  signal,
		Status:  code,
	}
	if pm.processCacheNeeded(fgsProcess) {
		pm.eventCache.add(process, fgsEvent, ktime.ToProto(event.Common.Ktime), event)
		return nil
	}
	if process != nil {
		fgsEvent.Process = process.GetProcessCopy()
	}
	return fgsEvent
}

func (pm *ProcessManager) handleExitMessage(msg *api.MsgExitEventUnix) *fgs.GetEventsResponse {
	var res *fgs.GetEventsResponse
	switch msg.Common.Op {
	case api.MSG_OP_EXIT:
		e := pm.GetProcessExit(msg)
		if e != nil {
			res = &fgs.GetEventsResponse{
				Event:    &fgs.GetEventsResponse_ProcessExit{ProcessExit: e},
				NodeName: pm.nodeName,
				Time:     ktime.ToProto(msg.Common.Ktime),
			}
		}
	default:
		pm.log.WithField("message", msg).Warn("Unhandled event")
	}
	return res
}

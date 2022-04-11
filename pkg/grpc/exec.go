package grpc

import (
	"strings"

	"github.com/isovalent/hubble-fgs/api/v1/fgs"
	"github.com/isovalent/hubble-fgs/pkg/api"
	fgsAPI "github.com/isovalent/hubble-fgs/pkg/api"
	"github.com/isovalent/hubble-fgs/pkg/reader"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// GetProcessExec returns Exec protobuf message for a given process, including the ancestor list.
func (pm *ProcessManager) GetProcessExec(
	proc *ProcessInternal,
) *fgs.ProcessExec {
	var parent *ProcessInternal
	var fgsAncestors []*fgs.Process

	ancestors := pm.getAncestors(proc.process)
	if len(ancestors) >= 1 {
		parent = ancestors[0]
		ancestors = ancestors[1:]
		pm.cache.refInc(parent)
		for _, a := range ancestors {
			pm.cache.refInc(a)
		}
	}
	// Set the cap field only if --enable-process-cred flag is set.
	var fgsParent, fgsProcess *fgs.Process
	fgsProcess = proc.process

	proc.mu.Lock()
	if pm.enableProcessCred {
		fgsProcess.Cap = proc.capabilities
	}
	if pm.enableProcessNs {
		fgsProcess.Ns = proc.namespaces
	}
	proc.mu.Unlock()

	if parent != nil {
		fgsParent = parent.GetProcessCopy()
	}
	for _, a := range ancestors {
		// If we have a docker link, but the pod info lookup
		// failed then this is a nested docker environment. In
		// this case inherit the pod-info from our ancestors.
		if fgsProcess.Docker != "" &&
			fgsProcess.Pod == nil &&
			a.process.Pod != nil {
			pod := proto.Clone(a.process.Pod).(*fgs.Pod)
			fgsProcess.Pod = pod
		}
		fgsAncestors = append(fgsAncestors, a.process)
	}
	// If this is not a clone we need to decrement parent refcnt because
	// the parent has been replaced and will not get its own exit event.
	// The new process will hold needed refcnts until it is destroyed.
	if strings.Contains(fgsProcess.Flags, "clone") == false &&
		strings.Contains(fgsProcess.Flags, "procFS") == false &&
		parent != nil {
		pm.cache.refDec(parent)
		ancestors := pm.getAncestors(fgsParent)
		if len(ancestors) >= 1 {
			ancestors = ancestors[0:]
			for _, a := range ancestors {
				pm.cache.refDec(a)
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
		proc := pm.Add(msg)
		procEvent := pm.GetProcessExec(proc)
		if pm.processCacheNeeded(procEvent.Process) {
			pm.eventCache.addProc(proc, procEvent, ktimeToProto(msg.Common.Ktime), msg)
		} else {
			procEvent.Process = proc.GetProcessCopy()
			res = &fgs.GetEventsResponse{
				Event:    &fgs.GetEventsResponse_ProcessExec{ProcessExec: procEvent},
				NodeName: pm.nodeName,
				Time:     ktimeToProto(msg.Common.Ktime),
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

	process, parent := pm.getParentProcessInternal(event.ProcessKey.Pid, event.ProcessKey.Ktime)
	if process != nil {
		pm.cache.refDec(process)
		fgsProcess = process.process
	} else {
		fgsProcess = &fgs.Process{
			Pid:       &wrapperspb.UInt32Value{Value: event.ProcessKey.Pid},
			StartTime: ktimeToProto(event.ProcessKey.Ktime),
		}
	}
	if parent != nil {
		pm.cache.refDec(parent)
		fgsParent = parent.GetProcessCopy()
	}

	ancestors := pm.getAncestors(fgsProcess)
	if len(ancestors) >= 2 {
		ancestors = ancestors[1:]
		for _, a := range ancestors {
			pm.cache.refDec(a)
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
		pm.eventCache.add(process, fgsEvent, ktimeToProto(event.Common.Ktime), event)
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
				Time:     ktimeToProto(msg.Common.Ktime),
			}
		}
	default:
		pm.log.WithField("message", msg).Warn("Unhandled event")
	}
	return res
}

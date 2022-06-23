package execAncestors

import (
	"strings"

	"github.com/cilium/tetragon/api/v1/tetragon"
	fgsAPI "github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/ktime"
	"github.com/cilium/tetragon/pkg/logger"
	readerexec "github.com/cilium/tetragon/pkg/reader/exec"
	"github.com/cilium/tetragon/pkg/reader/node"
	"github.com/isovalent/hubble-fgs/api/v1/fgs"
	"github.com/isovalent/hubble-fgs/pkg/api/ops"
	"github.com/isovalent/hubble-fgs/pkg/eventcache"
	"github.com/isovalent/hubble-fgs/pkg/execcache"
	"github.com/isovalent/hubble-fgs/pkg/process"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var (
	nodeName = node.GetNodeNameForExport()
)

type Grpc struct {
	execCache  *execcache.Cache
	eventCache *eventcache.Cache
	enableCred bool
	enableNs   bool
}

// getAncestors builds an ancestor list by traversing the parent exec IDs.
func getAncestors(proc *tetragon.Process) []*process.ProcessInternal {
	var ancestors []*process.ProcessInternal
	for parentExecID := proc.ParentExecId; parentExecID != ""; {
		entry, err := process.Get(parentExecID)
		if err != nil {
			logger.GetLogger().WithField("id in event", parentExecID).Debug("parent not found in cache")
			break
		}
		ancestors = append(ancestors, entry)
		parentExecID = entry.UnsafeGetProcess().ParentExecId
	}
	return ancestors
}

// GetProcessExec returns Exec protobuf message for a given process, including the ancestor list.
func (e *Grpc) GetProcessExec(
	proc *process.ProcessInternal,
) *fgs.ProcessExec {
	var parent *process.ProcessInternal
	var fgsAncestors []*tetragon.Process

	ancestors := getAncestors(proc.UnsafeGetProcess())
	if len(ancestors) >= 1 {
		parent = ancestors[0]
		ancestors = ancestors[1:]
		parent.RefInc()
		for _, a := range ancestors {
			a.RefInc()
		}
	}
	var fgsParent, fgsProcess *tetragon.Process

	// Set the cap field only if --enable-process-cred flag is set.
	proc.AnnotateProcess(e.enableCred, e.enableNs)
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
			pod := proto.Clone(a.UnsafeGetProcess().Pod).(*tetragon.Pod)
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
		ancestors := getAncestors(fgsParent)
		if len(ancestors) >= 1 {
			ancestors = ancestors[0:]
			for _, a := range ancestors {
				a.RefDec()
			}
		}
	}
	return &fgs.ProcessExec{
		Process:   fgsProcess,
		Parent:    fgsParent,
		Ancestors: fgsAncestors,
	}
}

func (e *Grpc) HandleExecveMessage(msg *fgsAPI.MsgExecveEventUnix) *fgs.GetEventsResponse {
	var res *fgs.GetEventsResponse
	switch msg.Common.Op {
	case ops.MSG_OP_EXECVE:
		proc := process.AddExecEvent(msg)
		procEvent := e.GetProcessExec(proc)
		if e.eventCache.Needed(procEvent.Process) {
			e.execCache.Add(proc, procEvent, ktime.ToProto(msg.Common.Ktime), msg)
		} else {
			procEvent.Process = proc.GetProcessCopy()
			res = &fgs.GetEventsResponse{
				Event:    &fgs.GetEventsResponse_ProcessExec{ProcessExec: procEvent},
				NodeName: nodeName,
				Time:     ktime.ToProto(msg.Common.Ktime),
			}
		}
	default:
		logger.GetLogger().WithField("message", msg).Warn("HandleExecveMessage: Unhandled event")
	}
	return res
}

// HandleCloneMessage -- don't generate any events. Just add the process to the cache.
func (e *Grpc) HandleCloneMessage(msg *fgsAPI.MsgCloneEventUnix) {
	switch msg.Common.Op {
	case ops.MSG_OP_CLONE:
		process.AddCloneEvent(msg)
	default:
		logger.GetLogger().WithField("message", msg).Warn("HandleCloneMessage: Unhandled event")
	}
}

// GetProcessExit returns Exit protobuf message for a given process.
func (e *Grpc) GetProcessExit(event *fgsAPI.MsgExitEventUnix) *fgs.ProcessExit {
	var fgsProcess, fgsParent *tetragon.Process

	process, parent := process.GetParentProcessInternal(event.ProcessKey.Pid, event.ProcessKey.Ktime)
	if process != nil {
		process.RefDec()
		fgsProcess = process.UnsafeGetProcess()
	} else {
		fgsProcess = &tetragon.Process{
			Pid:       &wrapperspb.UInt32Value{Value: event.ProcessKey.Pid},
			StartTime: ktime.ToProto(event.ProcessKey.Ktime),
		}
	}
	if parent != nil {
		parent.RefDec()
		fgsParent = parent.GetProcessCopy()
	}

	ancestors := getAncestors(fgsProcess)
	if len(ancestors) >= 2 {
		ancestors = ancestors[1:]
		for _, a := range ancestors {
			a.RefDec()
		}
	}

	code := event.Info.Code >> 8
	signal := readerexec.Signal(event.Info.Code & 0xFF)

	fgsEvent := &fgs.ProcessExit{
		Process: fgsProcess,
		Parent:  fgsParent,
		Signal:  signal,
		Status:  code,
	}
	if e.eventCache.Needed(fgsProcess) {
		e.eventCache.Add(process, fgsEvent, ktime.ToProto(event.Common.Ktime), event)
		return nil
	}
	if process != nil {
		fgsEvent.Process = process.GetProcessCopy()
	}
	return fgsEvent
}

func (e *Grpc) HandleExitMessage(msg *fgsAPI.MsgExitEventUnix) *fgs.GetEventsResponse {
	var res *fgs.GetEventsResponse
	switch msg.Common.Op {
	case ops.MSG_OP_EXIT:
		e := e.GetProcessExit(msg)
		if e != nil {
			res = &fgs.GetEventsResponse{
				Event:    &fgs.GetEventsResponse_ProcessExit{ProcessExit: e},
				NodeName: nodeName,
				Time:     ktime.ToProto(msg.Common.Ktime),
			}
		}
	default:
		logger.GetLogger().WithField("message", msg).Warn("HandleExitMessage: Unhandled event")
	}
	return res
}

func New(exec *execcache.Cache, event *eventcache.Cache, cred, ns bool) *Grpc {
	return &Grpc{
		execCache:  exec,
		eventCache: event,
		enableCred: cred,
		enableNs:   ns,
	}
}

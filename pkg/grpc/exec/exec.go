package exec

import (
	"fmt"
	"strings"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/eventcache"
	"github.com/cilium/tetragon/pkg/ktime"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/metrics/errormetrics"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/process"
	readerexec "github.com/cilium/tetragon/pkg/reader/exec"
	"github.com/cilium/tetragon/pkg/reader/node"
	"github.com/cilium/tetragon/pkg/reader/notify"
	"github.com/isovalent/hubble-fgs/pkg/api/ops"
	"github.com/isovalent/hubble-fgs/pkg/nscache"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var (
	nodeName = node.GetNodeNameForExport()
)

// GetProcessExec returns Exec protobuf message for a given process, including the ancestor list.
func GetProcessExec(proc *process.ProcessInternal) *tetragon.ProcessExec {
	var fgsParent *tetragon.Process

	fgsProcess := proc.UnsafeGetProcess()

	parentId := fgsProcess.ParentExecId
	processId := fgsProcess.ExecId

	parent, err := process.Get(parentId)
	if err != nil {
		logger.GetLogger().WithField("processId", processId).WithField("parentId", parentId).Infof("Process missing parent")
	} else {
		parent.RefInc()
	}

	// Set the cap field only if --enable-process-cred flag is set.
	proc.AnnotateProcess(option.Config.EnableProcessCred, option.Config.EnableProcessNs)
	if parent != nil {
		fgsParent = parent.GetProcessCopy()
	}

	// If this is not a clone we need to decrement parent refcnt because
	// the parent has been replaced and will not get its own exit event.
	// The new process will hold needed refcnts until it is destroyed.
	if strings.Contains(fgsProcess.Flags, "clone") == false &&
		strings.Contains(fgsProcess.Flags, "procFS") == false &&
		parent != nil {
		parent.RefDec()
	}

	return &tetragon.ProcessExec{
		Process: fgsProcess,
		Parent:  fgsParent,
	}
}

type MsgExecveEventUnix struct {
	processapi.MsgExecveEventUnix
}

func (msg *MsgExecveEventUnix) RetryInternal(ev notify.Event, timestamp uint64) (*process.ProcessInternal, error) {
	return nil, fmt.Errorf("Unreachable state: MsgExecveEventUnix with missing internal")
}

func (msg *MsgExecveEventUnix) Retry(internal *process.ProcessInternal, ev notify.Event) error {
	var podInfo *tetragon.Pod

	proc := ev.GetProcess()
	parent := ev.GetParent()

	containerId := proc.Docker
	filename := proc.Binary
	args := proc.Arguments
	nspid := msg.Process.NSPID

	if option.Config.EnableK8s && containerId != "" {
		podInfo, _ = process.GetPodInfo(containerId, filename, args, nspid)
		if podInfo == nil {
			errormetrics.ErrorTotalInc(errormetrics.EventCachePodInfoRetryFailed)
			return eventcache.ErrFailedToGetPodInfo
		}
		netinum := msg.Namespaces.NetInum
		if netinum != 0 && podInfo != nil {
			nscache.AddNetNs(uint64(netinum), podInfo)
		}
	}

	// We can assume that event.internal != nil here since it's being set by AddExecEvent
	// earlier in the code path. If this invariant ever changes in the future, we probably
	// want to panic anyway to help us catch the bug faster. So no need to do a nil check
	// here.
	internal.AddPodInfo(podInfo)
	ev.SetProcess(internal.GetProcessCopy())

	// Check we have a parent with exception for pid 1, note we do this last because we want
	// to ensure the podInfo and process are set before returning any errors.
	if proc.Pid.Value > 1 && parent == nil {
		parentId := proc.ParentExecId
		parent, err := process.Get(parentId)
		if parent == nil {
			return err
		}
		if strings.Contains(proc.Flags, "clone") == true {
			parent.RefInc()
		}
	}

	return nil
}

func (msg *MsgExecveEventUnix) Notify() bool {
	return true
}

func (msg *MsgExecveEventUnix) HandleMessage() *tetragon.GetEventsResponse {
	var res *tetragon.GetEventsResponse
	switch msg.Common.Op {
	case ops.MSG_OP_EXECVE:
		proc := process.AddExecEvent(&msg.MsgExecveEventUnix)
		procEvent := GetProcessExec(proc)

		ec := eventcache.Get()
		if ec != nil &&
			(ec.Needed(procEvent.Process) ||
				(procEvent.Process.Pid.Value > 1 && ec.Needed(procEvent.Parent))) {
			ec.Add(proc, procEvent, msg.MsgExecveEventUnix.Process.Ktime, msg)
		} else {
			netinum := msg.Namespaces.NetInum
			if netinum != 0 && procEvent.Process.Pod != nil {
				nscache.AddNetNs(uint64(netinum), procEvent.Process.Pod)
			}
			procEvent.Process = proc.GetProcessCopy()
			res = &tetragon.GetEventsResponse{
				Event:    &tetragon.GetEventsResponse_ProcessExec{ProcessExec: procEvent},
				NodeName: nodeName,
				Time:     ktime.ToProto(msg.Common.Ktime),
			}
		}
	default:
		logger.GetLogger().WithField("message", msg).Warn("HandleExecveMessage: Unhandled event")
	}
	return res
}

type MsgCloneEventUnix struct {
	processapi.MsgCloneEvent
}

func (msg *MsgCloneEventUnix) Notify() bool {
	return false
}

func (msg *MsgCloneEventUnix) RetryInternal(ev notify.Event, timestamp uint64) (*process.ProcessInternal, error) {
	return nil, fmt.Errorf("Unreachable state: MsgCloneEventUnix with missing internal")
}

func (msg *MsgCloneEventUnix) Retry(internal *process.ProcessInternal, ev notify.Event) error {
	return eventcache.HandleGenericEvent(internal, ev)
}

// HandleCloneMessage -- don't generate any events. Just add the process to the cache.
func (msg *MsgCloneEventUnix) HandleMessage() *tetragon.GetEventsResponse {
	switch msg.Common.Op {
	case ops.MSG_OP_CLONE:
		process.AddCloneEvent(&msg.MsgCloneEvent)
	default:
		logger.GetLogger().WithField("message", msg).Warn("HandleCloneMessage: Unhandled event")
	}
	return nil
}

// GetProcessExit returns Exit protobuf message for a given process.
func GetProcessExit(event *MsgExitEventUnix) *tetragon.ProcessExit {
	var fgsProcess, fgsParent *tetragon.Process

	process, parent := process.GetParentProcessInternal(event.ProcessKey.Pid, event.ProcessKey.Ktime)
	if process != nil {
		fgsProcess = process.UnsafeGetProcess()
	} else {
		fgsProcess = &tetragon.Process{
			Pid:       &wrapperspb.UInt32Value{Value: event.ProcessKey.Pid},
			StartTime: ktime.ToProto(event.ProcessKey.Ktime),
		}
	}
	if parent != nil {
		fgsParent = parent.GetProcessCopy()
	}

	code := event.Info.Code >> 8
	signal := readerexec.Signal(event.Info.Code & 0xFF)

	fgsEvent := &tetragon.ProcessExit{
		Process: fgsProcess,
		Parent:  fgsParent,
		Signal:  signal,
		Status:  code,
	}

	ec := eventcache.Get()
	if ec != nil &&
		(ec.Needed(fgsProcess) ||
			(fgsProcess.Pid.Value > 1 && ec.Needed(fgsParent))) {
		ec.Add(process, fgsEvent, event.ProcessKey.Ktime, event)
		return nil
	}
	if parent != nil {
		parent.RefDec()
	}
	if process != nil {
		process.RefDec()
		fgsEvent.Process = process.GetProcessCopy()
	}
	return fgsEvent
}

type MsgExitEventUnix struct {
	processapi.MsgExitEvent
}

func (msg *MsgExitEventUnix) Notify() bool {
	return true
}

func (msg *MsgExitEventUnix) RetryInternal(ev notify.Event, timestamp uint64) (*process.ProcessInternal, error) {
	p := ev.GetProcess()
	internal, parent := process.GetParentProcessInternal(p.Pid.Value, timestamp)
	var err error

	if parent != nil {
		ev.SetParent(parent.GetProcessCopy())
		parent.RefDec()
	} else {
		errormetrics.ErrorTotalInc(errormetrics.EventCacheParentInfoFailed)
		err = eventcache.ErrFailedToGetParentInfo
	}

	if internal != nil {
		internal.RefDec()
	} else {
		errormetrics.ErrorTotalInc(errormetrics.EventCacheProcessInfoFailed)
		err = eventcache.ErrFailedToGetProcessInfo
	}

	return internal, err
}

func (msg *MsgExitEventUnix) Retry(internal *process.ProcessInternal, ev notify.Event) error {
	return eventcache.HandleGenericEvent(internal, ev)
}

func (msg *MsgExitEventUnix) HandleMessage() *tetragon.GetEventsResponse {
	var res *tetragon.GetEventsResponse
	switch msg.Common.Op {
	case ops.MSG_OP_EXIT:
		e := GetProcessExit(msg)
		if e != nil {
			res = &tetragon.GetEventsResponse{
				Event:    &tetragon.GetEventsResponse_ProcessExit{ProcessExit: e},
				NodeName: nodeName,
				Time:     ktime.ToProto(msg.Common.Ktime),
			}
		}
	default:
		logger.GetLogger().WithField("message", msg).Warn("HandleExitMessage: Unhandled event")
	}
	return res
}

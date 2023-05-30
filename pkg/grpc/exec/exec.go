package exec

import (
	"fmt"

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
	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var (
	nodeName = node.GetNodeNameForExport()
)

const (
	ParentRefCnt  = 0
	ProcessRefCnt = 1
)

func (msg *MsgExecveEventUnix) getCleanupEvent() *MsgProcessCleanupEventUnix {
	if msg.CleanupProcess.Ktime == 0 {
		return nil
	}
	return &MsgProcessCleanupEventUnix{
		PID:   msg.CleanupProcess.Pid,
		Ktime: msg.CleanupProcess.Ktime,
	}
}

// getAncestors builds an ancestor list by traversing the parent exec IDs.
func getAncestors(proc *tetragon.Process) []*process.ProcessInternal {
	var ancestors []*process.ProcessInternal
	parentExecID := proc.ParentExecId
	for {
		entry, err := process.Get(parentExecID)
		if err != nil {
			logger.GetLogger().WithField("id in event", parentExecID).Debug("parent not found in cache")
			break
		}
		p := entry.UnsafeGetProcess()
		if p.Pid.Value == 0 {
			break
		}
		ancestors = append(ancestors, entry)
		parentExecID = p.ParentExecId
	}
	return ancestors
}

// GetProcessExec returns Exec protobuf message for a given process, including the ancestor list.
func GetProcessExec(event *MsgExecveEventUnix) *tetragon.ProcessExec {
	var fgsParent *tetragon.Process
	var fgsAncestors []*tetragon.Process

	proc := process.AddExecEvent(&event.MsgExecveEventUnix)
	fgsProcess := proc.UnsafeGetProcess()

	parentId := fgsProcess.ParentExecId
	parent, err := process.Get(parentId)
	if err == nil {
		parent.RefInc()
		fgsParent = parent.GetProcessCopy()
	}

	// Set the cap field only if --enable-process-cred flag is set.
	if err := proc.AnnotateProcess(option.Config.EnableProcessCred, option.Config.EnableProcessNs); err != nil {
		logger.GetLogger().WithError(err).WithField("processId", fgsProcess.ExecId).WithField("parentId", parentId).Debugf("Failed to annotate process with capabilities and namespaces info")
	}

	// Populate fgsAncestors by walking backwards through the parentId links. Some small
	// optimization to push Pod info up if its missing.
	if enterpriseOption.Config.EnableProcessAncestors && fgsParent != nil {
		for _, a := range getAncestors(fgsParent) {
			// If we have a docker link, but the pod info lookup
			// failed then this is a nested docker environment. In
			// this case inherit the pod-info from our ancestors.
			if option.Config.EnableK8s &&
				fgsProcess.Docker != "" &&
				fgsProcess.Pod == nil &&
				a.UnsafeGetProcess().Pod != nil {
				pod := proto.Clone(a.UnsafeGetProcess().Pod).(*tetragon.Pod)
				proc.AddPodInfo(pod)
				fgsProcess = proc.UnsafeGetProcess()
			}
			fgsAncestors = append(fgsAncestors, a.UnsafeGetProcess())
		}
	}

	fgsEvent := &tetragon.ProcessExec{
		Process:   fgsProcess,
		Parent:    fgsParent,
		Ancestors: fgsAncestors,
	}

	if ec := eventcache.Get(); ec != nil &&
		(ec.Needed(fgsEvent.Process) || (fgsProcess.Pid.Value > 1 && fgsEvent.Parent == nil)) {
		ec.Add(proc, fgsEvent, event.Common.Ktime, event.Process.Ktime, event)
		return nil
	}

	fgsEvent.Process = proc.GetProcessCopy()

	netinum := event.Namespaces.NetInum
	if netinum != 0 && fgsEvent.Process.Pod != nil {
		nscache.AddNetNs(uint64(netinum), fgsEvent.Process.Pod)
	}

	// do we need to cleanup anything?
	if cleanupEvent := event.getCleanupEvent(); cleanupEvent != nil {
		cleanupEvent.HandleMessage()
	}

	return fgsEvent
}

type MsgExecveEventUnix struct {
	processapi.MsgExecveEventUnix
}

func (msg *MsgExecveEventUnix) RetryInternal(_ notify.Event, _ uint64) (*process.ProcessInternal, error) {
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
		parent.RefInc()
		ev.SetParent(parent.GetProcessCopy())

		// setup ancestors, we missed parent in the original event so now we can do that
		if e, ok := ev.(*tetragon.ProcessExec); ok {
			var fgsAncestors []*tetragon.Process
			if enterpriseOption.Config.EnableProcessAncestors && parent != nil {
				for _, a := range getAncestors(parent.UnsafeGetProcess()) {
					fgsAncestors = append(fgsAncestors, a.UnsafeGetProcess())
				}
			}
			e.Ancestors = fgsAncestors
		}
	}

	// do we need to cleanup anything?
	if cleanupEvent := msg.getCleanupEvent(); cleanupEvent != nil {
		// Retry() is going to be executed in the cache loop handling function, but
		// HandleMessage may enqueue something in the cache channel. To avoid a deadlock,
		// execute the cleanup message handling in a separate goroutine.
		go cleanupEvent.HandleMessage()
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
		if e := GetProcessExec(msg); e != nil {
			res = &tetragon.GetEventsResponse{
				Event:    &tetragon.GetEventsResponse_ProcessExec{ProcessExec: e},
				NodeName: nodeName,
				Time:     ktime.ToProto(msg.Common.Ktime),
			}
		}
	default:
		logger.GetLogger().WithField("message", msg).Warn("HandleExecveMessage: Unhandled event")
	}
	return res
}

func (msg *MsgExecveEventUnix) Cast(o interface{}) notify.Message {
	t := o.(processapi.MsgExecveEventUnix)
	return &MsgExecveEventUnix{MsgExecveEventUnix: t}
}

type MsgCloneEventUnix struct {
	processapi.MsgCloneEvent
}

func (msg *MsgCloneEventUnix) Notify() bool {
	return false
}

func (msg *MsgCloneEventUnix) RetryInternal(_ notify.Event, _ uint64) (*process.ProcessInternal, error) {
	return nil, process.AddCloneEvent(&msg.MsgCloneEvent)
}

func (msg *MsgCloneEventUnix) Retry(_ *process.ProcessInternal, _ notify.Event) error {
	return nil
}

// HandleCloneMessage -- don't generate any events. Just add the process to the cache.
func (msg *MsgCloneEventUnix) HandleMessage() *tetragon.GetEventsResponse {
	switch msg.Common.Op {
	case ops.MSG_OP_CLONE:
		if err := process.AddCloneEvent(&msg.MsgCloneEvent); err != nil {
			ec := eventcache.Get()
			if ec != nil {
				ec.Add(nil, nil, msg.MsgCloneEvent.Common.Ktime, msg.MsgCloneEvent.Ktime, msg)
			}
		}
	default:
		logger.GetLogger().WithField("message", msg).Warn("HandleCloneMessage: Unhandled event")
	}
	return nil
}

func (msg *MsgCloneEventUnix) Cast(o interface{}) notify.Message {
	t := o.(processapi.MsgCloneEvent)
	return &MsgCloneEventUnix{MsgCloneEvent: t}
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
		fgsParent = parent.UnsafeGetProcess()
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
		ec.Add(nil, fgsEvent, event.Common.Ktime, event.ProcessKey.Ktime, event)
		return nil
	}
	if parent != nil {
		parent.RefDec()
		fgsEvent.Parent = parent.GetProcessCopy()
	}
	if process != nil {
		process.RefDec()
		fgsEvent.Process = process.GetProcessCopy()
	}
	return fgsEvent
}

type MsgExitEventUnix struct {
	processapi.MsgExitEvent
	RefCntDone [2]bool
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
		if !msg.RefCntDone[ParentRefCnt] {
			parent.RefDec()
			msg.RefCntDone[ParentRefCnt] = true
		}
	} else {
		errormetrics.ErrorTotalInc(errormetrics.EventCacheParentInfoFailed)
		err = eventcache.ErrFailedToGetParentInfo
	}

	if internal != nil {
		if !msg.RefCntDone[ProcessRefCnt] {
			internal.RefDec()
			msg.RefCntDone[ProcessRefCnt] = true
		}
	} else {
		errormetrics.ErrorTotalInc(errormetrics.EventCacheProcessInfoFailed)
		err = eventcache.ErrFailedToGetProcessInfo
	}

	if err == nil {
		return internal, err
	}
	return nil, err
}

func (msg *MsgExitEventUnix) Retry(internal *process.ProcessInternal, ev notify.Event) error {
	return eventcache.HandleGenericEvent(internal, ev, nil)
}

func (msg *MsgExitEventUnix) HandleMessage() *tetragon.GetEventsResponse {
	var res *tetragon.GetEventsResponse
	switch msg.Common.Op {
	case ops.MSG_OP_EXIT:
		msg.RefCntDone = [2]bool{false, false}
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

func (msg *MsgExitEventUnix) Cast(o interface{}) notify.Message {
	t := o.(processapi.MsgExitEvent)
	return &MsgExitEventUnix{MsgExitEvent: t}
}

type MsgProcessCleanupEventUnix struct {
	PID        uint32
	Ktime      uint64
	RefCntDone [2]bool
}

func (msg *MsgProcessCleanupEventUnix) Notify() bool {
	return false
}

func (msg *MsgProcessCleanupEventUnix) RetryInternal(_ notify.Event, timestamp uint64) (*process.ProcessInternal, error) {
	internal, parent := process.GetParentProcessInternal(msg.PID, timestamp)
	var err error

	if parent != nil {
		if !msg.RefCntDone[ParentRefCnt] {
			parent.RefDec()
			msg.RefCntDone[ParentRefCnt] = true
		}
	} else {
		err = eventcache.ErrFailedToGetParentInfo
	}

	if internal != nil {
		if !msg.RefCntDone[ProcessRefCnt] {
			internal.RefDec()
			msg.RefCntDone[ProcessRefCnt] = true
		}
	} else {
		err = eventcache.ErrFailedToGetProcessInfo
	}

	if err == nil {
		return internal, err
	}
	return nil, err
}

func (msg *MsgProcessCleanupEventUnix) Retry(_ *process.ProcessInternal, _ notify.Event) error {
	return nil
}

func (msg *MsgProcessCleanupEventUnix) HandleMessage() *tetragon.GetEventsResponse {
	msg.RefCntDone = [2]bool{false, false}
	if process, parent := process.GetParentProcessInternal(msg.PID, msg.Ktime); process != nil && parent != nil {
		parent.RefDec()
		process.RefDec()
	} else {
		if ec := eventcache.Get(); ec != nil {
			ec.Add(nil, nil, msg.Ktime, msg.Ktime, msg)
		}
	}
	return nil
}

func (msg *MsgProcessCleanupEventUnix) Cast(_ interface{}) notify.Message {
	return &MsgProcessCleanupEventUnix{}
}

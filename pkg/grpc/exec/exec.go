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
	"github.com/cilium/tetragon/pkg/reader/notify"
	"github.com/isovalent/hubble-fgs/pkg/api/ops"
	"github.com/isovalent/hubble-fgs/pkg/nscache"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const (
	ParentRefCnt  = 0
	ProcessRefCnt = 1
)

func (msg *MsgExecveEventUnix) getCleanupEvent() *MsgProcessCleanupEventUnix {
	if msg.Unix.Msg.CleanupProcess.Ktime == 0 {
		return nil
	}
	return &MsgProcessCleanupEventUnix{
		PID:   msg.Unix.Msg.CleanupProcess.Pid,
		Ktime: msg.Unix.Msg.CleanupProcess.Ktime,
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

	proc := process.AddExecEvent(event.Unix)
	fgsProcess := proc.UnsafeGetProcess()

	parentId := fgsProcess.ParentExecId
	parent, err := process.Get(parentId)
	if err == nil {
		parent.RefInc("parent")
		fgsParent = parent.UnsafeGetProcess()
	}

	// Set the cap field only if --enable-process-cred flag is set.
	if err := proc.AnnotateProcess(option.Config.EnableProcessCred, option.Config.EnableProcessNs); err != nil {
		logger.GetLogger().WithError(err).WithField("processId", fgsProcess.ExecId).WithField("parentId", parentId).Debugf("Failed to annotate process with capabilities and namespaces info")
	}

	// Populate fgsAncestors by walking backwards through the parentId links. Some small
	// optimization to push Pod info up if its missing.
	if option.Config.EnableProcessAncestors && fgsParent != nil {
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
		ec.Add(proc, fgsEvent, event.Unix.Msg.Common.Ktime, event.Unix.Process.Ktime, event)
		return nil
	}

	netinum := event.Unix.Msg.Namespaces.NetInum
	if netinum != 0 && fgsEvent.Process.Pod != nil {
		nscache.AddNetNs(uint64(netinum), fgsEvent.Process.Pod, fgsEvent.Process.GetPid().GetValue())
	}

	// Finalize the process event with extra fields
	if err := event.finalize(fgsEvent, proc, eventcache.NO_EV_CACHE); err != nil {
		// Propagate metric errors about finalizing the event
		errormetrics.ErrorTotalInc(errormetrics.EventFinalizeProcessInfoFailed)
		logger.GetLogger().WithFields(logrus.Fields{
			"event.name":            "Execve",
			"event.process.pid":     fgsProcess.GetPid().GetValue(),
			"event.process.binary":  fgsProcess.Binary,
			"event.process.exec_id": fgsProcess.ExecId,
			"event.event_cache":     "no",
		}).Debugf("ExecveEvent: failed to finalize process exec event")
		// For ProcessExec event we do not fail let's return what we have even if it's not complete
		// The eventmetrics will count further errors
	}

	// do we need to cleanup anything?
	if cleanupEvent := event.getCleanupEvent(); cleanupEvent != nil {
		cleanupEvent.HandleMessage()
	}

	return fgsEvent
}

type MsgExecveEventUnix struct {
	Unix *processapi.MsgExecveEventUnix
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
	nspid := msg.Unix.Process.NSPID

	if option.Config.EnableK8s && containerId != "" {
		podInfo = process.GetPodInfo(containerId, filename, args, nspid)
		if podInfo == nil {
			eventcache.CacheRetries(eventcache.PodInfo).Inc()
			return eventcache.ErrFailedToGetPodInfo
		}
		netinum := msg.Unix.Msg.Namespaces.NetInum
		if netinum != 0 && podInfo != nil {
			nscache.AddNetNs(uint64(netinum), podInfo, proc.Pid.Value)
		}
	}

	// We can assume that event.internal != nil here since it's being set by AddExecEvent
	// earlier in the code path. If this invariant ever changes in the future, we probably
	// want to panic anyway to help us catch the bug faster. So no need to do a nil check
	// here.
	internal.AddPodInfo(podInfo)

	// Check we have a parent with exception for pid 1, note we do this last because we want
	// to ensure the podInfo and process are set before returning any errors.
	if proc.Pid.Value > 1 && parent == nil {
		parentId := proc.ParentExecId
		parent, err := process.Get(parentId)
		if parent == nil {
			return err
		}
		parent.RefInc("parent")
		ev.SetParent(parent.UnsafeGetProcess())

		// setup ancestors, we missed parent in the original event so now we can do that
		if e, ok := ev.(*tetragon.ProcessExec); ok {
			var fgsAncestors []*tetragon.Process
			if option.Config.EnableProcessAncestors && parent != nil {
				for _, a := range getAncestors(parent.UnsafeGetProcess()) {
					fgsAncestors = append(fgsAncestors, a.UnsafeGetProcess())
				}
			}
			e.Ancestors = fgsAncestors
		}
	}

	// As of now pod information has been added, finalize the process event with extra fields
	if err := msg.finalize(ev, internal, eventcache.FROM_EV_CACHE); err != nil {
		// Propagate metric errors about finalizing the event
		errormetrics.ErrorTotalInc(errormetrics.EventFinalizeProcessInfoFailed)
		logger.GetLogger().WithFields(logrus.Fields{
			"event.name":            "Execve",
			"event.process.pid":     proc.Pid.GetValue(),
			"event.process.binary":  filename,
			"event.process.exec_id": proc.GetExecId(),
			"event.event_cache":     "yes",
		}).Debugf("ExecveEvent: failed to finalize process exec event")
		// For ProcessExec event we do not fail let's return what we have even if it's not complete
		// The eventmetrics will count further errors
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

// finalize() is called to finalize Process of the event ExecveEvent
//
// The aim of this function is to finalize events by adding or updating some
// fields without propagating those into the process cache.
// These fields could be related to the specific calling event, example only
// for ProcessExec and not ProcessKprobe.
//
// There are two conditions when we could update the event:
//  1. When the event finalize handler return update set to true, for this a deep copy
//     of the process was made, and the related fields added then the event.Process
//     must be set with ev.SetProcess() to this returned copy.
//  2. The finalize() is called from the event cache retry in this
//     case new information could have been added, so let's do another
//     ev.SetProcess() call to update the process of the event.
func (msg *MsgExecveEventUnix) finalize(ev notify.Event, internal *process.ProcessInternal, cache int) error {
	// This should never happen by this time
	if ev.GetProcess() == nil {
		return process.ErrProcessInfoMissing
	}

	proc, update := internal.UpdateExecOutsideCache(option.Config.EnableProcessCred)
	// Update the event.Process entry:
	// If update == true means we made a new copy of the process, added
	//    new information so let's update the event.
	// If we did reach here from the event cache retries then maybe there is
	//    new information let's update the event again.
	if update || cache == eventcache.FROM_EV_CACHE {
		ev.SetProcess(proc)
	}

	return nil
}

func (msg *MsgExecveEventUnix) Notify() bool {
	return true
}

func (msg *MsgExecveEventUnix) HandleMessage() *tetragon.GetEventsResponse {
	var res *tetragon.GetEventsResponse
	switch msg.Unix.Msg.Common.Op {
	case ops.MSG_OP_EXECVE:
		if e := GetProcessExec(msg); e != nil {
			res = &tetragon.GetEventsResponse{
				Event: &tetragon.GetEventsResponse_ProcessExec{ProcessExec: e},
				Time:  ktime.ToProto(msg.Unix.Msg.Common.Ktime),
			}
		}
	default:
		logger.GetLogger().WithField("message", msg).Warn("HandleExecveMessage: Unhandled event")
	}
	return res
}

func (msg *MsgExecveEventUnix) Cast(o interface{}) notify.Message {
	t := o.(processapi.MsgExecveEventUnix)
	return &MsgExecveEventUnix{Unix: &t}
}

type MsgCloneEventUnix struct {
	processapi.MsgCloneEvent
}

func (msg *MsgCloneEventUnix) Notify() bool {
	return false
}

func (msg *MsgCloneEventUnix) RetryInternal(_ notify.Event, _ uint64) (*process.ProcessInternal, error) {
	return process.AddCloneEvent(&msg.MsgCloneEvent)
}

func (msg *MsgCloneEventUnix) Retry(internal *process.ProcessInternal, _ notify.Event) error {
	proc := internal.UnsafeGetProcess()
	if option.Config.EnableK8s && proc.Docker != "" && proc.Pod == nil {
		podInfo := process.GetPodInfo(proc.Docker, proc.Binary, proc.Arguments, msg.NSPID)
		if podInfo == nil {
			eventcache.CacheRetries(eventcache.PodInfo).Inc()
			return eventcache.ErrFailedToGetPodInfo
		}
		internal.AddPodInfo(podInfo)
	}
	return nil
}

// HandleCloneMessage -- don't generate any events. Just add the process to the cache.
func (msg *MsgCloneEventUnix) HandleMessage() *tetragon.GetEventsResponse {
	switch msg.Common.Op {
	case ops.MSG_OP_CLONE:
		ec := eventcache.Get()
		if internal, err := process.AddCloneEvent(&msg.MsgCloneEvent); err == nil {
			if ec != nil && ec.Needed(internal.UnsafeGetProcess()) {
				// adding to the cache due to missing pod info
				ec.Add(internal, nil, msg.MsgCloneEvent.Common.Ktime, msg.MsgCloneEvent.Ktime, msg)
			}
		} else {
			if ec != nil {
				// adding to the cache due to missing parent
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

// MaybeParentRefDec -- If we have RefDec'd a process, we may need to RefDec its parent.
// This function checks if that's the case and does the RefDec if so. It then cascades
// this effect to its parent and so on until we hit a process without a zero ref count.
// It returns true if it did RefDec the parent and false otherwise.
func MaybeParentRefDec(child, parent *process.ProcessInternal) bool {
	// If we don't have a parent, we can't RefDec it.
	if parent == nil {
		return false
	}
	// If we have a process and the ref count is not zero, keep the parent.
	if child != nil && child.RefGet() != 0 {
		return false
	}
	// Either process == nil || process.RefGet() == 0 – remove parent refcnt.
	parent.RefDec("parent")
	// If the parent ref count is now zero, cascade until we hit a process where ref count != 0
	for parent.RefGet() == 0 {
		var err error
		parent, err = process.Get(parent.UnsafeGetProcess().ParentExecId)
		if err != nil {
			// Missing parent so nothing more to do.
			return true
		}
		parent.RefDec("parent")
	}
	return true
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

	// Per thread tracking rules PID == TID.
	//
	// Exit events should have TID==PID at same time we want to correlate
	// the {TID,PID} of the exit event with the {TID,PID} pair from the exec
	// event. They must match because its how we link the exit event to the
	// exec one.
	//
	// The exit event is constructed when looking up the process by its PID
	// from user space cache, so we endup with the TID that was pushed
	// into the process cache during clone or exec.
	//
	// Add extra logic to WARN on conditions where TID!=PID to aid debugging
	// and catch this unexpected case. Typically this indicates a bug either
	// in BPF or userspace caching logic. When this condition is encountered
	// we warn about it, but for the exit event the TID of the cache process
	// will be re-used.
	//
	// Check must be against event.Info.Tid so we cover all the cases of
	// the tetragonProcess.Pid against BPF.
	if fgsProcess.Pid.GetValue() != event.Info.Tid {
		logger.GetLogger().WithFields(logrus.Fields{
			"event.name":           "Exit",
			"event.process.pid":    event.ProcessKey.Pid,
			"event.process.tid":    event.Info.Tid,
			"event.process.binary": fgsProcess.Binary,
		}).Warn("ExitEvent: process PID and TID mismatch")
	}

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
	if process != nil {
		process.RefDec("process")
	}
	MaybeParentRefDec(process, parent)
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
	var err, parentErr error

	if internal != nil {
		ev.SetProcess(internal.UnsafeGetProcess())
		if !msg.RefCntDone[ProcessRefCnt] {
			internal.RefDec("process")
			msg.RefCntDone[ProcessRefCnt] = true
		}
	} else {
		eventcache.CacheRetries(eventcache.ProcessInfo).Inc()
		err = eventcache.ErrFailedToGetProcessInfo
	}

	if parent != nil {
		ev.SetParent(parent.UnsafeGetProcess())
		if !msg.RefCntDone[ParentRefCnt] {
			if MaybeParentRefDec(internal, parent) {
				msg.RefCntDone[ParentRefCnt] = true
			}
		}
	} else {
		eventcache.CacheRetries(eventcache.ParentInfo).Inc()
		parentErr = eventcache.ErrFailedToGetParentInfo
	}

	if err != nil {
		return nil, err
	}
	if parentErr != nil {
		return nil, parentErr
	}

	return internal, nil
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
				Event: &tetragon.GetEventsResponse_ProcessExit{ProcessExit: e},
				Time:  ktime.ToProto(msg.Common.Ktime),
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
	var err, parentErr error

	if internal != nil {
		if !msg.RefCntDone[ProcessRefCnt] {
			internal.RefDec("process")
			msg.RefCntDone[ProcessRefCnt] = true
		}
	} else {
		err = eventcache.ErrFailedToGetProcessInfo
	}

	if parent != nil {
		if !msg.RefCntDone[ParentRefCnt] {
			if MaybeParentRefDec(internal, parent) {
				msg.RefCntDone[ParentRefCnt] = true
			}
		}
	} else {
		parentErr = eventcache.ErrFailedToGetParentInfo
	}

	if err != nil {
		return nil, err
	}
	if parentErr != nil {
		return nil, parentErr
	}

	return internal, nil
}

func (msg *MsgProcessCleanupEventUnix) Retry(_ *process.ProcessInternal, _ notify.Event) error {
	return nil
}

func (msg *MsgProcessCleanupEventUnix) HandleMessage() *tetragon.GetEventsResponse {
	msg.RefCntDone = [2]bool{false, false}
	if process, parent := process.GetParentProcessInternal(msg.PID, msg.Ktime); process != nil && parent != nil {
		process.RefDec("process")
		MaybeParentRefDec(process, parent)
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

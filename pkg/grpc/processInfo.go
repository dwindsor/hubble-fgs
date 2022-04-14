package grpc

import (
	"encoding/base64"
	"fmt"
	"strings"

	v1 "github.com/cilium/hubble/pkg/api/v1"
	"github.com/isovalent/hubble-fgs/api/v1/fgs"
	"github.com/isovalent/hubble-fgs/pkg/api"
	fgsAPI "github.com/isovalent/hubble-fgs/pkg/api"
	"github.com/isovalent/hubble-fgs/pkg/ktime"
	"github.com/isovalent/hubble-fgs/pkg/metrics"
	"github.com/isovalent/hubble-fgs/pkg/reader"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// We handle two race conditions here one where the event races with
// an FGS execve event and the other -- much more common -- where we
// race with K8s watcher
// case 1 (execve race):
//  Its possible to receive this FGS event before the process event cache
//  has been populated with a FGS execve event. In this case we need to
//  cache the event until the process cache is populated.
// case 2 (k8s watcher race):
//  Its possible to receive an event before the k8s watcher receives the
//  podInfo event and populates the local cache. If we expect podInfo,
//  indicated by having a nonZero dockerID we cache the event until the
//  podInfo arrives.
func (pm *ProcessManager) processCacheNeeded(proc *fgs.Process) bool {
	return pm.enableEventCache && (proc == nil || (proc.Docker != "" && proc.Pod == nil))
}

func (pm *ProcessManager) getParentProcessInternal(pid uint32, ktime uint64) (*ProcessInternal, *ProcessInternal) {
	var parent, process *ProcessInternal
	var err error

	processID := pm.GetProcessID(pid, ktime)

	if process, err = pm.cache.get(processID); err != nil {
		pm.log.WithField("id in event", processID).WithField("pid", pid).WithField("ktime", ktime).Debug("process not found in cache")
		return nil, nil
	}

	if parent, err = pm.cache.get(process.process.ParentExecId); err != nil {
		pm.log.WithField("id in event", process.process.ParentExecId).WithField("pid", pid).WithField("ktime", ktime).Debug("parent process not found in cache")
		return process, nil
	}
	return process, parent
}

func (pm *ProcessManager) getProcess(
	process fgsAPI.MsgProcess,
	containerID string,
	parent fgsAPI.MsgExecveKey,
	capabilities fgsAPI.MsgCapabilities,
	namespaces fgsAPI.MsgNamespaces,
) (*ProcessInternal, *v1.Endpoint) {
	args, cwd := reader.ArgsDecoder(process.Args, process.Flags)
	var parentExecID string
	if parent.Pid != 0 {
		parentExecID = pm.GetExecIDFromKey(&parent)
	}
	execID := pm.GetExecID(&process)
	protoPod, endpoint := pm.watcher.GetPodInfo(containerID, process.Filename, args, process.NSPID)
	caps := reader.GetMsgCapabilities(capabilities)
	ns := reader.GetMsgNamespaces(namespaces)
	return &ProcessInternal{
		process: &fgs.Process{
			Pid:          &wrapperspb.UInt32Value{Value: process.PID},
			Uid:          &wrapperspb.UInt32Value{Value: process.UID},
			Cwd:          reader.MarkUnresolvedPathComponentsCwd(cwd, process.Flags),
			Binary:       reader.GetBinaryAbsolutePath(process.Filename, cwd),
			Arguments:    args,
			Flags:        strings.Join(reader.DecodeCommonFlags(process.Flags), " "),
			StartTime:    ktime.ToProtoOpt(process.Ktime, (process.Flags&api.EventProcFS) == 0),
			Auid:         &wrapperspb.UInt32Value{Value: process.AUID},
			Pod:          protoPod,
			ExecId:       execID,
			Docker:       containerID,
			ParentExecId: parentExecID,
			Refcnt:       0,
		},
		capabilities: caps,
		namespaces:   ns,
		refcnt:       1,
	}, endpoint
}

// Add converts an FGS exec event to protobuf format and adds the protobuf message to the cache.
func (pm *ProcessManager) Add(event *fgsAPI.MsgExecveEventUnix) *ProcessInternal {
	proc, _ := pm.getProcess(event.Process, event.Kube.Docker, event.Parent, event.Capabilities, event.Namespaces)
	pm.cache.add(proc)
	var parentExecID string
	if proc.process.Pid != nil {
		parentExecID = pm.cache.getFromPidMap(proc.process.Pid.Value)
		pm.cache.addToPidMap(proc.process.Pid.Value, proc.process.ExecId)
	}
	if strings.Contains(proc.process.Flags, "clone") || strings.Contains(proc.process.Flags, "procFS") {
		return proc
	}
	// This means the exec didn't clone. Look up the most recent exec ID for this PID
	// and use that as the parent.
	parent, err := pm.cache.get(parentExecID)
	if err != nil {
		metrics.ErrorCount.WithLabelValues(string(metrics.NoParentNoClone)).Inc()
		pm.log.WithFields(logrus.Fields{
			"parent exec id": parentExecID,
			"process":        proc,
		}).Debug("parent not found in cache")
		return proc
	}
	if parent.process.ExecId == proc.process.ExecId {
		pm.log.WithFields(logrus.Fields{
			"parent":  parent,
			"current": proc,
		}).Warn("parent and current process has the same exec ID")
		return proc
	}
	proc.process.ParentExecId = parent.process.ExecId
	return proc
}

// getAncestors builds an ancestor list by traversing the parent exec IDs.
func (pm *ProcessManager) getAncestors(proc *fgs.Process) []*ProcessInternal {
	var ancestors []*ProcessInternal
	for parentExecID := proc.ParentExecId; parentExecID != ""; {
		entry, err := pm.cache.get(parentExecID)
		if err != nil {
			pm.log.WithField("id in event", parentExecID).Debug("parent not found in cache")
			break
		}
		ancestors = append(ancestors, entry)
		parentExecID = entry.process.ParentExecId
	}
	return ancestors
}

func (pm *ProcessManager) GetProcessID(pid uint32, ktime uint64) string {
	return base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%d:%d", pm.nodeName, ktime, pid)))
}

// GetExecID returns the exec ID of a given process.
func (pm *ProcessManager) GetExecID(proc *fgsAPI.MsgProcess) string {
	return pm.GetProcessID(proc.PID, proc.Ktime)
}

func (pm *ProcessManager) GetExecIDFromKey(key *fgsAPI.MsgExecveKey) string {
	return pm.GetProcessID(key.Pid, key.Ktime)
}

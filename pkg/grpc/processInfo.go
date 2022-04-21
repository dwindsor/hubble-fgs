package grpc

import (
	"github.com/isovalent/hubble-fgs/api/v1/fgs"
	"github.com/isovalent/hubble-fgs/pkg/logger"
	"github.com/isovalent/hubble-fgs/pkg/process"
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

// getAncestors builds an ancestor list by traversing the parent exec IDs.
func (pm *ProcessManager) getAncestors(proc *fgs.Process) []*process.ProcessInternal {
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

package grpc

import (
	"github.com/isovalent/hubble-fgs/api/v1/fgs"
	"github.com/isovalent/hubble-fgs/pkg/logger"
	"github.com/isovalent/hubble-fgs/pkg/process"
)

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

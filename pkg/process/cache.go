//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package process

import (
	tetragon "github.com/cilium/tetragon/api/v1/tetragon"
	pc "github.com/cilium/tetragon/pkg/process"
	"github.com/cilium/tetragon/pkg/timer"

	metrics "github.com/isovalent/hubble-fgs/pkg/metrics/processcacheclean"
	"github.com/isovalent/hubble-fgs/pkg/option"
)

var (
	gcTimer = timer.NewPeriodicTimer("Process Cache Stale Entry Cleaner", cleanStaleEntries, true)

	// map of exited processes
	exited = make([]string, 0)
)

func Start() {
	gcTimer.Start(option.Config.ProcessCacheStaleInterval)
}

func Stop() {
	gcTimer.Stop()
}

func cleanStaleEntries() {
	__cleanStaleEntries(true)
}

func __cleanStaleEntries(excludeExecveProcesses bool) {
	processes := pc.DumpProcessCache(&tetragon.DumpProcessCacheReqArgs{
		SkipZeroRefcnt:            true,
		ExcludeExecveMapProcesses: excludeExecveProcesses,
	})

	if len(processes) == 0 {
		return
	}

	// There are legitimate reasons why a procss might have a non-zero ref count even after
	// it and its children have exited; for example, out of order events. The cleaner could
	// potentially be run before the associated ref count inc/dec arrives. We therefore don't
	// remove processes the first time we see them, but instead note them and remove them
	// on the next iteration. This provides a minimal grace period equal to the cleaner
	// interval.

	// Remove previously seen processes.
	for _, execId := range exited {
		process, err := pc.Get(execId)
		if err == nil {
			refCnt := int32(process.RefGet())
			if refCnt > 0 {
				metrics.ProcessCacheRemovedStale.Inc()
				for i := int32(0); i < refCnt; i++ {
					process.RefDec("stale")
				}
			} else if refCnt < 0 {
				metrics.ProcessCacheRemovedUnderflow.Inc()
				for i := refCnt; i < 0; i++ {
					process.RefInc("underflow")
				}
			}
		}
	}
	exited = make([]string, 0)

	// Make list of exited processes where all children have exited
	for _, v := range processes {
		if processAndChildrenHaveExited(v) {
			// If we have seen the process before, mark it for deletion.
			exited = append(exited, v.Process.ExecId)
		}
	}
}

func processAndChildrenHaveExited(p *tetragon.ProcessInternal) bool {
	return p.RefcntOps["process++"] == p.RefcntOps["process--"] &&
		p.RefcntOps["parent++"] == p.RefcntOps["parent--"]
}

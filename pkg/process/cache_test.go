// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

//go:build sudo_tests

package process

import (
	"strings"
	"testing"

	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/defaults"
	"github.com/cilium/tetragon/pkg/process"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"

	metrics "github.com/isovalent/hubble-fgs/pkg/metrics/processcacheclean"
)

func createFakeProcess(pid uint32) *processapi.MsgExecveEventUnix {
	proc := processapi.MsgExecveEventUnix{
		Process: processapi.MsgProcess{
			PID: pid,
			TID: pid,
		},
		Msg: &processapi.MsgExecveEvent{
			CleanupProcess: processapi.MsgExecveKey{
				Ktime: 1,
			},
		},
	}
	return &proc
}

func addFakeProcess(pid uint32) {
	proc := createFakeProcess(pid)
	process.AddExecEvent(proc)
}

func TestProcessCacheAddAndRemove(t *testing.T) {
	// create the process cache
	err := process.InitCache(nil, 10, defaults.DefaultProcessCacheGCInterval)
	require.NoError(t, err)
	// add a process to the cache.
	addFakeProcess(1234)
	processes := process.GetCacheEntries()
	require.Equal(t, 1, len(processes))

	execId := process.GetProcessID(1234, 0)

	require.Equal(t, execId, processes[0].Process.ExecId)

	// remove the entry from cache.
	myProcess, err := process.Get(execId)
	require.NoError(t, err)
	myProcess.RefDec("process")

	// check if process is still there (should be) and that its ref count is 0
	myExitingProcess, err := process.Get(execId)
	require.NoError(t, err)
	require.Equal(t, uint32(0), myExitingProcess.RefGet())
}

func TestProcessCacheProcessAndChildrenHaveExited(t *testing.T) {
	// create the process cache
	err := process.InitCache(nil, 10, defaults.DefaultProcessCacheGCInterval)
	require.NoError(t, err)

	addFakeProcess(123)
	// active process has not exited
	processes := process.GetCacheEntries()
	require.Equal(t, 1, len(processes))
	require.False(t, processAndChildrenHaveExited(processes[0]))
	pInt, err := process.Get(process.GetProcessID(123, 0))
	require.NoError(t, err)
	pInt.RefDec("process")
	// completed process has exited
	require.True(t, processAndChildrenHaveExited(processes[0]))

	// set the process as active again
	pInt.RefInc("process")

	pInt.RefInc("parent")
	// active process with child has not exited
	require.False(t, processAndChildrenHaveExited(processes[0]))

	pInt.RefDec("parent")
	// active process with exited child has not exited
	require.False(t, processAndChildrenHaveExited(processes[0]))

	pInt.RefDec("process")
	// completed process with exited child has exited
	require.True(t, processAndChildrenHaveExited(processes[0]))
}

func TestProcessCacheRemoveStale(t *testing.T) {
	// create the process cache
	err := process.InitCache(nil, 10, defaults.DefaultProcessCacheGCInterval)
	require.NoError(t, err)

	// add some processes to the cache.
	for i := 0; i < 8; i++ {
		addFakeProcess(uint32(1234 + i))
	}
	processes := process.GetCacheEntries()
	require.Equal(t, 8, len(processes))

	var p []*process.ProcessInternal
	for i := 0; i < 8; i++ {
		pInt, err := process.Get(process.GetProcessID(uint32(1234+i), 0))
		require.NoError(t, err)
		require.Equal(t, uint32(1), pInt.RefGet())
		p = append(p, pInt)
	}

	p[1].RefDec("process")                     // process exited
	require.Equal(t, uint32(0), p[1].RefGet()) // RefCnt == 0

	p[2].RefDec("process")                     // process exited
	p[2].RefInc("connect")                     // process makes connect
	require.Equal(t, uint32(1), p[2].RefGet()) // RefCnt != 0 but process has exited – ripe for stale cleaning

	p[3].RefDec("process")                     // process exited
	p[3].RefInc("parent")                      // child started
	require.Equal(t, uint32(1), p[3].RefGet()) // children not exited

	p[4].RefDec("process")                     // process exited
	p[4].RefInc("parent")                      // child started
	p[4].RefInc("connect")                     // process makes connect
	require.Equal(t, uint32(2), p[4].RefGet()) // children not exited, process made connect

	p[5].RefDec("process")                     // process exited
	p[5].RefInc("parent")                      // child started
	p[5].RefDec("parent")                      // child exited
	require.Equal(t, uint32(0), p[5].RefGet()) // RefCnt == 0

	p[6].RefDec("process")                     // process exited
	p[6].RefInc("parent")                      // child started
	p[6].RefDec("parent")                      // child exited
	p[6].RefInc("connect")                     // process makes connect
	require.Equal(t, uint32(1), p[6].RefGet()) // RefCnt != 0 but process and children have exited – ripe for stale cleaning

	p[7].RefDec("process")                            // process exited
	p[7].RefDec("close")                              // process closes connect
	require.Equal(t, int32(-1), int32(p[7].RefGet())) // RefCnt != 0 but process and children have exited – ripe for stale cleaning

	// Remove stale entries from cache. Need to run this twice because the first iteration simply
	// marks the processes as exited, and the second (later) iteration actually removes them.
	// We use the internal version of cleanStaleEntries so that we can disable execve map checking.
	__cleanStaleEntries(false)
	__cleanStaleEntries(false)

	// No entries should have been removed yet, but two entries should now have ref count = 0
	// (In real operation, these will later be removed by the process cache.)
	processes = process.GetCacheEntries()
	require.Equal(t, 8, len(processes))

	// Two entries should have been reported as cleaned.
	require.NoError(t, testutil.CollectAndCompare(metrics.ProcessCacheRemovedStale, strings.NewReader(`# HELP tetragon_process_cache_clean_total Number of stale entries cleaned from the process cache.
			# TYPE tetragon_process_cache_clean_total counter
			tetragon_process_cache_clean_total 2
			`)))

	require.NoError(t, testutil.CollectAndCompare(metrics.ProcessCacheRemovedUnderflow, strings.NewReader(`# HELP tetragon_process_cache_underflow_total Number of underflow entries cleaned from the process cache.
			# TYPE tetragon_process_cache_underflow_total counter
			tetragon_process_cache_underflow_total 1
			`)))

	// Confirm entries have expected ref counts
	for i := 0; i < 8; i++ {
		pInt, err := process.Get(p[i].GetProcessCopy().ExecId)
		require.NoError(t, err)
		require.Equal(t, uint32(1234+i), pInt.GetProcessCopy().Pid.Value)
		switch i {
		case 0:
			require.Equal(t, uint32(1), pInt.RefGet())
		case 1:
			require.Equal(t, uint32(0), pInt.RefGet())
		case 2:
			require.Equal(t, uint32(0), pInt.RefGet())
		case 3:
			require.Equal(t, uint32(1), pInt.RefGet())
		case 4:
			require.Equal(t, uint32(2), pInt.RefGet())
		case 5:
			require.Equal(t, uint32(0), pInt.RefGet())
		case 6:
			require.Equal(t, uint32(0), pInt.RefGet())
		case 7:
			require.Equal(t, uint32(0), pInt.RefGet())
		}
	}
}

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
	"testing"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestProcessCache(t *testing.T) {
	// add a process to the cache.
	cache, err := NewCache(10)
	require.NoError(t, err)
	pid := wrapperspb.UInt32Value{Value: 1234}
	execID := "process1"
	proc := ProcessInternal{
		process: &tetragon.Process{
			ExecId: execID,
			Pid:    &pid,
		},
		capabilities: &tetragon.Capabilities{
			Permitted: []tetragon.CapabilitiesType{
				tetragon.CapabilitiesType_CAP_AUDIT_READ,
				tetragon.CapabilitiesType_CAP_AUDIT_WRITE,
			},
		},
	}
	cache.Add(&proc)
	assert.Equal(t, cache.len(), 1)
	cache.AddToPidMap(pid.Value, execID)

	result, err := cache.get(proc.process.ExecId)
	assert.NoError(t, err)
	assert.Equal(t, proc.process.ExecId, result.process.ExecId)
	assert.Equal(t, proc.capabilities, result.capabilities)
	assert.Equal(t, cache.getFromPidMap(pid.Value), execID)

	// remove the entry from cache.
	assert.True(t, cache.remove(proc.process))
	assert.Equal(t, cache.len(), 0)
	assert.Equal(t, cache.pidMap.Len(), 0)
	_, err = cache.get(proc.process.ExecId)
	assert.Error(t, err)
	assert.Equal(t, cache.getFromPidMap(pid.Value), "")
}

package grpc

import (
	"testing"

	"github.com/covalentio/hubble-fgs/api/v1/fgs"
	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProcessCache(t *testing.T) {
	// add a process to the cache.
	cache, err := newProcessCache(logrus.New(), 10)
	require.NoError(t, err)
	pid := wrappers.UInt32Value{Value: 1234}
	execID := "process1"
	proc := processInternal{
		process: &fgs.Process{
			ExecId: execID,
			Pid:    &pid,
		},
		capabilities: &fgs.Capabilities{
			Permitted: []fgs.CapabilitiesType{
				fgs.CapabilitiesType_CAP_AUDIT_READ,
				fgs.CapabilitiesType_CAP_AUDIT_WRITE,
			},
		},
	}
	cache.add(&proc)
	assert.Equal(t, cache.len(), 1)
	cache.addToPidMap(pid.Value, execID)

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

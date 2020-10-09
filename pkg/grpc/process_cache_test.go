package grpc

import (
	"testing"

	"github.com/covalentio/hubble-fgs/api/v1/fgs"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProcessCache(t *testing.T) {
	// add a process to the cache.
	cache, err := newProcessCache(logrus.New(), 10)
	require.NoError(t, err)
	proc := processInternal{
		process: &fgs.Process{
			ExecId: "process1",
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

	result, err := cache.get(proc.process.ExecId)
	assert.NoError(t, err)
	assert.Equal(t, proc.process.ExecId, result.process.ExecId)
	assert.Equal(t, proc.capabilities, result.capabilities)

	// remove the entry from cache.
	assert.True(t, cache.remove(proc.process.ExecId))
	assert.Equal(t, cache.len(), 0)
	_, err = cache.get(proc.process.ExecId)
	assert.Error(t, err)
}

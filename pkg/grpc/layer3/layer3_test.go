// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

// go test -gcflags="" -c ./pkg/grpc/layer3/ -o go-tests/grpc-l3.test
// sudo ./go-tests/grpc-l3.test [ -test.run TestGrpcExec ]

package layer3

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/api/processapi"
	execOSS "github.com/cilium/tetragon/pkg/grpc/exec"
	"github.com/cilium/tetragon/pkg/watcher"
	"github.com/isovalent/hubble-fgs/pkg/api/ops"
	"github.com/isovalent/hubble-fgs/pkg/grpc/exec"
	"github.com/stretchr/testify/assert"
)

func CreateConnectEvents(Pid uint32, Ktime uint64, Docker string) (*MsgIPEventUnix, *MsgIPEventUnix) {
	connectMsg := MsgIPEventUnix{
		Common: processapi.MsgCommon{
			Op:     ops.MSG_OP_TCPCONNECTRET,
			Flags:  0,
			Pad_v2: [2]uint8{0, 0},
			Size:   40,
			Ktime:  21034976281104,
		},
		Kube: processapi.MsgK8sUnix{
			NetNS:  4026531992,
			Cid:    0,
			Cgrpid: 0,
			Docker: Docker,
		},
		ProcessKey: processapi.MsgExecveKey{
			Pid:   Pid,
			Pad:   0,
			Ktime: Ktime,
		},
	}

	closeMsg := MsgIPEventUnix{
		Common: processapi.MsgCommon{
			Op:     ops.MSG_OP_TCPCLOSE,
			Flags:  0,
			Pad_v2: [2]uint8{0, 0},
			Size:   40,
			Ktime:  21034976281104,
		},
		Kube: processapi.MsgK8sUnix{
			NetNS:  4026531992,
			Cid:    0,
			Cgrpid: 0,
			Docker: Docker,
		},
		ProcessKey: processapi.MsgExecveKey{
			Pid:   Pid,
			Pad:   0,
			Ktime: Ktime,
		},
	}

	return &connectMsg, &closeMsg
}

func TestGrpcL3InOrder(t *testing.T) {
	var cancelWg sync.WaitGroup

	execOSS.AllEvents = nil
	watcher := watcher.NewFakeK8sWatcher(nil)
	cancel := execOSS.InitEnv[*exec.MsgExecveEventUnix, *exec.MsgExitEventUnix](t, &cancelWg, watcher)
	defer func() {
		cancel()
		cancelWg.Wait()
	}()

	parentPid := atomic.AddUint32(&execOSS.BasePid, 1)
	currentPid := atomic.AddUint32(&execOSS.BasePid, 1)

	execRoot, execParent, execMsg, exitMsg := execOSS.CreateEvents[*exec.MsgExecveEventUnix, *exec.MsgExitEventUnix](currentPid, 21034975089403, parentPid, 75200000000, "")
	connectMsg, closeMsg := CreateConnectEvents(currentPid, 21034975089403, "")

	if e := (*execRoot).HandleMessage(); e != nil {
		execOSS.AllEvents = append(execOSS.AllEvents, e)
	}

	if e := (*execParent).HandleMessage(); e != nil {
		execOSS.AllEvents = append(execOSS.AllEvents, e)
	}

	if e := (*execMsg).HandleMessage(); e != nil {
		execOSS.AllEvents = append(execOSS.AllEvents, e)
	}

	if e := (*connectMsg).HandleMessage(); e != nil {
		execOSS.AllEvents = append(execOSS.AllEvents, e)
	}

	if e := (*closeMsg).HandleMessage(); e != nil {
		execOSS.AllEvents = append(execOSS.AllEvents, e)
	}

	if e := (*exitMsg).HandleMessage(); e != nil {
		execOSS.AllEvents = append(execOSS.AllEvents, e)
	}

	assert.Equal(t, len(execOSS.AllEvents), 6)

	var execRootEv, execParentEv, execEv *tetragon.ProcessExec
	var exitEv *tetragon.ProcessExit
	var connectEv *tetragon.ProcessConnect
	var closeEv *tetragon.ProcessClose

	for _, ev := range execOSS.AllEvents {
		if ev.GetProcessExec() != nil {
			tmp := ev.GetProcessExec()
			if tmp.Process.Pid.Value == uint32(1) {
				execRootEv = tmp
			} else if tmp.Process.Pid.Value == uint32(parentPid) {
				execParentEv = tmp
			} else if tmp.Process.Pid.Value == uint32(currentPid) {
				execEv = tmp
			}

		} else if ev.GetProcessExit() != nil {
			exitEv = ev.GetProcessExit()
		} else if ev.GetProcessConnect() != nil {
			connectEv = ev.GetProcessConnect()
		} else if ev.GetProcessClose() != nil {
			closeEv = ev.GetProcessClose()
		}
	}

	assert.NotNil(t, execRootEv)
	assert.NotNil(t, execParentEv)
	assert.NotNil(t, execEv)
	assert.NotNil(t, exitEv)
	assert.NotNil(t, connectEv)
	assert.NotNil(t, closeEv)

	assert.Equal(t, execOSS.GetProcessRefcntFromCache(t, 1, 0), uint32(2))
	assert.Equal(t, execOSS.GetProcessRefcntFromCache(t, parentPid, 75200000000), uint32(1))
	assert.Equal(t, execOSS.GetProcessRefcntFromCache(t, currentPid, 21034975089403), uint32(0))

	// check parents
	assert.Nil(t, execRootEv.Parent)
	assert.NotNil(t, execParentEv.Parent)
	assert.NotNil(t, execEv.Parent)
	assert.NotNil(t, exitEv.Parent)
	assert.NotNil(t, connectEv.Parent)
	assert.NotNil(t, closeEv.Parent)

	// check that all events have the same process info
	execEv.Process.Refcnt = 0
	exitEv.Process.Refcnt = 0
	connectEv.Process.Refcnt = 0
	closeEv.Process.Refcnt = 0
	assert.Equal(t, execEv.Process, exitEv.Process)
	assert.Equal(t, execEv.Process, connectEv.Process)
	assert.Equal(t, execEv.Process, closeEv.Process)

	// check that all events have the same parent info
	execEv.Parent.Refcnt = 0
	exitEv.Parent.Refcnt = 0
	connectEv.Parent.Refcnt = 0
	closeEv.Parent.Refcnt = 0
	assert.Equal(t, execEv.Parent, exitEv.Parent)
	assert.Equal(t, execEv.Parent, connectEv.Parent)
	assert.Equal(t, execEv.Parent, closeEv.Parent)
}

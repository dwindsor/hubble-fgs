// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

// go test -gcflags="" -c ./pkg/grpc/layer3/ -o go-tests/grpc-l3.test
// sudo ./go-tests/grpc-l3.test [ -test.run TestGrpcExec ]

package layer3

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	tetragonAPI "github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/cilium"
	"github.com/cilium/tetragon/pkg/eventcache"
	execOSS "github.com/cilium/tetragon/pkg/grpc/exec"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/process"
	"github.com/cilium/tetragon/pkg/rthooks"
	"github.com/cilium/tetragon/pkg/server"
	"github.com/cilium/tetragon/pkg/watcher"
	"github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	"github.com/isovalent/hubble-fgs/pkg/api/ops"
	"github.com/isovalent/hubble-fgs/pkg/grpc/exec"
	"github.com/stretchr/testify/assert"
)

func CreateConnectEvents(Pid uint32, Ktime uint64, Docker string) (*MsgIPEventUnix, *MsgIPWithStatsEventUnix) {
	connectMsg := MsgIPEventUnix{
		Msg: &networkapi.MsgIPEvent{
			Common: tetragonAPI.MsgCommon{
				Op:     ops.MSG_OP_TCPCONNECTRET,
				Flags:  0,
				Pad_v2: [2]uint8{0, 0},
				Size:   40,
				Ktime:  0,
			},
			ProcessKey: tetragonAPI.MsgExecveKey{
				Pid:   Pid,
				Pad:   0,
				Ktime: Ktime,
			},
		},
		Kube: tetragonAPI.MsgK8sUnix{
			Docker: Docker,
		},
	}

	closeMsg := MsgIPWithStatsEventUnix{
		Msg: &networkapi.MsgIPWithStatsEvent{
			MsgIPEvent: networkapi.MsgIPEvent{
				Common: tetragonAPI.MsgCommon{
					Op:     ops.MSG_OP_TCPCLOSE,
					Flags:  0,
					Pad_v2: [2]uint8{0, 0},
					Size:   40,
					Ktime:  0,
				},
				ProcessKey: tetragonAPI.MsgExecveKey{
					Pid:   Pid,
					Pad:   0,
					Ktime: Ktime,
				},
			},
		},
		Kube: tetragonAPI.MsgK8sUnix{
			Docker: Docker,
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
	execOSS.CheckProcessEqual(t, execEv.Process, exitEv.Process)
	execOSS.CheckProcessEqual(t, execEv.Process, connectEv.Process)
	execOSS.CheckProcessEqual(t, execEv.Process, closeEv.Process)

	// check that all events have the same parent info
	execOSS.CheckProcessEqual(t, execEv.Parent, exitEv.Parent)
	execOSS.CheckProcessEqual(t, execEv.Parent, connectEv.Parent)
	execOSS.CheckProcessEqual(t, execEv.Parent, closeEv.Parent)
}

func createExecEvent(Pid uint32, Ktime uint64, ParentPid uint32, ParentKtime uint64, Filename string) *exec.MsgExecveEventUnix {
	tmpEv := tetragonAPI.MsgExecveEventUnix{
		Msg: &tetragonAPI.MsgExecveEvent{
			Common: tetragonAPI.MsgCommon{
				Op:     ops.MSG_OP_EXECVE,
				Flags:  0,
				Pad_v2: [2]uint8{0, 0},
				Size:   326,
				Ktime:  0,
			},
			Kube: tetragonAPI.MsgK8s{
				NetNS:  4026531992,
				Cid:    0,
				Cgrpid: 0,
			},
			Parent: tetragonAPI.MsgExecveKey{
				Pid:   ParentPid,
				Pad:   0,
				Ktime: ParentKtime,
			},
			ParentFlags: 0,
		},
		Kube: tetragonAPI.MsgK8sUnix{
			Docker: "",
		},
		Process: tetragonAPI.MsgProcess{
			Size:     78,
			PID:      Pid,
			NSPID:    0,
			UID:      1010,
			AUID:     1010,
			Flags:    16385,
			Ktime:    Ktime,
			Filename: Filename,
			Args:     "--some-random-args\x00/root/cwd",
		},
	}
	return &exec.MsgExecveEventUnix{Unix: &tmpEv}
}

func createExitEvent(Pid uint32, Ktime uint64) *exec.MsgExitEventUnix {
	tmpEv := tetragonAPI.MsgExitEvent{
		Common: tetragonAPI.MsgCommon{
			Op:     ops.MSG_OP_EXIT,
			Flags:  0,
			Pad_v2: [2]uint8{0, 0},
			Size:   40,
			Ktime:  0,
		},
		ProcessKey: tetragonAPI.MsgExecveKey{
			Pid:   Pid,
			Pad:   0,
			Ktime: Ktime,
		},
		Info: tetragonAPI.MsgExitInfo{
			Code: 0,
			Tid:  0,
		},
	}
	return &exec.MsgExitEventUnix{MsgExitEvent: tmpEv}
}

type DummyNotifier struct {
	t *testing.T
}

func (n DummyNotifier) AddListener(_ server.Listener) {}

func (n DummyNotifier) RemoveListener(_ server.Listener) {}

func (n DummyNotifier) NotifyListener(original interface{}, processed *tetragon.GetEventsResponse) {
	switch v := original.(type) {
	case *exec.MsgExecveEventUnix:
	case *exec.MsgExitEventUnix:
	case *MsgIPEventUnix:
	case *MsgIPWithStatsEventUnix:
		if processed != nil {
			execOSS.AllEvents = append(execOSS.AllEvents, processed)
		} else {
			n.t.Fatalf("Processed arg is nil in NotifyListener with type %T", v)
		}
	default:
		n.t.Fatalf("Unknown type in NotifyListener = %T", v)
	}
}

func initEnv(t *testing.T, cancelWg *sync.WaitGroup, watcher watcher.K8sResourceWatcher) context.CancelFunc {
	ctx, cancel := context.WithCancel(context.Background())

	_, err := cilium.InitCiliumState(ctx, false)
	if err != nil {
		t.Fatalf("failed to call cilium.InitCiliumState %s", err)
	}

	if err := process.InitCache(watcher, 65536); err != nil {
		t.Fatalf("failed to call process.InitCache %s", err)
	}

	if err := observer.InitDataCache(1024); err != nil {
		t.Fatalf("failed to call observer.InitDataCache %s", err)
	}

	dn := DummyNotifier{t}
	do := &server.FakeObserver{}
	dr := rthooks.DummyHookRunner{}
	lServer := server.NewServer(ctx, cancelWg, dn, do, dr)

	// Exec cache is always needed to ensure events have an associated Process{}
	eventcache.NewWithTimer(lServer, time.Millisecond*execOSS.CacheTimerMs)

	return cancel
}

func TestGrpcL3CloseFirst(t *testing.T) {
	var cancelWg sync.WaitGroup

	execOSS.AllEvents = nil
	watcher := watcher.NewFakeK8sWatcher(nil)
	cancel := initEnv(t, &cancelWg, watcher)
	defer func() {
		cancel()
		cancelWg.Wait()
	}()

	parentPid := atomic.AddUint32(&execOSS.BasePid, 1)
	currentPid := atomic.AddUint32(&execOSS.BasePid, 1)
	execRoot, _, _, _ := execOSS.CreateEvents[*exec.MsgExecveEventUnix, *exec.MsgExitEventUnix](currentPid, 21034975089403, parentPid, 75200000000, "")

	execParent := createExecEvent(1000, 11111, 1, 0, "/usr/bin/containerd")
	exitParent := createExitEvent(1000, 11111)

	execRunc := createExecEvent(2000, 22222, 1000, 11111, "/usr/bin/runc")
	exitRunc := createExitEvent(2000, 22222)

	execNc := createExecEvent(2000, 33333, 1000, 11111, "/usr/bin/nc")
	exitNc := createExitEvent(2000, 33333)

	connectMsg, closeMsg := CreateConnectEvents(2000, 33333, "")

	(*execRoot).HandleMessage() // we will not check root process

	if e := (*execParent).HandleMessage(); e != nil { // exec containerd with pid 1000 and ktime 11111
		execOSS.AllEvents = append(execOSS.AllEvents, e)
	}

	if e := (*execRunc).HandleMessage(); e != nil { // exec runc with pid 2000 and ktime 22222
		execOSS.AllEvents = append(execOSS.AllEvents, e)
	}

	// OOO events start

	if e := (*closeMsg).HandleMessage(); e != nil { // close nc with pid 2000 and ktime 33333
		execOSS.AllEvents = append(execOSS.AllEvents, e)
	}

	if e := (*execNc).HandleMessage(); e != nil { // exec nc with pid 2000 and ktime 33333
		execOSS.AllEvents = append(execOSS.AllEvents, e)
	}

	if e := (*connectMsg).HandleMessage(); e != nil { // connect nc with pid 2000 and ktime 33333
		execOSS.AllEvents = append(execOSS.AllEvents, e)
	}

	if e := (*exitNc).HandleMessage(); e != nil { // exit nc with pid 2000 and ktime 33333
		execOSS.AllEvents = append(execOSS.AllEvents, e)
	}

	// OOO events end

	if e := (*exitRunc).HandleMessage(); e != nil { // exit runc with pid 2000 and ktime 22222
		execOSS.AllEvents = append(execOSS.AllEvents, e)
	}

	if e := (*exitParent).HandleMessage(); e != nil { // exit containerd with pid 1000 and ktime 11111
		execOSS.AllEvents = append(execOSS.AllEvents, e)
	}

	time.Sleep(time.Millisecond * ((eventcache.CacheStrikes + 4) * execOSS.CacheTimerMs)) // wait for cache to do it's work

	assert.Equal(t, len(execOSS.AllEvents), 8)

	var execParentEv, execRuncEv, execNcEv *tetragon.ProcessExec
	var exitParentEv, exitRuncEv, exitNcEv *tetragon.ProcessExit
	var connectEv *tetragon.ProcessConnect
	var closeEv *tetragon.ProcessClose

	for _, ev := range execOSS.AllEvents {
		if ev.GetProcessExec() != nil {
			tmp := ev.GetProcessExec()
			if tmp.Process.Pid.Value == uint32(1000) && tmp.Process.Binary == "/usr/bin/containerd" {
				execParentEv = tmp
			} else if tmp.Process.Pid.Value == uint32(2000) && tmp.Process.Binary == "/usr/bin/runc" {
				execRuncEv = tmp
			} else if tmp.Process.Pid.Value == uint32(2000) && tmp.Process.Binary == "/usr/bin/nc" {
				execNcEv = tmp
			}
		} else if ev.GetProcessExit() != nil {
			tmp := ev.GetProcessExit()
			if tmp.Process.Pid.Value == uint32(1000) && tmp.Process.Binary == "/usr/bin/containerd" {
				exitParentEv = tmp
			} else if tmp.Process.Pid.Value == uint32(2000) && tmp.Process.Binary == "/usr/bin/runc" {
				exitRuncEv = tmp
			} else if tmp.Process.Pid.Value == uint32(2000) && tmp.Process.Binary == "/usr/bin/nc" {
				exitNcEv = tmp
			}
		} else if ev.GetProcessConnect() != nil {
			connectEv = ev.GetProcessConnect()
		} else if ev.GetProcessClose() != nil {
			closeEv = ev.GetProcessClose()
		}
	}

	assert.NotNil(t, execParentEv)
	assert.NotNil(t, execRuncEv)
	assert.NotNil(t, execNcEv)
	assert.NotNil(t, exitParentEv)
	assert.NotNil(t, exitRuncEv)
	assert.NotNil(t, exitNcEv)
	assert.NotNil(t, connectEv)
	assert.NotNil(t, closeEv)

	assert.NotNil(t, execParentEv.Parent)
	assert.NotNil(t, execRuncEv.Parent)
	assert.NotNil(t, execNcEv.Parent)
	assert.NotNil(t, exitParentEv.Parent)
	assert.NotNil(t, exitRuncEv.Parent)
	assert.NotNil(t, exitNcEv.Parent)
	assert.NotNil(t, connectEv.Parent)
	assert.NotNil(t, closeEv.Parent)

	assert.Equal(t, execOSS.GetProcessRefcntFromCache(t, 1, 0), uint32(1))
	assert.Equal(t, execOSS.GetProcessRefcntFromCache(t, 1000, 11111), uint32(0))
	assert.Equal(t, execOSS.GetProcessRefcntFromCache(t, 2000, 22222), uint32(0))
	assert.Equal(t, execOSS.GetProcessRefcntFromCache(t, 2000, 33333), uint32(0))

	assert.Equal(t, execParentEv.Process.Pid.Value, uint32(1000))
	assert.Equal(t, execParentEv.Process.Binary, "/usr/bin/containerd")

	assert.Equal(t, execRuncEv.Process.Pid.Value, uint32(2000))
	assert.Equal(t, execRuncEv.Process.Binary, "/usr/bin/runc")

	assert.Equal(t, execNcEv.Process.Pid.Value, uint32(2000))
	assert.Equal(t, execNcEv.Process.Binary, "/usr/bin/nc")

	assert.Equal(t, exitParentEv.Process.Pid.Value, uint32(1000))
	assert.Equal(t, exitParentEv.Process.Binary, "/usr/bin/containerd")

	assert.Equal(t, exitRuncEv.Process.Pid.Value, uint32(2000))
	assert.Equal(t, exitRuncEv.Process.Binary, "/usr/bin/runc")

	assert.Equal(t, exitNcEv.Process.Pid.Value, uint32(2000))
	assert.Equal(t, exitNcEv.Process.Binary, "/usr/bin/nc")

	assert.Equal(t, connectEv.Process.Pid.Value, uint32(2000))
	assert.Equal(t, connectEv.Process.Binary, "/usr/bin/nc")

	assert.Equal(t, closeEv.Process.Pid.Value, uint32(2000))
	assert.Equal(t, closeEv.Process.Binary, "/usr/bin/nc")

	execOSS.CheckProcessEqual(t, execNcEv.Process, exitNcEv.Process)
	execOSS.CheckProcessEqual(t, execNcEv.Process, connectEv.Process)
	execOSS.CheckProcessEqual(t, execNcEv.Process, closeEv.Process)

	execOSS.CheckProcessEqual(t, execParentEv.Process, exitParentEv.Process)
	//
	execOSS.CheckProcessEqual(t, execNcEv.Parent, execParentEv.Process)
	execOSS.CheckProcessEqual(t, exitNcEv.Parent, execParentEv.Process)
	execOSS.CheckProcessEqual(t, connectEv.Parent, execParentEv.Process)
	execOSS.CheckProcessEqual(t, closeEv.Parent, execParentEv.Process)
}

//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.
//
package observer

import (
	"fmt"
	"path/filepath"
	"time"
	"unsafe"

	"github.com/isovalent/hubble-fgs/pkg/api"
	"github.com/isovalent/hubble-fgs/pkg/bpf"
	"github.com/isovalent/hubble-fgs/pkg/btf"
	"github.com/isovalent/hubble-fgs/pkg/sensors"
)

type ExecveKey struct {
	Pid uint32
}

type ExecveValueL struct {
	Common       api.MsgCommon
	Kube         api.MsgK8s
	Parent       api.MsgExecveKey
	ParentFlags  uint64
	Capabilities api.MsgCapabilities
}

type ExecveValue struct {
	Process api.MsgExecveKey
	Parent  api.MsgExecveKey
	Flags   uint32
	Nspid   uint32
	Buffer  uint64
}

func (k *ExecveKey) String() string             { return fmt.Sprintf("key=%d", k.Pid) }
func (k *ExecveKey) GetKeyPtr() unsafe.Pointer  { return unsafe.Pointer(k) }
func (k *ExecveKey) DeepCopyMapKey() bpf.MapKey { return &ExecveKey{k.Pid} }

func (k *ExecveKey) NewValue() bpf.MapValue { return &ExecveValue{} }

func (v *ExecveValue) String() string {
	return fmt.Sprintf("value=%d %s", 0, "")
}
func (v *ExecveValue) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }
func (v *ExecveValue) DeepCopyMapValue() bpf.MapValue {
	return &ExecveValue{}
}

func (k *Observer) pushExecveEvents(p ObserverProcs, tcpEntries map[uint32]procTCPEntry, pushExecve, writeMaps bool) {
	var err error
	var i int

	args, filename := procsFilename(p.args)
	cwd, flags := getCWD(p.pid)
	if (flags & api.EventRootCWD) == 0 {
		args = args + " " + cwd
	}

	m := api.MsgExecveEventUnix{}
	m.Common.Op = api.MSG_OP_EXECVE
	m.Common.Size = api.MsgUnixSize + p.psize + p.size

	m.Kube.NetNS = 0
	m.Kube.Cid = 0
	m.Kube.Cgrpid = 0
	m.Kube.Docker, i, err = procsDockerId(p.pid)
	if err != nil {
		k.log.WithError(err).Warn("Procfs execve event pods/ identifier error")
	} else if i > 0 {
		err := procDockerIdOffsetWriter(i, btf.GetCachedBTF())
		if err != nil {
			k.log.WithError(err).Warn("Write to Docker ID BTF error")
		}
		k.dockerIdOffsetWriter = i
	}

	m.Parent.Pid = p.ppid
	m.Parent.Ktime = p.pktime

	m.Capabilities.Permitted = p.permitted
	m.Capabilities.Effective = p.effective
	m.Capabilities.Inheritable = p.inheritable

	m.Process.Size = p.size
	m.Process.PID = p.pid
	m.Process.NSPID = p.nspid
	m.Process.UID = p.uid
	m.Process.AUID = p.auid
	m.Process.Flags = p.flags | flags
	m.Process.Ktime = p.ktime
	m.Common.Ktime = p.ktime
	m.Process.Filename = filename
	m.Process.Args = args

	if pushExecve {
		k.observerListeners(&m)
	}
	/* Collect any existing TCP sockets on PID and generate events. */
	k.pushTCPEvents(&m, tcpEntries, writeMaps, pushExecve)
}

func (k *Observer) writeExecveMap(procs []ObserverProcs) {

	if sensors.ExecveMap.PinState.IsDisabled() {
		k.log.Infof("hubble-fgs, map %s is disabled, skipping.", sensors.ExecveMap.Name)
		return
	}

	if sensors.ExecveMap.PinState.IsLoaded() {
		k.log.Infof("hubble-fgs, map %s is already loaded, skipping.", sensors.ExecveMap.Name)
		return
	}

	m, err := bpf.OpenMap(filepath.Join(k.mapDir, sensors.ExecveMap.Name))
	for i := 0; err != nil; i++ {
		m, err = bpf.OpenMap(filepath.Join(k.mapDir, sensors.ExecveMap.Name))
		if err != nil {
			time.Sleep(mapRetryDelay * time.Second)
		}
		if i > maxMapRetries {
			panic(err)
		}
	}
	for _, p := range procs {
		k := &ExecveKey{Pid: p.pid}
		v := &ExecveValue{}

		v.Parent.Pid = p.ppid
		v.Parent.Ktime = p.pktime
		v.Process.Pid = p.pid
		v.Process.Ktime = p.ktime
		v.Flags = 0
		v.Nspid = p.nspid
		v.Buffer = 0

		m.Update(k, v)
	}
	m.Close()
}

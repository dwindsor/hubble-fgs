//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

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

var (
	kernelPid = uint32(0)
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

func (k *Observer) procKernel() Procs {
	kernelArgs := []byte("<kernel>\u0000")
	return Procs{
		psize:       uint32(api.MSG_SIZEOF_EXECVE + len(kernelArgs) + api.MSG_SIZEOF_CWD),
		ppid:        kernelPid,
		pnspid:      0,
		pflags:      api.EventProcFS,
		pktime:      1,
		pargs:       kernelArgs,
		size:        uint32(api.MSG_SIZEOF_EXECVE + len(kernelArgs) + api.MSG_SIZEOF_CWD),
		uid:         0,
		pid:         kernelPid,
		nspid:       0,
		auid:        0,
		flags:       api.EventProcFS,
		ktime:       1,
		args:        kernelArgs,
		effective:   0,
		inheritable: 0,
		permitted:   0,
	}
}

func (k *Observer) pushExecveEvents(p Procs, tcpEntries map[uint32]procTCPEntry, pushExecve, writeMaps bool) {
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

	m.Namespaces.UtsInum = p.uts_ns
	m.Namespaces.IpcInum = p.ipc_ns
	m.Namespaces.MntInum = p.mnt_ns
	m.Namespaces.PidInum = p.pid_ns
	m.Namespaces.PidChildInum = p.pid_for_children_ns
	m.Namespaces.NetInum = p.net_ns
	m.Namespaces.TimeInum = p.time_ns
	m.Namespaces.TimeChildInum = p.time_for_children_ns
	m.Namespaces.CgroupInum = p.cgroup_ns
	m.Namespaces.UserInum = p.user_ns

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

func (k *Observer) writeExecveMap(procs []Procs) {
	execveMap := sensors.GetExecveMap()

	if execveMap.PinState.IsDisabled() {
		k.log.Infof("hubble-fgs, map %s is disabled, skipping.", execveMap.Name)
		return
	}

	m, err := bpf.OpenMap(filepath.Join(k.mapDir, execveMap.Name))
	for i := 0; err != nil; i++ {
		m, err = bpf.OpenMap(filepath.Join(k.mapDir, execveMap.Name))
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
	// In order for kprobe events from kernel ctx to not abort we need the
	// execve lookup to map to a valid entry. So to simplify the kernel side
	// and avoid having to add another branch of logic there to handle pid==0
	// case we simply add it here.
	m.Update(&ExecveKey{Pid: kernelPid}, &ExecveValue{
		Parent: api.MsgExecveKey{
			Pid:   kernelPid,
			Ktime: 1},
		Process: api.MsgExecveKey{
			Pid:   kernelPid,
			Ktime: 1,
		},
		Flags:  0,
		Nspid:  0,
		Buffer: 0,
	})
	m.Close()
}

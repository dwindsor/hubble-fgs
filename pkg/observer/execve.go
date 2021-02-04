package observer

import (
	"fmt"
	"unsafe"

	"github.com/covalentio/hubble-fgs/pkg/api"
	"github.com/covalentio/hubble-fgs/pkg/bpf"
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

func (k *ObserverKprobe) pushExecveEvents(p ObserverProcs, tcpEntries map[uint32]procTCPEntry, pushExecve bool) {
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
		k.log.Warn("Procfs execve event pods/ identifier error: %s\n", err)
	} else if i > 0 {
		err := procDockerIdOffsetWriter(i, k.btfObj)
		if err != nil {
			k.log.Warn("procDockerIdOffsetWriter error: %s", err)
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
		k.observerListenersExecve(&m)
	}
	/* Collect any existing TCP sockets on PID and generate events. */
	k.pushTCPEvents(&m, tcpEntries)
}

func (k *ObserverKprobe) writeExecveMap(procs []ObserverProcs) {

	if ObserverExecveMap.pinState.isDisabled() {
		k.log.Infof("hubble-fgs, map %s is disabled, skipping.\n", ObserverExecveMap.mapName)
		return
	}

	if ObserverExecveMap.pinState.isLoaded() {
		k.log.Infof("hubble-fgs, map %s is already loaded, skipping.\n", ObserverExecveMap.mapName)
		return
	}

	m, err := bpf.OpenMap(filepath.Join(k.mapDir, ObserverExecveMap.mapName))
	for i := 0; err != nil; i++ {
		m, err = bpf.OpenMap(filepath.Join(k.mapDir, ObserverExecveMap.mapName))
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

		m.Update(k, v)
	}
	m.Close()
}

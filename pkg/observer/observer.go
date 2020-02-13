// Copyright 2019 Authors of Hubble
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package observer

import (
	"github.com/covalentio/hubble-fgs/pkg/api"
	"github.com/covalentio/hubble-fgs/pkg/bpf"
	"github.com/covalentio/hubble-fgs/pkg/logger"
	"github.com/covalentio/hubble-fgs/pkg/reader"

	"bytes"
	"context"
	"encoding/binary"
	"encoding/gob"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"
	"unsafe"

	"go.uber.org/zap"
)

const (
	Progsize = 64
	MaxArgs  = 5
	ArgSize  = 32

	nanoPerSeconds = 1000000000
)

type bpfLoad struct {
	Observer__btf        string
	Observer__program    string
	observer__x64_attach string
	observer__attach     string
	observer__label      string
	observer__prog       string

	retProbe   bool
	errorFatal bool
}

var (
	LostCntr  = 0
	ErrorCntr = 0
	RecvCntr  = 0

	ProcFS        = "/proc/"
	KernelVersion = ""
	EnableExecve  = false

	ObserverBTF string
	BPFMaps     = []string{"execve_map", "tcpmon_map"}

	ObserverExecve = bpfLoad{
		"", "",
		"__x64_sys_execve",
		"sys_execve",
		"kprobe/sys_execve",
		"kprobe_execve",

		false,
		true,
	}

	ObserverExecveat = bpfLoad{
		"", "",
		"__x64_sys_execveat",
		"sys_execveat",
		"kprobe/sys_execveat",
		"kprobe_execveat",

		false,
		true,
	}

	ObserverFork = bpfLoad{
		"", "",
		"wake_up_new_task",
		"wake_up_new_task",
		"kprobe/wake_up_new_task",
		"kprobe_pid_clear",

		false,
		true,
	}

	ObserverTCPConnect = bpfLoad{
		"", "",
		"tcp_connect",
		"tcp_connect",
		"kprobe/tcp_connect",
		"kprobe_tcp_connect",

		false,
		true,
	}

	ObserverTCPConnectRet = bpfLoad{
		"", "",
		"__x64_sys_connect",
		"sys_connect",
		"kretprobe/sys_connect",
		"kretprobe_sys_connect",

		true,
		true,
	}

	ObserverBind = bpfLoad{
		"", "",
		"inet_bind",
		"inet_bind",
		"kprobe/sys_bind",
		"kprobe_sys_bind",

		false,
		true,
	}

	ObserverGetPort = bpfLoad{
		"", "",
		"inet_bind_hash",
		"inet_bind_hash",
		"kprobe/inet_bind_hash",
		"kprobe_inet_bind_hash",

		false,
		true,
	}

	ObserverListen = bpfLoad{
		"", "",
		"__x64_sys_listen",
		"sys_listen",
		"kprobe/sys_listen",
		"kprobe_sys_listen",
		false,
		true,
	}

	observerTimeout = 5 * time.Minute
	execTimeout     = 5 * time.Minute
	pollTimeout     = 5000

	zlog *zap.Logger
)

func (k *ObserverKprobe) observerListeners(msg *api.MsgIPv4TcpConnectUnix) {
	for _, c := range k.listeners {
		if err := c.encoder.Encode(msg); err != nil {
			zlog.Debug("Write failure removing Listener", zap.Error(err))
			k.RemoveListener(c.conn)
		}
	}
}

func (k *ObserverKprobe) AddListener(conn net.Conn) {
	channel := ObserverChannel{}
	channel.encoder = gob.NewEncoder(conn)
	channel.conn = conn
	k.listeners = append(k.listeners, channel)
	if EnableExecve {
		k.getRunningProcs(false, true)
	}
}

func (k *ObserverKprobe) RemoveListener(conn net.Conn) {
	for i, c := range k.listeners {
		if c.conn == conn {
			fmt.Printf("delete listener %v\n", conn)
			k.listeners = append(k.listeners[:i], k.listeners[i+1:]...)
		}
		fmt.Printf("walking listener %v\n", conn)
	}
}

func msgToUnix(m *api.MsgIPv4TcpConnect) *api.MsgIPv4TcpConnectUnix {
	unix := &api.MsgIPv4TcpConnectUnix{}

	unix.Common = m.Common
	unix.Tuple = m.Tuple

	unix.Kube.NetNS = m.Kube.NetNS
	unix.Kube.Cid = m.Kube.Cid
	unix.Kube.Cgrpid = m.Kube.Cgrpid
	unix.Kube.Docker = strings.Trim(string(m.Kube.Docker[:]), "\u0000")

	unix.Return = m.Return
	return unix
}

func nopMsgExecUnix() api.MsgExecUnix {
	execUnix := api.MsgExecUnix{}

	execUnix.Size = 0
	execUnix.PID = 0
	execUnix.UID = 0
	execUnix.Filename = "<enomem>"
	execUnix.Args = "<enomem>"
	return execUnix
}

func execParse(reader *bytes.Reader) (api.MsgExecUnix, bool, error) {
	execUnix := api.MsgExecUnix{}
	exec := api.MsgExec{}

	if err := binary.Read(reader, binary.LittleEndian, &exec); err != nil {
		return execUnix, true, err
	}

	execUnix.Size = exec.Size
	execUnix.PID = exec.PID
	execUnix.UID = exec.UID
	execUnix.Flags = exec.Flags
	execUnix.Ktime = exec.Ktime
	execUnix.AUID = exec.AUID

	size := exec.Size - api.SIZEOF_EXECVE
	if size > api.ARGSBUFFER {
		err := fmt.Errorf("msg exec size larger than argsbuffer")
		exec.Size = api.SIZEOF_EXECVE
		execUnix.Args = "enomem enomem"
		execUnix.Filename = "enomem"
		return execUnix, false, err
	} else {
		args := make([]byte, size)
		if err := binary.Read(reader, binary.LittleEndian, &args); err != nil {
			execUnix.Size = api.SIZEOF_EXECVE
			execUnix.Args = "enomem enomem"
			execUnix.Filename = "enomem"
			return execUnix, false, err
		} else {
			cmdArgs := bytes.Split(args, []byte{0x00})
			execUnix.Filename = string(cmdArgs[0])
			execUnix.Args = string(bytes.Join(cmdArgs[1:], []byte{0x00}))
		}
	}

	return execUnix, false, nil
}

func (k *ObserverKprobe) receiveEvent(msg *bpf.PerfEventSample, cpu int) {
	data := msg.DataDirect()
	var op uint8 = data[0]
	var empty bool

	RecvCntr++
	r := bytes.NewReader(data)

	switch op {
	case api.MSG_OP_IPV4_TCPCONNECT,
		api.MSG_OP_IPV4_TCPCONNECTRET,
		api.MSG_OP_IPV4_BIND,
		api.MSG_OP_IPV4_LISTEN,
		api.MSG_OP_EXECVE:
		m := api.MsgIPv4TcpConnect{}
		err := binary.Read(r, binary.LittleEndian, &m)
		if err != nil {
			break
		}
		msgUnix := msgToUnix(&m)
		msgUnix.Pid.Parent, empty, err = execParse(r)
		if err != nil && empty {
			msgUnix.Pid.Parent = nopMsgExecUnix()
		}

		msgUnix.Pid.Curr, empty, err = execParse(r)
		if err != nil && empty {
			msgUnix.Pid.Curr = nopMsgExecUnix()
		}

		if k.prettyPrinter {
			reader.ObserverIPV4TCPConnectPrinter(msgUnix, zlog)
		}

		k.observerListeners(msgUnix)
	}
}

func getCWD(pid uint32) (string, uint32, error) {
	flags := uint32(0)
	pidstr := fmt.Sprint(pid)
	cwd, err := filepath.EvalSymlinks(ProcFS + pidstr + "/cwd")
	if err != nil {
		return "", flags, err
	}

	if cwd == "/" {
		cwd = " "
		flags |= api.EventRootCWD
	}
	return cwd, flags, nil
}

func procsFilename(args []byte) (string, string) {
	cmdArgs := bytes.Split(args, []byte{0x00})
	filename := string(cmdArgs[0])
	cmds := string(bytes.Join(cmdArgs[1:], []byte{0x00}))
	return cmds, filename
}

func procsDockerID(pid uint32) string {
	pidstr := fmt.Sprint(pid)
	cgroups, err := ioutil.ReadFile(ProcFS + pidstr + "/cgroup")
	if err != nil {
		return ""
	}
	docker := strings.SplitAfter(string(cgroups), "docker/")
	if len(docker) == 1 { // no docker cgroups
		return ""
	}
	return strings.SplitAfter(docker[1], "\n")[0][0:12]
}

func (k *ObserverKprobe) pushExecveEvents(procs []ObserverProcs) {
	for _, p := range procs {
		pargs, pfilename := procsFilename(p.pargs)
		pcwd, pflags, err := getCWD(p.ppid)
		if err == nil {
			pargs = pargs + " " + pcwd
		}

		args, filename := procsFilename(p.args)
		cwd, flags, err := getCWD(p.pid)
		if err == nil {
			args = args + " " + cwd
		}

		m := api.MsgIPv4TcpConnectUnix{}
		m.Common.Op = api.MSG_OP_EXECVE
		m.Common.Ktime = 0
		m.Common.Size = api.MsgUnixSize + p.psize + p.size

		m.Kube.NetNS = 0
		m.Kube.Cid = 0
		m.Kube.Cgrpid = 0
		m.Kube.Docker = procsDockerID(p.pid)

		m.Pid.Parent.Size = p.psize
		m.Pid.Parent.PID = p.ppid
		m.Pid.Parent.UID = p.puid
		m.Pid.Parent.AUID = p.pauid
		m.Pid.Parent.Flags = p.pflags | pflags
		m.Pid.Parent.Ktime = p.pktime
		m.Pid.Parent.Filename = pfilename
		m.Pid.Parent.Args = pargs

		m.Pid.Curr.Size = p.size
		m.Pid.Curr.PID = p.pid
		m.Pid.Curr.UID = p.uid
		m.Pid.Curr.AUID = p.auid
		m.Pid.Curr.Flags = p.flags | flags
		m.Pid.Curr.Ktime = p.ktime
		m.Pid.Curr.Filename = filename
		m.Pid.Curr.Args = args

		if k.prettyPrinter {
			reader.ObserverIPV4TCPConnectPrinter(&m, zlog)
		}
		k.observerListeners(&m)
	}
}

func observerLost(msg *bpf.PerfEventLost, cpu int) {
	LostCntr = LostCntr + 1
}

func observerError(msg *bpf.PerfEvent) {
	ErrorCntr++
}

func isCtxDone(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return true
	default:
		return false
	}
}

func (k *ObserverKprobe) observerLoadMaps(btf, program string, stopCtx context.Context) error {
	var version int

	if KernelVersion != "" {
		__version, err := strconv.ParseInt(KernelVersion, 10, 32)
		if err != nil {
			return fmt.Errorf("failed kprobe %s invalid kernel version specified: %s\n", program, KernelVersion)
		}
		version = int(__version)
	} else {
		version = 0
	}

	for _, m := range BPFMaps {
		pin := k.bpfDir + m
		fd, err := bpf.LoadAndPinMaps(version, btf, program, pin, m)
		fmt.Printf("(%d, %s): LoadAndPinMaps(%s, %s, %s)\n", fd, err, program, pin, m)

		if err != nil {
			return fmt.Errorf("failed kprobe load map (%s): %s\n", fd, err)
		}
		if m == "execve_map" {
			k.execve_fd = fd
		} else if m == "tcpmon_map" {
			k.tcp_events_fd = fd
		}
	}
	return nil
}

func (k *ObserverKprobe) observerLoadInstance(load bpfLoad, stopCtx context.Context) error {
	var btf string
	var version int

	if load.Observer__btf == "" {
		btf = ObserverBTF
	} else {
		btf = load.Observer__btf
	}

	if KernelVersion != "" {
		__version, err := strconv.ParseInt(KernelVersion, 10, 32)
		if err != nil {
			return fmt.Errorf("failed kprobe %s invalid kernel version specified: %s\n", load.Observer__program, KernelVersion)
		}
		version = int(__version)
	} else {
		version = 0
	}

	fmt.Printf("prog %s execve_fd %d tcp events fd %d kern_version %d\n", load.Observer__program, k.execve_fd, k.tcp_events_fd, version)
	err, _ := bpf.LoadKprobeProgram(
		version,
		btf,
		load.Observer__program,
		load.observer__x64_attach,
		load.observer__label,
		k.bpfDir+load.observer__prog,
		load.retProbe, k.execve_fd, k.tcp_events_fd)
	if err != nil {
		/* If we fail attach with __x64_sys_execve variant try again with
		 * sys_execve variant.
		 */
		err, _ = bpf.LoadKprobeProgram(
			version,
			btf,
			load.Observer__program,
			load.observer__attach,
			load.observer__label,
			k.bpfDir+load.observer__prog,
			load.retProbe, k.execve_fd, k.tcp_events_fd)
		if err != nil && load.errorFatal {
			return fmt.Errorf("failed kprobe %s LoadKprobeProgram: %s\n", load.Observer__program, err)
		}
	}
	return nil
}

func (k *ObserverKprobe) observerLoadExecve(stopCtx context.Context) error {
	var btf string

	if ObserverExecve.Observer__btf == "" {
		btf = ObserverBTF
	} else {
		btf = ObserverExecve.Observer__btf
	}

	/* Assumption observer__program execve contains all maps */
	if err := k.observerLoadMaps(
		btf,
		ObserverExecve.Observer__program,
		stopCtx); err != nil {
		return err
	}

	if err := k.observerLoadInstance(ObserverExecve, stopCtx); err != nil {
		return err
	}
	if err := k.observerLoadInstance(ObserverExecveat, stopCtx); err != nil {
		return err
	}

	if err := k.observerLoadInstance(ObserverFork, stopCtx); err != nil {
		return err
	}

	return nil
}

func (k *ObserverKprobe) observerLoadEvents(stopCtx context.Context) error {
	if err := k.observerLoadInstance(ObserverTCPConnect, stopCtx); err != nil {
		return err
	}
	if err := k.observerLoadInstance(ObserverTCPConnectRet, stopCtx); err != nil {
		return err
	}
	if err := k.observerLoadInstance(ObserverBind, stopCtx); err != nil {
		return err
	}

	if err := k.observerLoadInstance(ObserverGetPort, stopCtx); err != nil {
		return err
	}

	if err := k.observerLoadInstance(ObserverListen, stopCtx); err != nil {
		return err
	}

	return nil
}

func (k *ObserverKprobe) runEvents(stopCtx context.Context) error {
	if err := k.observerLoadEvents(stopCtx); err != nil {
		return err
	}

	c := bpf.DefaultPerfEventConfig()
	e, err := bpf.NewPerCpuEvents(c)
	if err != nil {
		return fmt.Errorf("failed kprobe events NewPerCpuEvents: %s\n", err)
	}
	defer e.CloseAll()

	receiveEvent := k.receiveEvent

	for !isCtxDone(stopCtx) {
		todo, err := e.Poll(pollTimeout)
		switch {
		case isCtxDone(stopCtx):
			zlog.Debug("isCtxDone completed\n")
			return nil

		case err == syscall.EBADF:
			return fmt.Errorf("kprobe events syscall.EBADF: %s", err)

		case err != nil:
			zlog.Warn("kprobe events poll: ", zap.Error(err))
			continue
		}
		if todo > 0 {
			if err := e.ReadAll(receiveEvent, observerLost, observerError); err != nil {
				zlog.Warn("kprobe events read: ", zap.Error(err))
			}
		}
	}
	return nil
}

func (k *ObserverKprobe) createDir() {
	os.Mkdir(k.bpfDir, os.ModeDir)
}

type ObserverProcs struct {
	psize  uint32
	puid   uint32
	ppid   uint32
	pauid  uint32
	ppad   uint32
	pflags uint32
	pktime uint64
	pargs  []byte
	size   uint32
	uid    uint32
	pid    uint32
	auid   uint32
	pad    uint32
	flags  uint32
	ktime  uint64
	args   []byte
}

type ExecveKey struct {
	Pid uint32
}

type ExecveValueL struct {
	Common api.MsgCommon
	Tuple  api.MsgIPv4Tuple
	Kube   api.MsgK8s
	Return uint64
}

type ExecveValue struct {
	Common api.MsgCommon
	Tuple  api.MsgIPv4Tuple
	Kube   api.MsgK8s
	Return uint64
	Args   [api.ARGSBUFFER]byte
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
} // TBD

func stringToUTF8(s []byte) []byte {
	var utf8Cursor int = 0
	var i int = 0

	for i < len(s) {
		r, size := utf8.DecodeRune(s[i:])
		utf8Cursor += utf8.EncodeRune(s[utf8Cursor:], r)
		i += size
	}
	return s
}

func prependPath(s string, b []byte) []byte {
	split := strings.Split(string(b), "\u0000")
	split[0] = s
	fullCmd := strings.Join(split[0:], "\u0000")
	return []byte(fullCmd)
}

func getClkTck() (uint64, error) {
	cmd := exec.Command("getconf", "CLK_TCK")
	out := new(bytes.Buffer)
	cmd.Stdout = out
	if err := cmd.Run(); err != nil {
		return 0, fmt.Errorf("command getconf failed: %s\n", err)
	}
	clktck, err := strconv.ParseUint(strings.TrimSpace(out.String()), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("command getconf parse failed: %s\n", err)
	}
	return clktck, nil
}

func writeExecveMap(procs []ObserverProcs) {
	m, err := bpf.OpenMap("/sys/fs/bpf/tcpmon/execve_map")
	if err != nil {
		panic(err)
	}
	for _, p := range procs {
		off := 0

		k := &ExecveKey{Pid: p.pid}
		v := &ExecveValue{}
		cwd := make([]byte, api.MAX_SIZEOF_CWD)

		/* In theory we trim'd this above to fit but lets be paranoid
		 * because I already screwed this up once and crashing fgs is
		 * not so friendly.
		 */
		putU32 := func(val uint32) error {
			if off+4 > api.ARGSBUFFER {
				return fmt.Errorf("out of range")
			}

			binary.LittleEndian.PutUint32(v.Args[off:], val)
			off += 4
			return nil
		}

		putU64 := func(val uint64) error {
			if off+8 > api.ARGSBUFFER {
				return fmt.Errorf("out of range")
			}
			binary.LittleEndian.PutUint64(v.Args[off:], val)
			off += 8
			return nil
		}

		if err := putU32(p.psize); err != nil {
			continue
		}
		if err := putU32(p.ppid); err != nil {
			continue
		}
		if err := putU32(p.puid); err != nil {
			continue
		}
		if err := putU32(p.pauid); err != nil {
			continue
		}
		if err := putU32(p.ppad); err != nil {
			continue
		}
		if err := putU32(p.pflags); err != nil {
			continue
		}
		if err := putU64(p.pktime); err != nil {
			continue
		}
		off += copy(v.Args[off:], p.pargs)
		if (p.pflags & api.EventNeedsCWD) != 0 {
			off += copy(v.Args[off:], cwd)
		}
		if err := putU32(p.size); err != nil {
			continue
		}
		if err := putU32(p.pid); err != nil {
			continue
		}
		if err := putU32(p.uid); err != nil {
			continue
		}
		if err := putU32(p.auid); err != nil {
			continue
		}
		if err := putU32(p.pad); err != nil {
			continue
		}
		if err := putU32(p.flags); err != nil {
			continue
		}
		if err := putU64(p.ktime); err != nil {
			continue
		}
		off += copy(v.Args[off:], p.args)
		if (p.flags & api.EventNeedsCWD) != 0 {
			off += copy(v.Args[off:], cwd)
		}
		v.Common.Size = 1
		m.Update(k, v)
	}
}

func (k *ObserverKprobe) getRunningProcs(write, push bool) []ObserverProcs {
	var procs []ObserverProcs
	procFS, _ := ioutil.ReadDir(ProcFS)

	for _, d := range procFS {
		clktck, err := getClkTck()
		if err != nil {
			fmt.Printf("Warning: procFS wallclock time may be inaccurate. %s\n", err)
			clktck = 1
		}

		if d.IsDir() == false {
			continue
		}
		cmdline, err := ioutil.ReadFile(ProcFS + d.Name() + "/cmdline")
		if err != nil {
			continue
		}
		if string(cmdline) == "" {
			continue
		}
		statline, err := ioutil.ReadFile(ProcFS + d.Name() + "/stat")
		if err != nil {
			continue
		}
		pid, err := strconv.ParseUint(d.Name(), 10, 32)
		if err != nil {
			continue
		}

		stats := strings.Split(string(statline), " ")
		ppid := stats[3]
		_ppid, err := strconv.ParseUint(ppid, 10, 32)
		if err != nil {
			continue
		}
		_ktime := stats[21]
		ktime, err := strconv.ParseUint(_ktime, 10, 64)
		if err != nil {
			ktime = 0
		}
		ktime = (ktime / clktck) * nanoPerSeconds

		pcmdline, err := ioutil.ReadFile(ProcFS + ppid + "/cmdline")
		if err != nil {
			continue
		}
		pstatline, err := ioutil.ReadFile(ProcFS + ppid + "/stat")
		if err != nil {
			continue
		}
		pstats := strings.Split(string(pstatline), " ")
		_pktime := pstats[21]
		pktime, err := strconv.ParseUint(_pktime, 10, 64)
		if err != nil {
			pktime = 0
		}
		pktime = (pktime / clktck) * nanoPerSeconds
		execPath, err := filepath.EvalSymlinks(ProcFS + d.Name() + "/exe")
		if execPath != "" {
			cmdline = prependPath(execPath, cmdline)
		}
		pexecPath, err := filepath.EvalSymlinks(ProcFS + ppid + "/exe")
		if pexecPath != "" {
			pcmdline = prependPath(pexecPath, pcmdline)
		}

		pcmdsUTF := stringToUTF8(pcmdline)
		cmdsUTF := stringToUTF8(cmdline)

		p := ObserverProcs{
			ppid: uint32(_ppid), pargs: pcmdsUTF,
			pflags: api.EventProcFS | api.EventNeedsCWD | api.EventNeedsAUID,
			pktime: pktime,
			pid:    uint32(pid), args: cmdsUTF,
			flags: api.EventProcFS | api.EventNeedsCWD | api.EventNeedsAUID,
			ktime: ktime}
		p.size = uint32(api.SIZEOF_EXECVE + len(p.args) + api.MAX_SIZEOF_CWD)
		p.psize = uint32(api.SIZEOF_EXECVE + len(p.pargs) + api.MAX_SIZEOF_CWD)
		/* If we can't fit this in the buffer lets trim some parts and
		 * make it fit.
		 */
		if p.size+p.psize > api.ARGSBUFFER {
			var deduct uint32
			var need int32

			need = int32((p.size + p.psize) - api.ARGSBUFFER)
			// First consume CWD space from parent because this speculative extra space
			// next try to consume CWD space from child and finally start truncating args
			// if necessary.
			deduct = api.MAX_SIZEOF_CWD
			p.pflags = p.pflags & ^uint32(api.EventNeedsCWD)
			p.pflags = p.pflags | api.EventNoCWDSupport
			p.psize -= deduct
			need -= int32(deduct)
			if need > 0 {
				deduct = api.MAX_SIZEOF_CWD
				p.size -= deduct
				p.flags = p.flags & ^uint32(api.EventNeedsCWD)
				p.flags = p.flags | api.EventNoCWDSupport
				need -= int32(deduct)
			}

			for i := int32(0); i < need; i++ {
				if len(p.pargs) > len(p.args) {
					p.pflags |= api.EventTruncArgs
					p.pargs = p.pargs[:len(p.pargs)-1]
					p.psize--
				} else {
					p.flags |= api.EventTruncArgs
					p.args = p.args[:len(p.args)-1]
					p.size--
				}
			}
		}

		procs = append(procs, p)
	}

	if write {
		writeExecveMap(procs)
	}
	if push {
		k.pushExecveEvents(procs)
	}
	return procs
}

func (k *ObserverKprobe) populateExecve(ctx context.Context) {
	k.getRunningProcs(true, false)
}

type ObserverChannel struct {
	conn    net.Conn
	encoder *gob.Encoder
}

type ObserverKprobe struct {
	bpfDir        string
	execve_fd     int
	tcp_events_fd int
	prettyPrinter bool
	listeners     []ObserverChannel
}

func (k *ObserverKprobe) observerFindBTF(ctx context.Context) error {
	if ObserverBTF == "" {
		return fmt.Errorf("No BTF target found\n")
	}
	return nil
}

func (k *ObserverKprobe) Start() error {
	k.createDir()
	if err := k.observerFindBTF(context.TODO()); err != nil {
		return fmt.Errorf("observerFindBTF error: %s\n", err)
	}
	if err := k.observerLoadExecve(context.TODO()); err != nil {
		return fmt.Errorf("observerLoadExecve error: %s\n", err)
	}
	k.populateExecve(context.TODO())
	if err := k.runEvents(context.TODO()); err != nil {
		return fmt.Errorf("observerLoadEvents failed: %s", err)
	}
	return nil
}

func (k *ObserverKprobe) deleteProgs() {
	os.Remove(k.bpfDir + ObserverExecve.observer__prog)
	os.Remove(k.bpfDir + ObserverExecveat.observer__prog)
	os.Remove(k.bpfDir + ObserverTCPConnect.observer__prog)
	os.Remove(k.bpfDir + ObserverBind.observer__prog)
	os.Remove(k.bpfDir + ObserverGetPort.observer__prog)
	os.Remove(k.bpfDir + ObserverTCPConnectRet.observer__prog)
	for _, m := range BPFMaps {
		os.Remove(k.bpfDir + m)
	}
	os.Remove(k.bpfDir)
}

func NewObserverKprobe(bpfDir string, pretty bool) *ObserverKprobe {
	zlog = logger.GetLogger()
	return &ObserverKprobe{
		bpfDir:        bpfDir,
		prettyPrinter: pretty,
	}
}

func PrintStats() {
	fmt.Printf("Observer Stats: errors %d lost %d recvd %d\n", ErrorCntr, LostCntr, RecvCntr)
}

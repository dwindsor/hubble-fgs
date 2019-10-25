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
)

var (
	LostCntr  = 0
	ErrorCntr = 0
	RecvCntr  = 0

	ProcFS = "/proc/"

	ObserverExecve__program    string
	observerExecve__x64_attach = "__x64_sys_execve"
	observerExecve__attach     = "sys_execve"
	observerExecve__label      = "kprobe/sys_execve"
	observerExecve__prog       = "kprobe_execve"
	observerExecve__map        = "kprobe_execve_map"
	observerExecve__map_label  = "execve_map"

	ObserverExecveat__program    string
	observerExecveat__x64_attach = "__x64_sys_execveat"
	observerExecveat__attach     = "sys_execveat"
	observerExecveat__label      = "kprobe/sys_execveat"
	observerExecveat__prog       = "kprobe_execveat"
	observerExecveat__map        = "kprobe_execve_map"
	observerExecveat__map_label  = "execve_map"

	ObserverTCPConnect__program   string
	observerTCPConnect__attach    = "tcp_connect"
	observerTCPConnect__label     = "kprobe/tcp_connect"
	observerTCPConnect__prog      = "kprobe_tcp_connect"
	observerTCPConnect__map       = "kprobe_tcp_events"
	observerTCPConnect__map_label = "tcpmon_map"

	ObserverTCPConnectRet__program    string
	observerTCPConnectRet__x64_attach = "__x64_sys_connect"
	observerTCPConnectRet__attach     = "sys_connect"
	observerTCPConnectRet__label      = "kretprobe/sys_connect"
	observerTCPConnectRet__prog       = "kretprobe_sys_connect"
	observerTCPConnectRet__map        = observerTCPConnect__map
	observerTCPConnectRet__map_label  = observerTCPConnect__map_label

	observerTimeout = 5 * time.Minute
	execTimeout     = 5 * time.Minute
	pollTimeout     = 5000

	log *zap.Logger
)

func (k *ObserverKprobe) observerListeners(msg *api.MsgIPv4TcpConnectUnix) {
	for _, c := range k.listeners {
		enc := gob.NewEncoder(c)
		if err := enc.Encode(msg); err != nil {
			log.Debug("Write failure removing Listener", zap.Error(err))
			k.RemoveListener(c)
		}
	}
}

func (k *ObserverKprobe) AddListener(conn net.Conn) {
	k.listeners = append(k.listeners, conn)
}

func (k *ObserverKprobe) RemoveListener(conn net.Conn) {
	for i, c := range k.listeners {
		if c == conn {
			fmt.Printf("delete listener %v\n", conn)
			k.listeners = append(k.listeners[:i], k.listeners[i+1:]...)
		}
		fmt.Printf("walking listener %v\n", c)
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

	execUnix.PID = 0
	execUnix.UID = 0
	execUnix.Filename = "<enomem>"
	execUnix.Args = "<enomem>"
	return execUnix
}

func execParse(reader *bytes.Reader) (api.MsgExecUnix, error) {
	execUnix := api.MsgExecUnix{}
	exec := api.MsgExec{}

	if err := binary.Read(reader, binary.LittleEndian, &exec); err != nil {
		return execUnix, err
	}

	execUnix.PID = exec.PID
	execUnix.UID = exec.UID

	size := exec.Size - 16
	args := make([]byte, size)
	if err := binary.Read(reader, binary.LittleEndian, &args); err != nil {
		return execUnix, err
	}

	cmdArgs := bytes.Split(args, []byte{0x00})
	execUnix.Filename = string(cmdArgs[0])
	execUnix.Args = string(bytes.Join(cmdArgs[1:], []byte{0x00}))

	return execUnix, nil
}

func (k *ObserverKprobe) receiveEvent(msg *bpf.PerfEventSample, cpu int) {
	data := msg.DataDirect()
	var op uint8 = data[0]

	RecvCntr++
	r := bytes.NewReader(data)

	switch op {
	case api.MSG_OP_IPV4_TCPCONNECT, api.MSG_OP_IPV4_TCPCONNECTRET:
		m := api.MsgIPv4TcpConnect{}
		err := binary.Read(r, binary.LittleEndian, &m)
		if err != nil {
			panic(err)
		}
		msgUnix := msgToUnix(&m)
		msgUnix.Pid.Parent, err = execParse(r)
		if err != nil {
			msgUnix.Pid.Parent = nopMsgExecUnix()
		}

		msgUnix.Pid.Curr, err = execParse(r)
		if err != nil {
			msgUnix.Pid.Curr = nopMsgExecUnix()
		}

		if k.prettyPrinter {
			reader.ObserverIPV4TCPConnectPrinter(msgUnix, log)
		}

		k.observerListeners(msgUnix)
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

func (k *ObserverKprobe) observerLoadExecve(stopCtx context.Context) error {
	var execve_fd int
	var err error

	err, execve_fd = bpf.LoadKprobe(
		ObserverExecve__program,
		observerExecve__x64_attach,
		observerExecve__label,
		k.bpfDir+observerExecve__prog,
		k.bpfDir+observerExecve__map,
		observerExecve__map_label, false, 0, 0)
	if err != nil {
		/* If we fail attach with __x64_sys_execve variant try again with
		 * sys_execve variant.
		 */
		err, execve_fd = bpf.LoadKprobe(
			ObserverExecve__program,
			observerExecve__attach,
			observerExecve__label,
			k.bpfDir+observerExecve__prog,
			k.bpfDir+observerExecve__map,
			observerExecve__map_label, false, 0, 0)
		if err != nil {
			return fmt.Errorf("failed kprobe execve LoadKprobe: %s\n", err)
		}
	}
	k.execve_fd = execve_fd

	err, _ = bpf.LoadKprobe(
		ObserverExecveat__program,
		observerExecveat__x64_attach,
		observerExecveat__label,
		k.bpfDir+observerExecveat__prog,
		"",
		"",
		false, k.execve_fd, 0)
	if err != nil {
		/* If we fail attach with __x64_sys_execve variant try again with
		 * sys_execve variant.
		 */
		err, _ = bpf.LoadKprobe(
			ObserverExecveat__program,
			observerExecveat__attach,
			observerExecveat__label,
			k.bpfDir+observerExecveat__prog,
			"",
			"",
			false, k.execve_fd, 0)
		if err != nil {
			return fmt.Errorf("failed kprobe execve LoadKprobe: %s\n", err)
		}
	}
	return nil
}

func (k *ObserverKprobe) observerLoadEvents(stopCtx context.Context) error {
	err, tcp_events := bpf.LoadKprobe(
		ObserverTCPConnect__program,
		observerTCPConnect__attach,
		observerTCPConnect__label,
		k.bpfDir+observerTCPConnect__prog,
		k.bpfDir+observerTCPConnect__map,
		observerTCPConnect__map_label,
		false, k.execve_fd, 0)
	if err != nil {
		return fmt.Errorf("failed kprobe TCPConnect LoadKprobe: %s\n", err)
	}
	k.tcp_events_fd = tcp_events
	err, _ = bpf.LoadKprobe(
		ObserverTCPConnectRet__program,
		observerTCPConnectRet__x64_attach,
		observerTCPConnectRet__label,
		k.bpfDir+observerTCPConnectRet__prog,
		"",
		"",
		true, k.execve_fd, tcp_events)
	if err != nil {
		err, _ = bpf.LoadKprobe(
			ObserverTCPConnectRet__program,
			observerTCPConnectRet__attach,
			observerTCPConnectRet__label,
			k.bpfDir+observerTCPConnectRet__prog,
			"",
			"",
			true, k.execve_fd, tcp_events)
		if err != nil {
			fmt.Printf("Warning kprobe TCPConnectRet LoadKprobe: %s\n", err)
		}
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
			log.Debug("isCtxDone completed\n")
			return nil

		case err == syscall.EBADF:
			return fmt.Errorf("kprobe events syscall.EBADF: %s", err)

		case err != nil:
			log.Warn("kprobe events poll: ", zap.Error(err))
			continue
		}
		if todo > 0 {
			if err := e.ReadAll(receiveEvent, observerLost, observerError); err != nil {
				log.Warn("kprobe events read: ", zap.Error(err))
			}
		}
	}
	return nil
}

func (k *ObserverKprobe) createDir() {
	os.Mkdir(k.bpfDir, os.ModeDir)
}

type ObserverProcs struct {
	psize uint32
	puid  uint32
	ppid  uint32
	ppad  uint32
	pargs []byte
	size  uint32
	uid   uint32
	pid   uint32
	pad   uint32
	args  []byte
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

func getRunningProcs() []ObserverProcs {
	var procs []ObserverProcs
	procFS, _ := ioutil.ReadDir(ProcFS)

	for _, d := range procFS {
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
		pcmdline, err := ioutil.ReadFile(ProcFS + ppid + "/cmdline")
		if err != nil {
			continue
		}

		pcmdsUTF := stringToUTF8(pcmdline)
		cmdsUTF := stringToUTF8(cmdline)

		p := ObserverProcs{ppid: uint32(_ppid), pargs: pcmdsUTF, pid: uint32(pid), args: cmdsUTF}
		p.size = uint32(4 + 4 + 4 + 4 + len(p.args))
		p.psize = uint32(4 + 4 + 4 + 4 + len(p.pargs))
		procs = append(procs, p)
	}

	m, err := bpf.OpenMap("/sys/fs/bpf/tcpmon/kprobe_execve_map")
	if err != nil {
		panic(err)
	}
	for _, p := range procs {
		off := 0

		k := &ExecveKey{Pid: p.pid}
		v := &ExecveValue{}

		binary.LittleEndian.PutUint32(v.Args[off:], p.psize)
		off += 4
		binary.LittleEndian.PutUint32(v.Args[off:], p.ppid)
		off += 4
		binary.LittleEndian.PutUint32(v.Args[off:], p.puid)
		off += 4
		binary.LittleEndian.PutUint32(v.Args[off:], p.ppad)
		off += 4
		off += copy(v.Args[off:], p.pargs)

		binary.LittleEndian.PutUint32(v.Args[off:], p.size)
		off += 4
		binary.LittleEndian.PutUint32(v.Args[off:], p.pid)
		off += 4
		binary.LittleEndian.PutUint32(v.Args[off:], p.uid)
		off += 4
		binary.LittleEndian.PutUint32(v.Args[off:], p.pad)
		off += 4
		off += copy(v.Args[off:], p.args)
		m.Update(k, v)
	}
	return procs
}

func (k *ObserverKprobe) populateExecve(ctx context.Context) {
	getRunningProcs()
}

type ObserverKprobe struct {
	bpfDir        string
	execve_fd     int
	tcp_events_fd int
	prettyPrinter bool
	listeners     []net.Conn
}

func (k *ObserverKprobe) Start() {
	k.createDir()
	k.observerLoadExecve(context.TODO())
	k.populateExecve(context.TODO())
	if err := k.observerLoadEvents(context.TODO()); err != nil {
		fmt.Printf("observerLoadEvents failed: %s", err)
	}
}

func NewObserverKprobe(bpfDir string, pretty bool) *ObserverKprobe {
	log = logger.GetLogger()
	return &ObserverKprobe{
		bpfDir:        bpfDir,
		prettyPrinter: pretty,
	}
}

func PrintStats() {
	fmt.Printf("Observer Stats: errors %d lost %d recvd %d\n", ErrorCntr, LostCntr, RecvCntr)
}

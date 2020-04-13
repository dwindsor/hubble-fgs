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

	"bufio"
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
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"
	"unsafe"

	"go.uber.org/zap"

	"golang.org/x/sys/unix"
)

const (
	Progsize = 64
	MaxArgs  = 5
	ArgSize  = 32

	MaxSupportedPids = 32768

	nanoPerSeconds = 1000000000

	varLibHubbleFGS = "/var/lib/hubble-fgs/"
	localBTFFile    = "./bpf/btf"
	defaultBPFPath  = "./bpf/"

	execveEventProg = "bpf_execve_event.o"
	execveProg      = "bpf_execve.o"

	TCP_PROC_STATE_LISTEN = 10
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
	ProcFS        = "/proc/"
	KernelVersion = ""
	SetPidMax     = false

	ObserverBTF  string
	Verbosity    int
	BPFArrayMaps = []string{"execve_map", "tcpmon_map"}
	BPFHashMaps  = []string{"execve_map", "tcpmon_map"}

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

	observerPrograms = []*bpfLoad{
		&ObserverExecve,
		&ObserverExecveat,
		&ObserverFork,
		&ObserverTCPConnect,
		&ObserverTCPConnectRet,
		&ObserverBind,
		&ObserverGetPort,
		&ObserverListen}
)

func (k *ObserverKprobe) observerListeners(msg *api.MsgIPv4TcpConnectUnix) {
	if pass := k.runFilters(msg); pass {
		for _, c := range k.listeners {
			if err := c.encoder.Encode(msg); err != nil {
				zlog.Debug("Write failure removing Listener", zap.Error(err))
				k.RemoveListener(c.conn)
			}
		}
	}
}

func (k *ObserverKprobe) AddListener(conn net.Conn) {
	channel := ObserverChannel{}
	channel.encoder = gob.NewEncoder(conn)
	channel.conn = conn
	k.listeners = append(k.listeners, channel)
	if Verbosity > 0 {
		fmt.Printf("add listener %v\n", conn)
	}
	k.getRunningProcs(false, k.enableExecve)
}

func (k *ObserverKprobe) RemoveListener(conn net.Conn) {
	for i, c := range k.listeners {
		if c.conn == conn {
			if Verbosity > 0 {
				fmt.Printf("delete listener %v\n", conn)
			}
			k.listeners = append(k.listeners[:i], k.listeners[i+1:]...)
		}
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
	execUnix.NSPID = 0
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
	execUnix.NSPID = exec.NSPID
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

func (k *ObserverKprobe) runFilters(msgUnix *api.MsgIPv4TcpConnectUnix) bool {
	pass := true
	for _, f := range k.msgFilter {
		res := f.run(msgUnix, k)

		if res {
			f.filterPass++
			pass = true
			break
		} else {
			f.filterDrop++
			pass = false
		}
	}

	if pass {
		k.filterPass++
	} else {
		k.filterDrop++
	}

	return pass
}

func (k *ObserverKprobe) receiveEvent(msg *bpf.PerfEventSample, cpu int) {
	data := msg.DataDirect()
	var op uint8 = data[0]
	var empty bool

	k.recvCntr++
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

		/* OR filter together */
		k.observerListeners(msgUnix)
		/* Keeping pretty printer because it helps debugging filters */
		if k.prettyPrinter {
			reader.ObserverIPV4TCPConnectPrinter(msgUnix, zlog)
		}
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

func (k *ObserverKprobe) pushTCPEvents(msg *api.MsgIPv4TcpConnectUnix, tcpEntries map[uint32]procTCPEntry) {
	pid := msg.Pid.Curr.PID

	fdDir := fmt.Sprintf("%s/%d/fd", ProcFS, pid)
	procFD, err := ioutil.ReadDir(fdDir)
	if err != nil {
		fmt.Printf("Warning: ReadDir %d/fd/ failed: %s\n", pid, err)
	}
	for _, d := range procFD {
		socket, err := os.Readlink(fdDir + "/" + d.Name())
		if err != nil {
			fmt.Printf("Warning: readlink error %s: %s\n", d.Name(), err)
		}
		if strings.Contains(socket, "socket") == true {
			fields := strings.Split(socket, ":")
			inode := fields[1]
			inode = strings.TrimRight(inode, "]")
			inode = strings.TrimLeft(inode, "[")
			inodeEntry, err := strconv.ParseUint(inode, 10, 32)
			if err != nil {
				fmt.Printf("Warning: tcpEntry inode not parsable: %s\n", inode)
			} else {
				entry := tcpEntries[uint32(inodeEntry)]
				msg.Tuple.SAddr = entry.localIP
				msg.Tuple.DAddr = entry.remoteIP
				msg.Tuple.DPort = entry.remotePort
				msg.Tuple.SPort = entry.localPort
				msg.Tuple.Proto = 2

				if entry.state == 0 {
					continue
				}

				if entry.state == TCP_PROC_STATE_LISTEN {
					msg.Common.Op = api.MsgOpIPv4Listen
				} else {
					msg.Common.Op = api.MsgOpIPv4TCPConnect
				}

				if k.prettyPrinter {
					reader.ObserverIPV4TCPConnectPrinter(msg, zlog)
				}

				k.observerListeners(msg)
			}
		}
	}
}

func (k *ObserverKprobe) pushExecveEvents(p ObserverProcs, tcpEntries map[uint32]procTCPEntry, pushExecve bool) {
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
	m.Pid.Parent.NSPID = p.pnspid
	m.Pid.Parent.UID = p.puid
	m.Pid.Parent.AUID = p.pauid
	m.Pid.Parent.Flags = p.pflags | pflags
	m.Pid.Parent.Ktime = p.pktime
	m.Pid.Parent.Filename = pfilename
	m.Pid.Parent.Args = pargs

	m.Pid.Curr.Size = p.size
	m.Pid.Curr.PID = p.pid
	m.Pid.Curr.NSPID = p.nspid
	m.Pid.Curr.UID = p.uid
	m.Pid.Curr.AUID = p.auid
	m.Pid.Curr.Flags = p.flags | flags
	m.Pid.Curr.Ktime = p.ktime
	m.Pid.Curr.Filename = filename
	m.Pid.Curr.Args = args

	if k.prettyPrinter {
		reader.ObserverIPV4TCPConnectPrinter(&m, zlog)
	}
	if pushExecve {
		k.observerListeners(&m)
	}
	/* Collect any existing TCP sockets on PID and generate events. */
	k.pushTCPEvents(&m, tcpEntries)
}

func (k *ObserverKprobe) pushEvents(procs []ObserverProcs, tcpEntries map[uint32]procTCPEntry, pushExecve bool) {
	for _, p := range procs {
		k.pushExecveEvents(p, tcpEntries, pushExecve)
	}
}

type procTCPEntry struct {
	id                   int
	localIP              uint32
	localPort            uint16
	remoteIP             uint32
	remotePort           uint16
	state                uint32
	txq                  int
	rxq                  int
	timerActive          int
	jiffiesExpire        uint64
	jiffiesRTO           uint64
	uid                  uint32
	unansweredProbes     uint32
	inode                uint32
	socketRefCount       uint32
	locationSocketMemory uint64
	retransTimeout       uint64
	predictedTick        uint64
	congestionWindow     uint64
	slowstartThresh      uint64
}

func (k *ObserverKprobe) observerLost(msg *bpf.PerfEventLost, cpu int) {
	k.lostCntr++
}

func (k *ObserverKprobe) observerError(msg *bpf.PerfEvent) {
	k.errorCntr++
}

func isCtxDone(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return true
	default:
		return false
	}
}

func kernelStringToNumeric(ver string) int64 {
	vers := strings.Split(ver, ".")
	a, erra := strconv.ParseInt(vers[0], 10, 32)
	b, errb := strconv.ParseInt(vers[1], 10, 32)
	c, errc := strconv.ParseInt(vers[2], 10, 32)
	if erra != nil || errb != nil || errc != nil {
		return 0
	}
	return ((a << 16) + (b << 8) + c)
}

func getKernelVersion() (int, string, error) {
	var version int = 0
	var verStr string = ""

	if KernelVersion != "" {
		version = int(kernelStringToNumeric(KernelVersion))
		verStr = KernelVersion
	} else {
		if versionSig, err := ioutil.ReadFile(ProcFS + "/version_signature"); err == nil {
			versionStrings := strings.Fields(string(versionSig))
			version = int(kernelStringToNumeric(versionStrings[len(versionStrings)-1]))
			verStr = versionStrings[len(versionStrings)-1]
		} else {
			var uname unix.Utsname

			err := unix.Uname(&uname)
			if err != nil {
				verStr = "unknown"
				// On error default to bpf discovery which
				// will work in many cases, notable exception
				// is the cloud vendors and others that mangle
				// the kernel version string.
				return 0, verStr, nil
			}
			n := bytes.IndexByte(uname.Release[:], 0)
			// vendors like to define kernel 4.14.128-foo but
			// everything after '-' is meaningless from BPF
			// side so toss it out.
			release := strings.Split(string(uname.Release[:n]), "-")
			verStr = release[0]
			numeric := strings.TrimRight(verStr, "+")
			version = int(kernelStringToNumeric(numeric))
		}
	}
	return version, verStr, nil
}

func getKernelMaps() ([]string, error) {
	version, _, err := getKernelVersion()
	if err != nil {
		return nil, fmt.Errorf("Get supported maps failed: %s\n", err)
	}
	minHashMapVersion := int(kernelStringToNumeric("4.18.0"))
	if version >= minHashMapVersion {
		return BPFHashMaps, nil
	}
	return BPFArrayMaps, nil
}

func (k *ObserverKprobe) observerLoadMaps(btf, program string, stopCtx context.Context) error {
	BPFMaps, err := getKernelMaps()
	if err != nil {
		return err
	}

	version, _, err := getKernelVersion()
	if err != nil {
		return err
	}

	for _, m := range BPFMaps {
		pin := k.bpfDir + m
		fd, err := bpf.LoadAndPinMaps(version, Verbosity, btf, program, pin, m)
		if Verbosity > 0 {
			fmt.Printf("LoadAndPinMaps(%s, %s, %s)\n", program, pin, m)
		}

		if err != nil {
			return fmt.Errorf("failed kprobe load map (%d): %s\n", fd, err)
		}
		if strings.Contains(m, "execve_") == true {
			k.execve_fd = fd
		} else if m == "tcpmon_map" {
			k.tcp_events_fd = fd
		}
	}
	return nil
}

func (k *ObserverKprobe) observerLoadInstance(load bpfLoad, stopCtx context.Context) error {
	var btf string

	if load.Observer__btf == "" {
		btf = ObserverBTF
	} else {
		btf = load.Observer__btf
	}

	version, _, err := getKernelVersion()
	if err != nil {
		return err
	}

	if Verbosity > 0 {
		fmt.Printf("prog %s execve_fd %d tcp events fd %d kern_version %d\n", load.Observer__program, k.execve_fd, k.tcp_events_fd, version)
	}
	err, _ = bpf.LoadKprobeProgram(
		version, Verbosity,
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
			version, Verbosity,
			btf,
			load.Observer__program,
			load.observer__attach,
			load.observer__label,
			k.bpfDir+load.observer__prog,
			load.retProbe, k.execve_fd, k.tcp_events_fd)
		if err != nil && load.errorFatal {
			return fmt.Errorf("Failed prog %s execve_fd %d tcp events fd %d kern_version %d LoadKprobeProgram: %s\n",
				load.Observer__program, k.execve_fd, k.tcp_events_fd, version, err)
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

	_, verStr, _ := getKernelVersion()
	fmt.Printf("Loading kernel version %s\n", verStr)

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

func (k *ObserverKprobe) __runEvents(stopCtx context.Context) (*bpf.PerCpuEvents, error) {
	if err := k.observerLoadEvents(stopCtx); err != nil {
		return nil, err
	}
	fmt.Printf("hubble-fgs, loaded BPF maps and events successfully.\n")

	e, err := bpf.NewPerCpuEvents(k.perfConfig)
	if err != nil {
		return nil, fmt.Errorf("failed kprobe events NewPerCpuEvents: %s\n", err)
	}
	return e, nil
}

func (k *ObserverKprobe) __loopEvents(stopCtx context.Context, e *bpf.PerCpuEvents) error {
	receiveEvent := k.receiveEvent
	observerLost := k.observerLost
	observerError := k.observerError

	fmt.Printf("hubble-fgs, listening for events...\n")
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

func (k *ObserverKprobe) runEvents(stopCtx context.Context) error {
	e, err := k.__runEvents(stopCtx)
	if err != nil {
		return err
	}
	defer e.CloseAll()
	k.__loopEvents(stopCtx, e)
	return nil
}

func (k *ObserverKprobe) createDir() {
	os.Mkdir(k.bpfDir, os.ModeDir)
}

type ObserverProcs struct {
	psize  uint32
	puid   uint32
	ppid   uint32
	pnspid uint32
	pauid  uint32
	pflags uint32
	pktime uint64
	pargs  []byte
	size   uint32
	uid    uint32
	pid    uint32
	nspid  uint32
	auid   uint32
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
		if err := putU32(p.pnspid); err != nil {
			continue
		}
		if err := putU32(p.puid); err != nil {
			continue
		}
		if err := putU32(p.pauid); err != nil {
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
		if err := putU32(p.nspid); err != nil {
			continue
		}
		if err := putU32(p.uid); err != nil {
			continue
		}
		if err := putU32(p.auid); err != nil {
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

func getPIDNS(filename string) uint32 {
	file, err := ioutil.ReadFile(filename)
	if err != nil {
		fmt.Printf("ReadFile: %s error: %s\n", filename, err)
		return 0
	}
	statuslines := strings.Split(string(file), "\n")
	for _, line := range statuslines {
		if strings.Contains(line, "NStgid:") {
			fields := strings.Fields(line)
			if len(fields) < 3 {
				return 0
			}
			pidField := fields[len(fields)-1]
			pid, err := strconv.ParseUint(pidField, 10, 32)
			if err != nil {
				fmt.Printf("Warning: NStgid parser failed %s: %s\n", filename, err)
				return 0
			}
			return uint32(pid)
		}
	}
	return 0
}

func stringToTCPEntry(s string) *procTCPEntry {
	var entry procTCPEntry

	fields := strings.Fields(s)

	id, _ := strconv.ParseUint(strings.TrimRight(fields[0], ":"), 10, 32)
	local := strings.Split(fields[1], ":")
	remote := strings.Split(fields[2], ":")
	localIP, err := strconv.ParseUint(local[0], 16, 32)
	if err != nil {
		fmt.Printf("Warning: localIP parse error: %s\n", err)
	}
	localPort, err := strconv.ParseUint(local[1], 16, 16)
	if err != nil {
		fmt.Printf("Warning: localPort parse error: %s\n", err)
	}
	remoteIP, err := strconv.ParseUint(remote[0], 16, 32)
	if err != nil {
		fmt.Printf("Warning: remoteIP parse error: %s\n", err)
	}
	remotePort, err := strconv.ParseUint(remote[1], 16, 16)
	if err != nil {
		fmt.Printf("Warning: remotePort parse error: %s\n", err)
	}
	state, err := strconv.ParseUint(fields[3], 16, 32)
	if err != nil {
		fmt.Printf("Warning: TCP state parse error: %s\n", err)
	}
	inode, err := strconv.ParseUint(fields[9], 10, 32)
	if err != nil {
		fmt.Printf("Warning: inode parse error: %s\n", err)
	}

	entry.id = int(id)
	entry.inode = uint32(inode)
	entry.localIP = uint32(localIP)
	entry.localPort = uint16(localPort)
	entry.remoteIP = uint32(remoteIP)
	entry.remotePort = uint16(remotePort)
	entry.state = uint32(state)

	return &entry
}

func (k *ObserverKprobe) getTCPConnections() (map[uint32]procTCPEntry, error) {
	entryMap := make(map[uint32]procTCPEntry)

	tcp, err := os.Open(ProcFS + "/net/tcp")
	if err != nil {
		return nil, err
	}
	scanner := bufio.NewScanner(tcp)
	scanner.Scan()
	for scanner.Scan() {
		entry := stringToTCPEntry(scanner.Text())
		entryMap[entry.inode] = *entry
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return entryMap, nil
}

func (k *ObserverKprobe) getRunningProcs(write, push bool) []ObserverProcs {
	var procs []ObserverProcs
	procFS, _ := ioutil.ReadDir(ProcFS)
	r := regexp.MustCompile(`[^\s\(]+|(\({1,2}[^\)]*\){1,2})`)

	entryMap, err := k.getTCPConnections()
	if err != nil {
		fmt.Printf("Warning: failed to parse and build proc net map. Will not post connections started before hubble-fgs.\n")
	}

	for _, d := range procFS {
		var pcmdline, pstatline []byte
		var pstats []string
		var pktime uint64
		var pexecPath string
		var pnspid uint32

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
			fmt.Printf("ReadFile: %s /stat error\n", ProcFS+d.Name()+"/cmdline")
			continue
		}
		pid, err := strconv.ParseUint(d.Name(), 10, 32)
		if err != nil {
			fmt.Printf("ReadFile: %s /parseuint error\n", ProcFS+d.Name()+"/cmdline")
			continue
		}

		stats := r.FindAllString(string(statline), -1)
		ppid := stats[3]
		_ppid, err := strconv.ParseUint(ppid, 10, 32)
		if err != nil {
			_ppid = 0 // 0 pid indicates no known parent
		}

		_ktime := stats[21]
		ktime, err := strconv.ParseUint(_ktime, 10, 64)
		if err != nil {
			fmt.Printf("Warning: Ktime parsing error: %s: %s : %s\n", _ktime, ProcFS+ppid+"/stat", err)
			ktime = 0
		}
		ktime = (ktime / clktck) * nanoPerSeconds
		nspid := getPIDNS(ProcFS + d.Name() + "/status")

		if _ppid != 0 {
			var err error

			pcmdline, err = ioutil.ReadFile(ProcFS + ppid + "/cmdline")
			if err != nil {
				fmt.Printf("ReadFile: %s /cmdline error\n", ProcFS+d.Name()+"/cmdline")
				continue
			}

			pstatline, err = ioutil.ReadFile(ProcFS + ppid + "/stat")
			if err != nil {
				fmt.Printf("ReadFile: %s /stat error\n", ProcFS+d.Name()+"/cmdline")
				continue
			}
			pstats = r.FindAllString(string(pstatline), -1)
			_pktime := pstats[21]
			pktime, err = strconv.ParseUint(_pktime, 10, 64)
			if err != nil {
				fmt.Printf("Warning: Parent ktime parsing error: %s: %s : %s\n", _pktime, ProcFS+ppid+"/stat", err)
				pktime = 0
			}
			pktime = (pktime / clktck) * nanoPerSeconds
			pnspid = getPIDNS(ProcFS + ppid + "/status")
		} else {
			pcmdline = nil
			pstatline = nil
			pstats = nil
			pktime = 0
			pnspid = 0
		}

		execPath, err := filepath.EvalSymlinks(ProcFS + d.Name() + "/exe")
		if execPath != "" {
			cmdline = prependPath(execPath, cmdline)
		}

		if _ppid != 0 {
			pexecPath, _ = filepath.EvalSymlinks(ProcFS + ppid + "/exe")
			if pexecPath != "" {
				pcmdline = prependPath(pexecPath, pcmdline)
			}
		} else {
			pexecPath = ""
		}

		pcmdsUTF := stringToUTF8(pcmdline)
		cmdsUTF := stringToUTF8(cmdline)

		p := ObserverProcs{
			ppid: uint32(_ppid), pnspid: pnspid, pargs: pcmdsUTF,
			pflags: api.EventProcFS | api.EventNeedsCWD | api.EventNeedsAUID,
			pktime: pktime,
			pid:    uint32(pid), nspid: nspid, args: cmdsUTF,
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
	k.pushEvents(procs, entryMap, push)
	return procs
}

func (k *ObserverKprobe) populateExecve(ctx context.Context) {
	k.getRunningProcs(true, false)
}

type ObserverChannel struct {
	conn    net.Conn
	encoder *gob.Encoder
}

type MsgFilterRun func(*api.MsgIPv4TcpConnectUnix, *ObserverKprobe) bool

type MsgFilter struct {
	run        MsgFilterRun
	filterPass int
	filterDrop int
}

type ObserverKprobe struct {
	bpfDir        string
	execve_fd     int
	tcp_events_fd int
	prettyPrinter bool
	listeners     []ObserverChannel
	perfConfig    *bpf.PerfEventConfig
	enableExecve  bool
	/* Statistics */
	lostCntr   int
	errorCntr  int
	recvCntr   int
	filterPass int
	filterDrop int
	/* Filters */
	msgFilter []*MsgFilter
}

func defaultFilter(msg *api.MsgIPv4TcpConnectUnix) bool {
	return true
}

func (k *ObserverKprobe) observerMinReqs(ctx context.Context) (bool, error) {
	version, _, err := getKernelVersion()
	if err != nil {
		return false, fmt.Errorf("Kernel version lookup failed, required for requirements check.\n")
	}
	minVersion := int(kernelStringToNumeric("4.19.0"))
	if version >= minVersion {
		return true, nil
	}
	filename := ProcFS + "/sys/kernel/pid_max"
	pidMax, err := ioutil.ReadFile(filename)
	if err != nil {
		return false, fmt.Errorf("ReadFile: %s error: %s\n", filename, err)
	}
	pidString := strings.Fields(string(pidMax))
	pids, err := strconv.ParseUint(pidString[0], 10, 32)
	if err != nil {
		return false, fmt.Errorf("pidMax parsing failed: %s\n", err)
	}
	if pids > MaxSupportedPids {
		if SetPidMax == true {
			procPid := []byte("32768")
			err := ioutil.WriteFile(filename, procPid, 0)
			if err != nil {
				return false, fmt.Errorf("set-max-pid failed: %s\n", err)
			}
			fmt.Printf("hubble-fgs, Configured max_pid %d -> %d\n", pids, MaxSupportedPids)
			return true, nil
		}
		return false, fmt.Errorf("Current pid_max (%d) greater than max supported pids (%d). 4.19+ kernel required to support all features with current pid_max. Either use --set-pid-max to have hubble-fgs configure pid or upgrade kernel.", pids, MaxSupportedPids)
	}
	return true, nil
}

func btfFileExists(file string) error {
	_, err := os.Stat(file)
	return err
}

func (k *ObserverKprobe) observerFindProgs(ctx context.Context) error {
	if ObserverExecve.Observer__program == "" {
		if k.enableExecve {
			ObserverExecve.Observer__program = varLibHubbleFGS + execveEventProg
		} else {
			ObserverExecve.Observer__program = varLibHubbleFGS + execveProg
		}
	}

	for _, p := range observerPrograms {
		if _, err := os.Stat(p.Observer__program); err == nil {
			continue
		}
		last := strings.Split(p.Observer__program, "/")
		filename := last[len(last)-1]

		path := varLibHubbleFGS + filename
		if _, err := os.Stat(path); err == nil {
			p.Observer__program = path
			continue
		}

		path = defaultBPFPath + filename
		if _, err := os.Stat(path); err == nil {
			p.Observer__program = path
			continue
		}
		return fmt.Errorf("Observer Program '%s' can not be found\n", p.Observer__program)
	}
	return nil
}

func (k *ObserverKprobe) observerFindBTF(ctx context.Context) error {
	if ObserverBTF == "" {
		var uname unix.Utsname

		err := unix.Uname(&uname)
		if err != nil {
			return fmt.Errorf("Kernel version lookup (uname -r) failing. Use '--kernel' to set manually: %s\n", err)
		}
		n := bytes.IndexByte(uname.Release[:], 0)
		runFile := varLibHubbleFGS + "vmlinux-" + string(uname.Release[:n])
		if _, err := os.Stat(runFile); err == nil {
			ObserverBTF = runFile
			return nil
		}

		if _, err := os.Stat(localBTFFile); err == nil {
			ObserverBTF = localBTFFile
			return nil
		}

		return fmt.Errorf("Kernel version '%s' BTF search failed kernel is not white listed. Use --btf option to specify BTF path and/or '--kernel' to specify kernel version.", uname.Release[:n])
	}
	return nil
}

func (k *ObserverKprobe) Start() error {
	k.createDir()
	if err := k.observerFindBTF(context.TODO()); err != nil {
		return fmt.Errorf("hubble-fgs, Aborting kernel autodiscovery failed. %s\n", err)
	}
	if err := k.observerFindProgs(context.TODO()); err != nil {
		return fmt.Errorf("hubble-fgs, Aborting could not find BPF programs. %s\n", err)
	}
	if _, err := k.observerMinReqs(context.TODO()); err != nil {
		return fmt.Errorf("hubble-fgs, Aborting minimum pid requirements not met. %s\n", err)
	}
	if err := k.observerLoadExecve(context.TODO()); err != nil {
		return fmt.Errorf("hubble-fgs, Aborting could not load BPF programs. %s\n", err)
	}
	k.populateExecve(context.TODO())
	k.perfConfig = bpf.DefaultPerfEventConfig()
	if err := k.runEvents(context.TODO()); err != nil {
		return fmt.Errorf("hubble-fgs, Aborting runtime error. %s", err)
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
	maps, err := getKernelMaps()
	if err != nil {
		fmt.Printf("Deleting maps failed: %s\n", err)
	}
	for _, m := range maps {
		os.Remove(k.bpfDir + m)
	}
	os.Remove(k.bpfDir)
}

func NewObserverKprobe(bpfDir string, execve, pretty bool) *ObserverKprobe {
	zlog = logger.GetLogger()
	return &ObserverKprobe{
		bpfDir:        bpfDir,
		enableExecve:  execve,
		prettyPrinter: pretty,
	}
}

func (k *ObserverKprobe) PrintStats() {
	fmt.Printf("Observer Stats: errors %d lost %d recvd %d filterPass %d filterDrop %d\n",
		k.errorCntr, k.lostCntr, k.recvCntr, k.filterPass, k.filterDrop)
}

func (k *ObserverKprobe) AttachFilter(f *MsgFilter) {
	k.msgFilter = append(k.msgFilter, f)
}

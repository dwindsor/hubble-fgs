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
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io/ioutil"
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

	"github.com/covalentio/hubble-fgs/pkg/api"
	"github.com/covalentio/hubble-fgs/pkg/bpf"
	"github.com/covalentio/hubble-fgs/pkg/logger"
	"github.com/covalentio/hubble-fgs/pkg/reader"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	Progsize = 64
	MaxArgs  = 5
	ArgSize  = 32

	MaxSupportedPids = 32768

	nanoPerSeconds = 1000000000

	TCP_PROC_STATE_LISTEN = 10
)

const (
	BPF_PROG_TYPE_UNSPEC                  = 0
	BPF_PROG_TYPE_SOCKET_FILTER           = 1
	BPF_PROG_TYPE_KPROBE                  = 2
	BPF_PROG_TYPE_SCHED_CLS               = 3
	BPF_PROG_TYPE_SCHED_ACT               = 4
	BPF_PROG_TYPE_TRACEPOINT              = 5
	BPF_PROG_TYPE_XDP                     = 6
	BPF_PROG_TYPE_PERF_EVENT              = 7
	BPF_PROG_TYPE_CGROUP_SKB              = 8
	BPF_PROG_TYPE_CGROUP_SOCK             = 9
	BPF_PROG_TYPE_LWT_IN                  = 10
	BPF_PROG_TYPE_LWT_OUT                 = 11
	BPF_PROG_TYPE_LWT_XMIT                = 12
	BPF_PROG_TYPE_SOCK_OPS                = 13
	BPF_PROG_TYPE_SK_SKB                  = 14
	BPF_PROG_TYPE_CGROUP_DEVICE           = 15
	BPF_PROG_TYPE_SK_MSG                  = 16
	BPF_PROG_TYPE_RAW_TRACEPOINT          = 17
	BPF_PROG_TYPE_CGROUP_SOCK_ADDR        = 18
	BPF_PROG_TYPE_LWT_SEG6LOCAL           = 19
	BPF_PROG_TYPE_LIRC_MODE2              = 20
	BPF_PROG_TYPE_SK_REUSEPORT            = 21
	BPF_PROG_TYPE_FLOW_DISSECTOR          = 22
	BPF_PROG_TYPE_CGROUP_SYSCTL           = 23
	BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE = 24
	BPF_PROG_TYPE_CGROUP_SOCKOPT          = 25
	BPF_PROG_TYPE_TRACING                 = 26
	BPF_PROG_TYPE_STRUCT_OPS              = 27
	BPF_PROG_TYPE_EXT                     = 28
	BPF_PROG_TYPE_LSM                     = 29
)

func NameToProgType(n string) int {
	switch n {
	case "kprobe":
		return BPF_PROG_TYPE_KPROBE
	case "tracepoint":
		return BPF_PROG_TYPE_KPROBE
	case "sockops":
		return BPF_PROG_TYPE_SOCK_OPS
	case "skmsg":
		return BPF_PROG_TYPE_SK_MSG
	case "cgrp_ingress":
		return BPF_PROG_TYPE_CGROUP_SKB
	case "tc_ingress":
		return BPF_PROG_TYPE_SCHED_CLS
	case "tc_egress":
		return BPF_PROG_TYPE_SCHED_CLS
	}
	return -1
}

type shouldLoad func(k *ObserverKprobe) bool

func alwaysLoad(k *ObserverKprobe) bool  { return true }
func neverLoad(k *ObserverKprobe) bool   { return false }
func isTLSLoad(k *ObserverKprobe) bool   { return k.enableTLS }
func isTLSTCLoad(k *ObserverKprobe) bool { return k.enableTLSTC }
func isExternal(k *ObserverKprobe) bool  { return false }

type bpfLoad struct {
	Observer__btf        string
	Observer__program    string
	observer__x64_attach string
	observer__attach     string
	observer__label      string
	observer__prog       string

	retProbe   bool
	errorFatal bool

	probeType string
	load      shouldLoad

	tracefd int
}

type ObserverMap struct {
	mapName   string
	mapType   string
	bpf       *bpfLoad
	shouldPin shouldLoad
}

var (
	ProcFS        = "/proc/"
	KernelVersion = ""
	SetPidMax     = false

	HubbleLib          string
	ObserverBTF        string
	Verbosity          int
	IgnoreMissingProgs bool

	ObserverExecve = bpfLoad{
		"", "bpf_execve_event.o",
		"sched_process_exec",
		"sched_process_exec",
		"tracepoint/sys_execve",
		"event_execve",

		false,
		true,
		"tracepoint",
		alwaysLoad,

		-1,
	}

	ObserverExit = bpfLoad{
		"", "bpf_exit.o",
		"sched_process_exit",
		"sched_process_exit",
		"tracepoint/sys_exit",
		"event_exit",

		false,
		true,
		"tracepoint",
		alwaysLoad,

		-1,
	}

	ObserverFork = bpfLoad{
		"", "bpf_fork.o",
		"wake_up_new_task",
		"wake_up_new_task",
		"kprobe/wake_up_new_task",
		"kprobe_pid_clear",

		false,
		true,
		"kprobe",
		alwaysLoad,

		-1,
	}

	ObserverTCPConnect = bpfLoad{
		"", "bpf_tcpmon.o",
		"tcp_connect",
		"tcp_connect",
		"kprobe/tcp_connect",
		"kprobe_tcp_connect",

		false,
		true,
		"kprobe",
		alwaysLoad,

		-1,
	}

	ObserverTCPConnectRet = bpfLoad{
		"", "bpf_tcpmonret.o",
		"__x64_sys_connect",
		"sys_connect",
		"kretprobe/sys_connect",
		"kretprobe_sys_connect",

		true,
		true,
		"kprobe",
		alwaysLoad,

		-1,
	}

	ObserverListen = bpfLoad{
		"", "bpf_listen.o",
		"__inet_hash",
		"__inet_hash",
		"kprobe/inet_hash",
		"kprobe_inet_hash",

		false,
		true,
		"kprobe",
		alwaysLoad,

		-1,
	}

	ObserverSockopsEstablished = bpfLoad{
		"", "bpf_sockops.o",
		"sockops",
		"sockops",
		"sockops/tls_sockops",
		"sockops_tls_sockops",

		false,
		true,
		"sockops",
		isTLSLoad,

		-1,
	}

	ObserverSkmsgTLS = bpfLoad{
		"", "bpf_skmsg_tls.o",
		"sk_msg",
		"sk_msg",
		"sk_msg/tls",
		"sk_msg_tls",

		false,
		true,
		"skmsg",
		isTLSLoad,

		-1,
	}

	ObserverCgrpIngress = bpfLoad{
		"", "bpf_cgrp_in_tls.o",
		"cgroup_skb",
		"cgroup_skb",
		"cgroup_skb/ingress",
		"cgroup_skb_ingress",

		false,
		true,
		"cgrp_ingress",
		isTLSLoad,

		-1,
	}

	ObserverTLSEvent = bpfLoad{
		"", "bpf_event_tls.o",
		"tcp_v4_fill_cb",
		"tcp_v4_fill_cb",
		"kprobe/tcp_v4_fill_cb",
		"kprobe_tcp_v4_fill_cb",

		false,
		true,
		"kprobe",
		isTLSLoad,

		-1,
	}

	ObserverTLSTCIngress = bpfLoad{
		"", "bpf_tc_ingress.o",
		"ingress_tcp",
		"ingress_tcp",
		"tc/ingress_tcp",
		"tc_ingress_tcp",

		false,
		true,
		"tc_ingress",
		isTLSTCLoad,

		-1,
	}

	ObserverTLSTCEgress = bpfLoad{
		"", "bpf_tc_egress.o",
		"egress_tcp",
		"egress_tcp",
		"tc/egress_tcp",
		"tc_egress_tcp",

		false,
		true,
		"tc_egress",
		isTLSTCLoad,

		-1,
	}

	observerTimeout = 5 * time.Minute
	execTimeout     = 5 * time.Minute
	pollTimeout     = 5000

	observerPrograms = []*bpfLoad{
		&ObserverExecve,
		&ObserverExit,
		&ObserverFork,
		&ObserverTCPConnect,
		&ObserverTCPConnectRet,
		&ObserverListen,
		&ObserverSockopsEstablished,
		&ObserverSkmsgTLS,
		&ObserverCgrpIngress,
		&ObserverTLSEvent,
		&ObserverTLSTCEgress,
		&ObserverTLSTCIngress}

	/* Event Ring map */
	ObserverTCPMonMap = ObserverMap{"tcpmon_map", "", &ObserverExecve, alwaysLoad}
	/* Networking and Process Monitoring maps */
	ObserverExecveMap = ObserverMap{"execve_map", "", &ObserverExecve, alwaysLoad}
	ObserverSocketMap = ObserverMap{"socket_map", "", &ObserverTCPConnect, alwaysLoad}
	ObserverTcpMap    = ObserverMap{"ipv4_tcp_map", "", &ObserverTCPConnect, alwaysLoad}
	/* TLS maps */
	ObserverTCTLSMap = ObserverMap{"tls_map", "tc_ingress", &ObserverTLSTCEgress, isTLSTCLoad}
	ObserverSockMap  = ObserverMap{"fgs_sock_map", "sockops", &ObserverSockopsEstablished, isTLSLoad}
	ObserverTLSMap   = ObserverMap{"tls_map", "skmsg", &ObserverSkmsgTLS, isTLSLoad}
	/* Internal statistics for debugging */
	ObserverExecveStats = ObserverMap{"execve_map_stats", "", &ObserverExecve, alwaysLoad}
	ObserverSocketStats = ObserverMap{"socket_map_stats", "", &ObserverExecve, alwaysLoad}
	ObserverTlsStats    = ObserverMap{"tls_map_stats", "", &ObserverExecve, alwaysLoad}
	/* Cilium maps */
	ObserverCiliumSnat = ObserverMap{"cilium_snat_v4_external", "", &ObserverTCPConnect, isExternal}

	observerMaps = []*ObserverMap{
		&ObserverSocketMap,
		&ObserverExecveMap,
		&ObserverTCPMonMap,
		&ObserverSockMap,
		&ObserverTLSMap,
		&ObserverTCTLSMap,
		&ObserverExecveStats,
		&ObserverSocketStats,
		&ObserverTlsStats,
		&ObserverCiliumSnat,
	}
)

func (k *ObserverKprobe) disableBpfLoad(bpf *bpfLoad) {

	disableFn := func(k *ObserverKprobe) bool {
		return false
	}

	bpf.load = disableFn
	for _, om := range observerMaps {
		if om.bpf == bpf {
			logger.GetLogger().Infof("disabling map %s", om.mapName)
			om.shouldPin = disableFn
		}
	}
}

func (k *ObserverKprobe) observerListenersTLS(msg *api.MsgTLSEvent) {
	for listener, _ := range k.listeners {
		if err := listener.Notify(msg); err != nil {
			k.log.Debug("Write failure removing Listener")
			k.RemoveListener(listener)
		}
	}
}

func (k *ObserverKprobe) observerListenersExecve(msg *api.MsgExecveEventUnix) {
	for listener, _ := range k.listeners {
		if err := listener.Notify(msg); err != nil {
			k.log.Debug("Write failure removing Listener")
			k.RemoveListener(listener)
		}
	}
}

func (k *ObserverKprobe) observerListenersExit(msg *api.MsgExitEventUnix) {
	for listener, _ := range k.listeners {
		if err := listener.Notify(msg); err != nil {
			k.log.Debug("Write failure removing Listener")
			k.RemoveListener(listener)
		}
	}
}

func (k *ObserverKprobe) observerListenersTcp(msg *api.MsgIPv4TcpEventUnix) {
	if pass := k.runFilters(msg); pass {
		for listener, _ := range k.listeners {
			if err := listener.Notify(msg); err != nil {
				k.log.WithError(err).Debug("Write failure removing Listener")
				k.RemoveListener(listener)
			}
		}
	}
}

func (k *ObserverKprobe) AddListener(listener Listener) {
	k.log.WithField("listener", listener).Debug("Add listener")
	k.listeners[listener] = struct{}{}
	k.getRunningProcs(false, true)
}

func (k *ObserverKprobe) RemoveListener(listener Listener) {
	k.log.WithField("listener", listener).Debug("Delete listener")
	delete(k.listeners, listener)
	if err := listener.Close(); err != nil {
		k.log.WithError(err).Warn("failed to close listener")
	}
}

func msgToExecveUnix(m *api.MsgExecveEvent) *api.MsgExecveEventUnix {
	unix := &api.MsgExecveEventUnix{}

	unix.Common = m.Common
	unix.Kube.NetNS = m.Kube.NetNS
	unix.Kube.Cid = m.Kube.Cid
	unix.Kube.Cgrpid = m.Kube.Cgrpid
	unix.Kube.Docker = strings.Trim(string(m.Kube.Docker[:]), "\u0000")
	unix.Parent = m.Parent
	return unix
}

func msgToExitUnix(m *api.MsgExitEvent) *api.MsgExitEventUnix {
	return m
}

func msgToTcpUnix(m *api.MsgIPv4Tcp) *api.MsgIPv4TcpEventUnix {
	unix := &api.MsgIPv4TcpEventUnix{}

	unix.Common = m.Common
	unix.Tuple = m.Tuple
	unix.Return = m.Return
	unix.ProcessKey = m.ProcessKey

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
		fmt.Printf("read error!\n")
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
		args := make([]byte, size) //+2)
		if err := binary.Read(reader, binary.LittleEndian, &args); err != nil {
			fmt.Printf("read error: binary reader error size %d exec.Size %d api %d\n", size, exec.Size, api.SIZEOF_EXECVE)
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

func (k *ObserverKprobe) runFilters(msgUnix *api.MsgIPv4TcpEventUnix) bool {
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
	case api.MSG_OP_TLS:
		m := api.MsgTLSEvent{}
		err := binary.Read(r, binary.LittleEndian, &m)
		if err != nil {
			break
		}
		/* OR filter together */
		k.observerListenersTLS(&m)
		/* Keeping pretty printer because it helps debugging filters */
		if k.prettyPrinter {
			reader.ObserverTLSPrinter(&m, k.log)
		}
	case api.MSG_OP_EXECVE:
		m := api.MsgExecveEvent{}
		err := binary.Read(r, binary.LittleEndian, &m)
		if err != nil {
			fmt.Printf("api.MSG_OP_EXECVE binary read failure: %s\n", err)
			break
		}
		msgUnix := msgToExecveUnix(&m)
		msgUnix.Process, empty, err = execParse(r)
		if err != nil && empty {
			msgUnix.Process = nopMsgExecUnix()
		}
		k.observerListenersExecve(msgUnix)
	case api.MSG_OP_EXIT:
		m := api.MsgExitEvent{}
		err := binary.Read(r, binary.LittleEndian, &m)
		if err != nil {
			fmt.Printf("api.MSG_OP_EXIT binary read failure: %s\n", err)
			break
		}
		msgUnix := msgToExitUnix(&m)
		k.observerListenersExit(msgUnix)
	case api.MSG_OP_IPV4_TCPCONNECT,
		api.MSG_OP_IPV4_TCPCONNECTRET,
		api.MSG_OP_IPV4_BIND,
		api.MSG_OP_IPV4_LISTEN:
		m := api.MsgIPv4Tcp{}
		err := binary.Read(r, binary.LittleEndian, &m)
		if err != nil {
			break
		}
		msgUnix := msgToTcpUnix(&m)
		k.observerListenersTcp(msgUnix)
	}
}

func getCWD(pid uint32) (string, uint32) {
	flags := uint32(0)
	pidstr := fmt.Sprint(pid)

	if pid == 0 {
		return "", flags
	}

	cwd, err := os.Readlink(filepath.Join(ProcFS, pidstr, "cwd"))
	if err != nil {
		flags |= api.EventRootCWD | api.EventErrorCWD
		return " ", flags
	}

	if cwd == "/" {
		cwd = " "
		flags |= api.EventRootCWD
	}
	return cwd, flags
}

func procsFilename(args []byte) (string, string) {
	cmdArgs := bytes.Split(args, []byte{0x00})
	filename := string(cmdArgs[0])
	cmds := string(bytes.Join(cmdArgs[1:], []byte{0x00}))
	return cmds, filename
}

func procsDockerID(pid uint32) string {
	pidstr := fmt.Sprint(pid)
	cgroups, err := ioutil.ReadFile(filepath.Join(ProcFS, pidstr, "cgroup"))
	if err != nil {
		return ""
	}
	docker := strings.SplitAfter(string(cgroups), "docker/")
	if len(docker) == 1 { // no docker cgroups
		return ""
	}
	return strings.SplitAfter(docker[1], "\n")[0][0:12]
}

func (k *ObserverKprobe) pushTCPEvents(msg *api.MsgExecveEventUnix, tcpEntries map[uint32]procTCPEntry) {
	pid := msg.Process.PID
	tcp := api.MsgIPv4TcpEventUnix{}

	tcp.ProcessKey.Pid = pid
	tcp.ProcessKey.Ktime = msg.Process.Ktime

	fdDir := fmt.Sprintf("%s/%d/fd", ProcFS, pid)
	procFD, err := ioutil.ReadDir(fdDir)
	if err != nil {
		k.log.WithError(err).Warnf("ReadDir %d/fd/ failed", pid)
	}
	for _, d := range procFD {
		socket, err := os.Readlink(fdDir + "/" + d.Name())
		if err != nil && Verbosity > 0 {
			k.log.WithError(err).Warnf("Readlink error %s", d.Name())
		}
		if strings.Contains(socket, "socket") == true {
			fields := strings.Split(socket, ":")
			if len(fields) < 2 {
				continue
			}
			inode := fields[1]
			inode = strings.TrimRight(inode, "]")
			inode = strings.TrimLeft(inode, "[")
			inodeEntry, err := strconv.ParseUint(inode, 10, 32)
			if err != nil {
				k.log.WithError(err).Warnf("tcpEntry inode not parsable: %s", inode)
			} else {
				entry := tcpEntries[uint32(inodeEntry)]
				tcp.Tuple.SAddr = entry.localIP
				tcp.Tuple.DAddr = entry.remoteIP
				tcp.Tuple.DPort = entry.remotePort
				tcp.Tuple.SPort = entry.localPort
				tcp.Tuple.Proto = 2

				if entry.state == 0 {
					continue
				}

				if entry.state == TCP_PROC_STATE_LISTEN {
					tcp.Common.Op = api.MsgOpIPv4Listen
				} else {
					tcp.Common.Op = api.MsgOpIPv4TCPConnectReturn
				}

				k.observerListenersTcp(&tcp)
			}
		}
	}
}

func (k *ObserverKprobe) pushExecveEvents(p ObserverProcs, tcpEntries map[uint32]procTCPEntry, pushExecve bool) {
	args, filename := procsFilename(p.args)
	cwd, flags := getCWD(p.pid)
	if (flags & api.EventRootCWD) == 0 {
		args = args + " " + cwd
	}

	m := api.MsgExecveEventUnix{}
	m.Common.Op = api.MSG_OP_EXECVE
	m.Common.Ktime = 0
	m.Common.Size = api.MsgUnixSize + p.psize + p.size

	m.Kube.NetNS = 0
	m.Kube.Cid = 0
	m.Kube.Cgrpid = 0
	m.Kube.Docker = procsDockerID(p.pid)

	m.Parent.Pid = p.ppid
	m.Parent.Ktime = p.pktime

	m.Process.Size = p.size
	m.Process.PID = p.pid
	m.Process.NSPID = p.nspid
	m.Process.UID = p.uid
	m.Process.AUID = p.auid
	m.Process.Flags = p.flags | flags
	m.Process.Ktime = p.ktime
	m.Process.Filename = filename
	m.Process.Args = args

	if pushExecve {
		k.observerListenersExecve(&m)
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

func (k *ObserverKprobe) observerLoadMaps(btf string, stopCtx context.Context) error {
	version, _, err := getKernelVersion()
	if err != nil {
		return err
	}

	for _, m := range observerMaps {
		var err error

		if m.shouldPin(k) == false {
			continue
		}

		pin := k.mapDir + m.mapName

		fd, err := bpf.LoadAndPinMaps(version, Verbosity, btf, m.bpf.Observer__program, pin, m.mapName,
			NameToProgType(m.bpf.probeType))
		k.log.Debugf("LoadAndPinMaps(%s, %s, %s)\n", m.bpf.Observer__program, pin, m.mapName)
		if err != nil {
			return fmt.Errorf("failed %d load map (%s): %s\n", fd, m.mapType, err)
		}
	}

	k.startUpdateMapMetrics()
	return nil
}

func (k *ObserverKprobe) getDefaultRouteLinks() ([]netlink.Link, error) {
	var links []netlink.Link

	nilDst := &netlink.Route{Dst: nil}
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_V4, nilDst, netlink.RT_FILTER_DST)
	if err != nil {
		k.log.WithError(err).Warn("RouteListFiltered failed:")
		return nil, err
	}
	allLinks, err := netlink.LinkList()
	if err != nil {
		k.log.WithError(err).Warn("LinkList failed:")
		return nil, err
	}
	for _, route := range routes {
		for _, link := range allLinks {
			if link.Attrs().Index == route.LinkIndex {
				links = append(links, link)
			}
		}
	}
	return links, nil
}

func (k *ObserverKprobe) observerLoadTC(load *bpfLoad, version, Verbosity int, btf string) (error, int) {
	var attachLinks []netlink.Link

	err, fd := bpf.LoadTC(version, Verbosity,
		btf,
		load.Observer__program,
		load.observer__label,
		k.bpfDir+load.observer__prog,
		k.mapDir,
		k.ciliumDir)
	if err != nil {
		return err, fd
	}
	if k.interfaces != "" {
		links, err := netlink.LinkList()
		if err != nil {
			return err, 0
		}
		ifaceMatch := strings.Split(k.interfaces, ",")
		for _, link := range links {
			for _, m := range ifaceMatch {
				add, err := regexp.MatchString(m, link.Attrs().Name)
				if err != nil || !add {
					continue
				}
				attachLinks = append(attachLinks, link)
			}
		}
	} else {
		attachLinks, err = k.getDefaultRouteLinks()
		if err != nil {
			return err, 0
		}
	}

	for _, link := range attachLinks {
		k.log.Infof("Attaching %s to device %s", load.probeType, link.Attrs().Name)
		isIngress := "tc_ingress" == load.probeType
		if err = bpf.QdiscTCInsert(link.Attrs().Name, isIngress); err != nil {
			return err, 0
		}
		bpf.AttachTCIngress(fd, link.Attrs().Name, isIngress)
	}

	return nil, 0
}

func (k *ObserverKprobe) loadInstance(load *bpfLoad, version, Verbosity int, btf string, x64 bool) (error, int) {
	var attach string

	if x64 {
		attach = load.observer__x64_attach
	} else {
		attach = load.observer__attach
	}
	if load.probeType == "tracepoint" {
		return bpf.LoadTracingProgram(
			version, Verbosity,
			btf,
			load.Observer__program,
			attach,
			load.observer__label,
			k.bpfDir+load.observer__prog,
			k.mapDir,
			load.retProbe)
	} else if load.probeType == "sockops" {
		return bpf.LoadSockopsProgram(
			version, Verbosity,
			btf,
			load.Observer__program,
			load.observer__label,
			k.bpfDir+load.observer__prog,
			k.mapDir)
	} else if load.probeType == "skmsg" {
		return bpf.LoadSkmsgProgram(
			version, Verbosity,
			btf,
			load.Observer__program,
			load.observer__label,
			k.bpfDir+load.observer__prog,
			k.mapDir)
	} else if load.probeType == "cgrp_ingress" {
		return bpf.LoadCgroupProgram(
			version, Verbosity,
			btf,
			load.Observer__program,
			load.observer__label,
			k.bpfDir+load.observer__prog,
			k.mapDir)
	} else if load.probeType == "tc_ingress" || load.probeType == "tc_egress" {
		return k.observerLoadTC(load, version, Verbosity, btf)
	} else {
		return bpf.LoadKprobeProgram(
			version, Verbosity,
			btf,
			load.Observer__program,
			attach,
			load.observer__label,
			k.bpfDir+load.observer__prog,
			k.mapDir,
			load.retProbe)
	}
}

func (k *ObserverKprobe) observerLoadInstance(load *bpfLoad, stopCtx context.Context) error {
	var btf string
	var fd int

	if load.Observer__btf == "" {
		btf = ObserverBTF
	} else {
		btf = load.Observer__btf
	}

	version, _, err := getKernelVersion()
	if err != nil {
		return err
	}

	k.log.Debugf("prog %s kern_version %d\n", load.Observer__program, version)
	if load.probeType == "tracepoint" {
		err, fd = k.loadInstance(load, version, Verbosity, btf, true)
		if err != nil && fd == -17 { // tracepoint exists be unfriendly and delete it
			removeTracepoint(load.tracefd)
			err, fd = k.loadInstance(load, version, Verbosity, btf, true)
		}
		if err != nil {
			return fmt.Errorf("Failed prog %s kern_version %d err %d LoadTracingProgram: %s\n",
				load.Observer__program, version, fd, err)
		}
	} else {
		err, fd = k.loadInstance(load, version, Verbosity, btf, true)
		if err != nil {
			/* If we fail attach with __x64_sys_execve variant try again with
			 * sys_execve variant.
			 */
			err, fd = k.loadInstance(load, version, Verbosity, btf, false)
			if err != nil && load.errorFatal {
				return fmt.Errorf("Failed prog %s kern_version %d LoadKprobeProgram: %s\n",
					load.Observer__program, version, err)
			}
		}
	}
	load.tracefd = fd
	return nil
}

func (k *ObserverKprobe) observerLoadProgs(stopCtx context.Context) error {
	var btf string

	if ObserverExecve.Observer__btf == "" {
		btf = ObserverBTF
	} else {
		btf = ObserverExecve.Observer__btf
	}

	_, verStr, _ := getKernelVersion()
	k.log.Infof("Loading kernel version %s", verStr)

	/* Assumption observer__program execve contains all maps */
	if err := k.observerLoadMaps(btf, stopCtx); err != nil {
		return err
	}

	for _, p := range observerPrograms {
		if p.load(k) == false {
			continue
		}
		if err := k.observerLoadInstance(p, stopCtx); err != nil {
			return err
		}
	}
	k.log.Infof("hubble-fgs, loaded BPF maps and events successfully.\n")
	return nil
}

func (k *ObserverKprobe) __runEvents(stopCtx context.Context) (*bpf.PerCpuEvents, error) {
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

	k.log.Info("Listening for events...")
	for !isCtxDone(stopCtx) {
		todo, err := e.Poll(pollTimeout)
		switch {
		case isCtxDone(stopCtx):
			k.log.Debug("isCtxDone completed")
			return nil

		case err == syscall.EBADF:
			return fmt.Errorf("kprobe events syscall.EBADF: %s", err)

		case err != nil:
			k.log.WithError(err).Warn("kprobe events poll failed")
			continue
		}
		if todo > 0 {
			if err := e.ReadAll(receiveEvent, observerLost, observerError); err != nil {
				k.log.WithError(err).Warn("kprobe events read failed")
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
	os.Mkdir(k.mapDir, os.ModeDir)
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
	Common      api.MsgCommon
	Kube        api.MsgK8s
	Parent      api.MsgExecveKey
	ParentFlags uint64
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

func (k *ObserverKprobe) writeExecveMap(procs []ObserverProcs) {

	if !ObserverExecveMap.shouldPin(k) {
		return
	}

	m, err := bpf.OpenMap(filepath.Join(k.mapDir, ObserverExecveMap.mapName))
	if err != nil {
		panic(err)
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
}

func getPIDNS(filename string) uint32 {
	file, err := ioutil.ReadFile(filename)
	if err != nil {
		logger.GetLogger().WithError(err).Warnf("ReadFile failed: %s", filename)
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
				logger.GetLogger().WithError(err).Warnf("NStgid parser failed %s", filename)
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
		logger.GetLogger().WithError(err).Warn("localIP parse error")
	}
	localPort, err := strconv.ParseUint(local[1], 16, 16)
	if err != nil {
		logger.GetLogger().WithError(err).Warn("localPort parse error")
	}
	remoteIP, err := strconv.ParseUint(remote[0], 16, 32)
	if err != nil {
		logger.GetLogger().WithError(err).Warn("remoteIP parse error")
	}
	remotePort, err := strconv.ParseUint(remote[1], 16, 16)
	if err != nil {
		logger.GetLogger().WithError(err).Warn("remotePort parse error")
	}
	state, err := strconv.ParseUint(fields[3], 16, 32)
	if err != nil {
		logger.GetLogger().WithError(err).Warn("TCP state parse error")
	}
	inode, err := strconv.ParseUint(fields[9], 10, 32)
	if err != nil {
		logger.GetLogger().WithError(err).Warn("inode parse error")
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
		k.log.WithError(err).Warn("Failed to parse and build proc net map. Will not post connections started before hubble-fgs.")
	}

	for _, d := range procFS {
		var pcmdline, pstatline []byte
		var pstats []string
		var pktime uint64
		var pexecPath string
		var pnspid uint32

		clktck, err := getClkTck()
		if err != nil {
			k.log.WithError(err).Warn("procFS wallclock time may be inaccurate")
			clktck = 1
		}

		if d.IsDir() == false {
			continue
		}
		cmdline, err := ioutil.ReadFile(filepath.Join(ProcFS, d.Name(), "cmdline"))
		if err != nil {
			continue
		}
		if string(cmdline) == "" {
			continue
		}
		statline, err := ioutil.ReadFile(filepath.Join(ProcFS, d.Name(), "stat"))
		if err != nil {
			k.log.WithError(err).Warnf("ReadFile: %s /stat error", filepath.Join(ProcFS, d.Name(), "cmdline"))
			continue
		}
		pid, err := strconv.ParseUint(d.Name(), 10, 32)
		if err != nil {
			k.log.WithError(err).Warnf("ReadFile: %s /parseuint error", filepath.Join(ProcFS, d.Name(), "cmdline"))
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
			k.log.WithError(err).Warnf("Ktime parsing error: %s: %s", _ktime, filepath.Join(ProcFS, ppid, "stat"))
			ktime = 0
		}
		ktime = (ktime / clktck) * nanoPerSeconds
		nspid := getPIDNS(filepath.Join(ProcFS, d.Name(), "status"))

		if _ppid != 0 {
			var err error

			pcmdline, err = ioutil.ReadFile(filepath.Join(ProcFS, ppid, "cmdline"))
			if err != nil {
				k.log.WithError(err).Warnf("ReadFile: %s /cmdline error\n", filepath.Join(ProcFS, d.Name(), "cmdline"))
				continue
			}

			pstatline, err = ioutil.ReadFile(filepath.Join(ProcFS, ppid, "stat"))
			if err != nil {
				k.log.WithError(err).Warnf("ReadFile: %s /stat error\n", filepath.Join(ProcFS, d.Name(), "cmdline"))
				continue
			}
			pstats = r.FindAllString(string(pstatline), -1)
			_pktime := pstats[21]
			pktime, err = strconv.ParseUint(_pktime, 10, 64)
			if err != nil {
				k.log.WithError(err).Warnf("Warning: Parent ktime parsing error: %s: %s", _pktime, filepath.Join(ProcFS, ppid, "stat"))
				pktime = 0
			}
			pktime = (pktime / clktck) * nanoPerSeconds
			pnspid = getPIDNS(filepath.Join(ProcFS, ppid, "status"))
		} else {
			pcmdline = nil
			pstatline = nil
			pstats = nil
			pktime = 0
			pnspid = 0
		}

		execPath, err := filepath.EvalSymlinks(filepath.Join(ProcFS, d.Name(), "exe"))
		if execPath != "" {
			cmdline = prependPath(execPath, cmdline)
		}

		if _ppid != 0 {
			pexecPath, _ = filepath.EvalSymlinks(filepath.Join(ProcFS, ppid, "exe"))
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
	k.log.Infof("Read ProcFS %s appended %d/%d entries\n", ProcFS, len(procs), len(procFS))

	if write {
		k.writeExecveMap(procs)
	}
	k.pushEvents(procs, entryMap, push)
	return procs
}

func (k *ObserverKprobe) populateExecve(ctx context.Context) {
	k.getRunningProcs(true, false)
}

type MsgFilterRun func(*api.MsgIPv4TcpEventUnix, *ObserverKprobe) bool

type MsgFilter struct {
	run        MsgFilterRun
	filterPass int
	filterDrop int
}

type ObserverKprobe struct {
	/* Configuration */
	bpfDir     string
	mapDir     string
	ciliumDir  string
	interfaces string
	listeners  map[Listener]struct{}
	perfConfig *bpf.PerfEventConfig
	/* Features */
	prettyPrinter bool
	enableTLS     bool
	enableTLSTC   bool
	/* Statistics */
	lostCntr   int
	errorCntr  int
	recvCntr   int
	filterPass int
	filterDrop int
	/* Filters */
	msgFilter []*MsgFilter
	log       logrus.FieldLogger
}

func defaultFilter(msg *api.MsgIPv4TcpEventUnix) bool {
	return true
}

func (k *ObserverKprobe) observerMinReqs(ctx context.Context) (bool, error) {
	_, _, err := getKernelVersion()
	if err != nil {
		return false, fmt.Errorf("Kernel version lookup failed, required for kprobe.\n")
	}
	return true, nil
}

func btfFileExists(file string) error {
	_, err := os.Stat(file)
	return err
}

func (k *ObserverKprobe) observerFindProgs(ctx context.Context) error {
	for _, p := range observerPrograms {
		if _, err := os.Stat(p.Observer__program); err == nil {
			continue
		}
		last := strings.Split(p.Observer__program, "/")
		filename := last[len(last)-1]

		path := HubbleLib + filename
		if _, err := os.Stat(path); err == nil {
			p.Observer__program = path
			continue
		}

		if IgnoreMissingProgs {
			logger.GetLogger().Warningf("failed to find BPF prog %s, but was told to ignore such errors. Disabling it and moving on.", p.Observer__program)
			k.disableBpfLoad(p)
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
		runFile := HubbleLib + "vmlinux-" + string(uname.Release[:n])
		if _, err := os.Stat(runFile); err == nil {
			ObserverBTF = runFile
			return nil
		}

		runFile = HubbleLib + "btf"
		if _, err := os.Stat(runFile); err == nil {
			ObserverBTF = runFile
			return nil
		}

		return fmt.Errorf("Kernel version '%s' BTF search failed kernel is not white listed. Use --btf option to specify BTF path and/or '--kernel' to specify kernel version.", uname.Release[:n])
	}
	return nil
}

func (k *ObserverKprobe) Start(ctx context.Context) error {
	k.createDir()
	if err := k.observerFindBTF(ctx); err != nil {
		return fmt.Errorf("hubble-fgs, Aborting kernel autodiscovery failed. %s\n", err)
	}
	if err := k.observerFindProgs(ctx); err != nil {
		return fmt.Errorf("hubble-fgs, Aborting could not find BPF programs. %s\n", err)
	}
	if _, err := k.observerMinReqs(ctx); err != nil {
		return fmt.Errorf("hubble-fgs, Aborting minimum requirements not met. %s\n", err)
	}
	if err := k.observerLoadProgs(ctx); err != nil {
		return fmt.Errorf("hubble-fgs, Aborting could not load BPF programs. %s\n", err)
	}
	k.populateExecve(ctx)
	k.perfConfig = bpf.DefaultPerfEventConfig()
	if err := k.runEvents(ctx); err != nil {
		return fmt.Errorf("hubble-fgs, Aborting runtime error. %s", err)
	}
	return nil
}

func removeTracepoint(fd int) {
	PERF_EVENT_IOC_DISABLE := uint(0x2401)
	err := unix.IoctlSetInt(fd, PERF_EVENT_IOC_DISABLE, 0)
	if err != nil && Verbosity > 1 {
		logger.GetLogger().WithError(err).Warnf("Warning failed tracepoint removal")
	}
	unix.Close(fd)
}

func (k *ObserverKprobe) RemovePrograms() {
	for _, l := range observerPrograms {
		os.Remove(k.bpfDir + l.observer__prog)
		if l.tracefd >= 0 {
			removeTracepoint(l.tracefd)
		}
	}

	for _, m := range observerMaps {
		os.Remove(k.mapDir + m.mapName)
	}
	os.Remove(k.bpfDir)
	os.Remove(k.mapDir)
}

func NewObserverKprobe(bpfDir, mapDir, ciliumDir, interfaces string, tls, tlstc, pretty bool) *ObserverKprobe {
	return &ObserverKprobe{
		bpfDir:        bpfDir,
		mapDir:        mapDir,
		ciliumDir:     ciliumDir,
		interfaces:    interfaces,
		enableTLS:     tls,
		enableTLSTC:   tlstc,
		prettyPrinter: pretty,
		listeners:     make(map[Listener]struct{}),
		log:           logger.GetLogger(),
	}
}

func (k *ObserverKprobe) PrintStats() {
	k.log.Infof("Observer Stats: errors %d lost %d recvd %d filterPass %d filterDrop %d",
		k.errorCntr, k.lostCntr, k.recvCntr, k.filterPass, k.filterDrop)
}

func (k *ObserverKprobe) AttachFilter(f *MsgFilter) {
	k.msgFilter = append(k.msgFilter, f)
}

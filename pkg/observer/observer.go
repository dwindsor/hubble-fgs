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
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/covalentio/hubble-fgs/pkg/api"
	"github.com/covalentio/hubble-fgs/pkg/bpf"
	"github.com/covalentio/hubble-fgs/pkg/ksyms"
	"github.com/covalentio/hubble-fgs/pkg/logger"
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

	maxMapRetries = 4
	mapRetryDelay = 1
)

const (
	TLS_MIN_CERT_SIZE = 12
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
	case "sk_skb_parser":
		return BPF_PROG_TYPE_SK_SKB
	case "sk_skb_verdict":
		return BPF_PROG_TYPE_SK_SKB
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

// bpfLoadState represents the state of a BPF program or map
//
// NB: Currently there is no case where we attempt to load a program that is
// already loaded. If this changes, we can use the count as a reference count
// to track users of a bpf program.
type bpfLoadState struct {
	//   0: idle (not loaded)
	//   1: loaded
	//  -1: disabled
	count int
}

func bpfLoadStateIdle() bpfLoadState {
	return bpfLoadState{0}
}

func (s *bpfLoadState) isLoaded() bool {
	return s.count > 0
}

func (s *bpfLoadState) isIdle() bool {
	return s.count == 0
}

func (s bpfLoadState) isDisabled() bool {
	return s.count == -1
}

func (s *bpfLoadState) setDisabled() {
	if s.isLoaded() {
		panic(fmt.Errorf("called setDisabled() while program is loaded (cnt: %d)", s.count))
	}
	s.count = -1
}

func (s *bpfLoadState) setLoaded() {
	if s.isDisabled() {
		panic(fmt.Errorf("called setLoaded() while program is disabled (cnt: %d)", s.count))
	}
	s.count = 1
}

type bpfLoad struct {
	Observer__program    string
	observer__x64_attach string
	observer__attach     string
	observer__label      string
	observer__prog       string

	retProbe   bool
	errorFatal bool

	probeType string
	loadState bpfLoadState

	tracefd int

	loaderData interface{}
}

type ObserverMap struct {
	mapName  string
	mapType  string
	bpf      *bpfLoad
	pinState bpfLoadState
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
		"bpf_execve_event.o",
		"sched/sched_process_exec",
		"sched/sched_process_exec",
		"tracepoint/sys_execve",
		"event_execve",

		false,
		true,
		"tracepoint",
		bpfLoadStateIdle(),

		-1,

		struct{}{},
	}

	ObserverExit = bpfLoad{
		"bpf_exit.o",
		"sched/sched_process_exit",
		"sched/sched_process_exit",
		"tracepoint/sys_exit",
		"event_exit",

		false,
		true,
		"tracepoint",
		bpfLoadStateIdle(),

		-1,

		struct{}{},
	}

	ObserverFork = bpfLoad{
		"bpf_fork.o",
		"wake_up_new_task",
		"wake_up_new_task",
		"kprobe/wake_up_new_task",
		"kprobe_pid_clear",

		false,
		true,
		"kprobe",
		bpfLoadStateIdle(),

		-1,

		struct{}{},
	}

	ObserverCred = bpfLoad{
		"bpf_cred.o",
		"commit_creds",
		"commit_creds",
		"kprobe/commit_creds",
		"kprobe_commit_creds",

		false,
		true,
		"kprobe",
		bpfLoadStateIdle(),

		-1,

		struct{}{},
	}

	ObserverTCPConnect = bpfLoad{
		"bpf_tcpmon.o",
		"tcp_connect",
		"tcp_connect",
		"kprobe/tcp_connect",
		"kprobe_tcp_connect",

		false,
		true,
		"kprobe",
		bpfLoadStateIdle(),

		-1,

		struct{}{},
	}

	ObserverTCPConnectRet = bpfLoad{
		"bpf_tcpmonret.o",
		"__x64_sys_connect",
		"sys_connect",
		"kretprobe/sys_connect",
		"kretprobe_sys_connect",

		true,
		true,
		"kprobe",
		bpfLoadStateIdle(),

		-1,

		struct{}{},
	}

	ObserverTCPClose = bpfLoad{
		"bpf_tcpclose.o",
		"tcp_set_state",
		"tcp_set_state",
		"kprobe/tcp_set_state",
		"kprobe_tcp_set_state",

		false,
		true,
		"kprobe",
		bpfLoadStateIdle(),

		-1,

		struct{}{},
	}

	ObserverListen = bpfLoad{
		"bpf_listen.o",
		"__inet_hash",
		"__inet_hash",
		"kprobe/inet_hash",
		"kprobe_inet_hash",

		false,
		true,
		"kprobe",
		bpfLoadStateIdle(),

		-1,

		struct{}{},
	}

	ObserverSockopsEstablished = bpfLoad{
		"bpf_sockops.o",
		"sockops",
		"sockops",
		"sockops/fgs_sockops",
		"sockops_fgs_sockops",

		false,
		true,
		"sockops",
		bpfLoadStateIdle(),

		-1,

		struct{}{},
	}

	ObserverSkmsg = bpfLoad{
		"bpf_skmsg.o",
		"sk_msg",
		"sk_msg",
		"sk_msg/fgs",
		"sk_msg_fgs",

		false,
		true,
		"skmsg",
		bpfLoadStateIdle(),

		-1,

		struct{}{},
	}

	ObserverSkSkbVerdict = bpfLoad{
		"bpf_skskb_verdict.o",
		"sk_skb",
		"sk_skb",
		"sk_skb_verdict/fgs",
		"sk_skb_verdict_fgs",

		false,
		true,
		"sk_skb_verdict",
		bpfLoadStateIdle(),

		-1,

		struct{}{},
	}

	ObserverSkSkbParser = bpfLoad{
		"bpf_skskb_parser.o",
		"sk_skb",
		"sk_skb",
		"sk_skb_parser/fgs",
		"sk_skb_parser_fgs",

		false,
		true,
		"sk_skb_parser",
		bpfLoadStateIdle(),

		-1,

		struct{}{},
	}

	ObserverTLSTCIngress = bpfLoad{
		"bpf_tc_ingress.o",
		"ingress_tcp",
		"ingress_tcp",
		"classifier/ingress_tcp",
		"classifier_ingress_tcp",

		false,
		true,
		"tc_ingress",
		bpfLoadStateIdle(),

		-1,

		struct{}{},
	}

	ObserverTLSTCEgress = bpfLoad{
		"bpf_tc_egress.o",
		"egress_tcp",
		"egress_tcp",
		"tc/egress_tcp",
		"tc_egress_tcp",

		false,
		true,
		"tc_egress",
		bpfLoadStateIdle(),

		-1,

		struct{}{},
	}

	observerTimeout = 5 * time.Minute
	execTimeout     = 5 * time.Minute
	pollTimeout     = 5000

	observerAllPrograms = []*bpfLoad{
		&ObserverExecve,
		&ObserverExit,
		&ObserverFork,
		&ObserverCred,
		&ObserverTCPConnect,
		&ObserverTCPConnectRet,
		&ObserverTCPClose,
		&ObserverListen,
		&ObserverSockopsEstablished,
		&ObserverSkmsg,
		&ObserverSkSkbVerdict,
		&ObserverSkSkbParser,
		&ObserverTLSTCEgress,
		&ObserverTLSTCIngress,
	}

	/* Event Ring map */
	ObserverTCPMonMap = ObserverMap{"tcpmon_map", "", &ObserverExecve, bpfLoadStateIdle()}
	/* Networking and Process Monitoring maps */
	ObserverExecveMap = ObserverMap{"execve_map", "", &ObserverExecve, bpfLoadStateIdle()}
	ObserverSocketMap = ObserverMap{"socket_map", "", &ObserverTCPConnect, bpfLoadStateIdle()}
	ObserverTcpMap    = ObserverMap{"ipv4_tcp_map", "", &ObserverTCPConnect, bpfLoadStateIdle()} // NB: This seems to be unused?
	/* TLS maps */
	ObserverTCTLSMap     = ObserverMap{"tls_map", "tc_ingress", &ObserverTLSTCEgress, bpfLoadStateIdle()}
	ObserverSockMap      = ObserverMap{"fgs_sock_map", "sockops", &ObserverSockopsEstablished, bpfLoadStateIdle()}
	ObserverTLSMap       = ObserverMap{"tls_map", "skmsg", &ObserverSkmsg, bpfLoadStateIdle()}
	ObserverTLSTailCalls = ObserverMap{"tls_calls", "tc_ingress", &ObserverTLSTCIngress, bpfLoadStateIdle()}
	/* Internal statistics for debugging */
	ObserverExecveStats = ObserverMap{"execve_map_stats", "", &ObserverExecve, bpfLoadStateIdle()}
	ObserverSocketStats = ObserverMap{"socket_map_stats", "", &ObserverExecve, bpfLoadStateIdle()}
	ObserverTlsStats    = ObserverMap{"tls_map_stats", "", &ObserverExecve, bpfLoadStateIdle()}
	/* Cilium maps */
	ObserverCiliumSnat = ObserverMap{"cilium_snat_v4_external", "", &ObserverTCPConnect, bpfLoadStateIdle()}

	observerAllMaps = []*ObserverMap{
		&ObserverSocketMap,
		&ObserverExecveMap,
		&ObserverTCPMonMap,
		&ObserverSockMap,
		&ObserverTLSMap,
		&ObserverTCTLSMap,
		&ObserverTLSTailCalls,
		&ObserverExecveStats,
		&ObserverSocketStats,
		&ObserverTlsStats,
		&ObserverCiliumSnat,
	}
)

func (k *ObserverKprobe) disableBpfLoad(bpf *bpfLoad) {

	bpf.loadState.setDisabled()
	for _, om := range observerAllMaps {
		if om.bpf == bpf {
			logger.GetLogger().Infof("disabling map %s", om.mapName)
			om.pinState.setDisabled()
		}
	}
}

func (k *ObserverKprobe) observerListenersTLS(msg *api.MsgTLSEventUnix) {
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

func (k *ObserverKprobe) observerListenersCred(msg *api.MsgCredEventUnix) {
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

func (k *ObserverKprobe) observerListenersTest(msg *api.MsgTestEventUnix) {
	for listener, _ := range k.listeners {
		if err := listener.Notify(msg); err != nil {
			k.log.Debug("Write failure removing Listener")
			k.RemoveListener(listener)
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

func msgToTLSEventUnix(m *api.MsgTLSEvent, certs []string, errCode uint32, errState api.MsgTLSParserState) *api.MsgTLSEventUnix {
	unix := &api.MsgTLSEventUnix{}

	unix.Common = m.Common
	unix.Tuple = m.Tuple
	unix.ClientHello = m.ClientHello
	unix.ServerHello = m.ServerHello
	unix.ProcessKey = m.ProcessKey

	if errCode > 0 {
		unix.ServerCert.Error = errCode
		unix.ServerCert.ParserState = errState
	} else {
		unix.ServerCert.Certificates = certs
	}
	return unix
}
func msgToExecveUnix(m *api.MsgExecveEvent, offset int) *api.MsgExecveEventUnix {
	unix := &api.MsgExecveEventUnix{}

	unix.Common = m.Common
	unix.Kube.NetNS = m.Kube.NetNS
	unix.Kube.Cid = m.Kube.Cid
	unix.Kube.Cgrpid = m.Kube.Cgrpid
	// The first byte is set to zero if there is no docker ID for this event.
	if m.Kube.Docker[0] != 0x00 {
		unix.Kube.Docker = strings.TrimFunc(string(m.Kube.Docker[offset:]), func(c rune) bool {
			return c == 0x00
		})
	}
	unix.Parent = m.Parent
	unix.Capabilities = m.Capabilities
	return unix
}

func msgToCredUnix(m *api.MsgCredEvent) *api.MsgCredEventUnix {
	return m
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

func msgToTestUnix(m *api.MsgTestEvent) *api.MsgTestEventUnix {
	return m
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
		k.handleTls(r)
	case api.MSG_OP_TLS_CONT:
		k.handleTlsCont(r)
	case api.MSG_OP_EXECVE:
		m := api.MsgExecveEvent{}
		err := binary.Read(r, binary.LittleEndian, &m)
		if err != nil {
			fmt.Printf("api.MSG_OP_EXECVE binary read failure: %s\n", err)
			break
		}
		msgUnix := msgToExecveUnix(&m, k.dockerIdOffsetWriter)
		msgUnix.Process, empty, err = execParse(r)
		if err != nil && empty {
			msgUnix.Process = nopMsgExecUnix()
		}
		k.observerListenersExecve(msgUnix)
	case api.MSG_OP_CRED:
		m := api.MsgCredEvent{}
		err := binary.Read(r, binary.LittleEndian, &m)
		if err != nil {
			fmt.Printf("api.MSG_OP_CRED binary read failure: %s\n", err)
			break
		}
		msgUnix := msgToCredUnix(&m)
		k.observerListenersCred(msgUnix)
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
		api.MSG_OP_IPV4_TCPCLOSE,
		api.MSG_OP_IPV4_BIND,
		api.MSG_OP_IPV4_LISTEN,
		api.MSG_OP_IPV4_ACCEPT:
		m := api.MsgIPv4Tcp{}
		err := binary.Read(r, binary.LittleEndian, &m)
		if err != nil {
			break
		}
		msgUnix := msgToTcpUnix(&m)
		k.observerListenersTcp(msgUnix)

	case api.MSG_OP_TEST:
		m := api.MsgTestEvent{}
		err := binary.Read(r, binary.LittleEndian, &m)
		if err != nil {
			break
		}
		msgUnix := msgToTestUnix(&m)
		k.observerListenersTest(msgUnix)

	case api.MSG_OP_KFREE_SKB:
		m := api.MsgKfreeSkb{}
		err := binary.Read(r, binary.LittleEndian, &m)
		if err != nil {
			k.log.WithError(err).Warnf("Failed to read kfree_skb msg")
			break
		}
		k.handleKfreeSkb(&m)

	case api.MSG_OP_GENERIC_KPROBE:
		k.handleGenericKprobe(r)

	case api.MSG_OP_GENERIC_TRACEPOINT:
		k.handleGenericTracepoint(r)

	default:
		k.log.Infof("unknown op ignored: %v \n", op)
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

func (k *ObserverKprobe) observerLoadSensorMaps(stopCtx context.Context, sensor *observerSensor, btf string) error {
	version, _, err := getKernelVersion()
	if err != nil {
		return err
	}

	for _, m := range sensor.maps {
		var err error

		if m.pinState.isDisabled() {
			k.log.Infof("hubble-fgs, map %s is disabled, skipping.\n", m.mapName)
			continue
		}

		pin := k.mapDir + m.mapName

		fd, err := bpf.LoadAndPinMaps(version, Verbosity, k.btfObj, m.bpf.Observer__program, pin, m.mapName,
			NameToProgType(m.bpf.probeType))
		k.log.Debugf("LoadAndPinMaps(%s, %s, %s)\n", m.bpf.Observer__program, pin, m.mapName)
		if err != nil {
			return fmt.Errorf("failed %d load map (%s): %s\n", fd, m.mapType, err)
		}
		k.log.Infof("hubble-fgs, map %s was loaded.\n", m.mapName)
	}

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
		k.btfObj,
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
			k.btfObj,
			load.Observer__program,
			attach,
			load.observer__label,
			k.bpfDir+load.observer__prog,
			k.mapDir)
	} else if load.probeType == "sockops" {
		return bpf.LoadSockopsProgram(
			version, Verbosity,
			k.btfObj,
			load.Observer__program,
			load.observer__label,
			k.bpfDir+load.observer__prog,
			k.mapDir)
	} else if load.probeType == "skmsg" {
		return bpf.LoadSkmsgProgram(
			version, Verbosity,
			k.btfObj,
			load.Observer__program,
			load.observer__label,
			k.bpfDir+load.observer__prog,
			k.mapDir)
	} else if load.probeType == "sk_skb_verdict" {
		return bpf.LoadSkSkbVerdictProgram(
			version, Verbosity,
			k.btfObj,
			load.Observer__program,
			load.observer__label,
			k.bpfDir+load.observer__prog,
			k.mapDir)
	} else if load.probeType == "sk_skb_parser" {
		return bpf.LoadSkSkbParserProgram(
			version, Verbosity,
			k.btfObj,
			load.Observer__program,
			load.observer__label,
			k.bpfDir+load.observer__prog,
			k.mapDir)
	} else if load.probeType == "cgrp_ingress" {
		return bpf.LoadCgroupProgram(
			version, Verbosity,
			k.btfObj,
			load.Observer__program,
			load.observer__label,
			k.bpfDir+load.observer__prog,
			k.mapDir)
	} else if load.probeType == "tc_ingress" || load.probeType == "tc_egress" {
		return k.observerLoadTC(load, version, Verbosity, btf)
	} else if load.probeType == "generic_kprobe" {
		return k.loadGenericKprobeSensor(load, version, Verbosity)
	} else if load.probeType == "generic_tracepoint" {
		return k.loadGenericTracepointSensor(load, btf, version, Verbosity, x64)
	} else {
		return bpf.LoadKprobeProgram(
			version, Verbosity,
			k.btfObj,
			load.Observer__program,
			attach,
			load.observer__label,
			k.bpfDir+load.observer__prog,
			k.mapDir,
			load.retProbe)
	}
}

func (k *ObserverKprobe) observerLoadInstance(load *bpfLoad, stopCtx context.Context) error {
	var fd int

	version, _, err := getKernelVersion()
	if err != nil {
		return err
	}

	k.log.Debugf("prog %s kern_version %d\n", load.Observer__program, version)
	if load.probeType == "tracepoint" {
		err, fd = k.loadInstance(load, version, Verbosity, ObserverBTF, true)
		if err != nil && fd == -17 { // tracepoint exists be unfriendly and delete it
			k.log.Infof("Tracepoint %s exists: removing and retrying", load.Observer__program)
			removeTracepoint(load.tracefd)
			err, fd = k.loadInstance(load, version, Verbosity, ObserverBTF, true)
		}
		if err != nil {
			return fmt.Errorf("Failed prog %s kern_version %d err %d LoadTracingProgram: %s\n",
				load.Observer__program, version, fd, err)
		}
	} else {
		err, fd = k.loadInstance(load, version, Verbosity, ObserverBTF, true)
		if err != nil {
			/* If we fail attach with __x64_sys_execve variant try again with
			 * sys_execve variant.
			 */
			err, fd = k.loadInstance(load, version, Verbosity, ObserverBTF, false)
			if err != nil && load.errorFatal {
				return fmt.Errorf("Failed prog %s kern_version %d LoadKprobeProgram: %s\n",
					load.Observer__program, version, err)
			}
		}
	}
	load.tracefd = fd
	return nil
}

func (k *ObserverKprobe) observerUnloadSensor(sensor *observerSensor, ctx context.Context) error {
	k.log.Infof("Unloading sensor %s", sensor.name)
	if !sensor.loaded {
		k.log.Warningf("attempted to unload sensor %s which is not loaded", sensor.name)
		return fmt.Errorf("unload of sensor %s failed: sensor not loaded", sensor.name)
	}

	for _, p := range sensor.progs {
		k.removeProgram(p)
	}

	for _, m := range sensor.maps {
		os.Remove(k.mapDir + m.mapName)
	}

	sensor.loaded = false
	return nil
}

func (k *ObserverKprobe) observerLoadSensor(stopCtx context.Context, sensor *observerSensor) error {
	if sensor == nil {
		return nil
	}

	k.log.Infof("Loading sensor %s", sensor.name)
	if sensor.loaded {
		k.log.Warningf("attempted to load sensor %s which is already loaded", sensor.name)
		return fmt.Errorf("loading sensor %s failed: sensor already loaded", sensor.name)
	}

	_, verStr, _ := getKernelVersion()
	k.log.Infof("Loading kernel version %s", verStr)

	if err := k.observerLoadSensorMaps(stopCtx, sensor, ObserverBTF); err != nil {
		return err
	}

	for _, p := range sensor.progs {
		if p.loadState.isDisabled() {
			k.log.Infof("hubble-fgs, prog %s is disabled, skipping.\n", p.Observer__program)
			continue
		}

		if err := k.observerLoadInstance(p, stopCtx); err != nil {
			return err
		}
		p.loadState.setLoaded()
		k.log.Infof("hubble-fgs, prog %s was loaded.\n", p.Observer__program)
	}
	k.log.Infof("hubble-fgs, loaded BPF maps and events for sensor %s successfully.\n", sensor.name)
	sensor.loaded = true
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
			k.log.WithError(err).Debug("kprobe events poll failed")
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

func prependPath(s string, b []byte) []byte {
	split := strings.Split(string(b), "\u0000")
	split[0] = s
	fullCmd := strings.Join(split[0:], "\u0000")
	return []byte(fullCmd)
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

type MsgTLSEventCert struct {
	tls    *api.MsgTLSEvent
	cert   []byte
	header uint32
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
	/* see ObserverSync description */
	ObserverSync

	/* Kernel symbols */
	ksyms *ksyms.Ksyms

	/* Runtime docker Id info */
	dockerIdOffsetWriter int

	/* Runtime Containers */
	tlsInProgress map[api.MsgTLSIPv4]*MsgTLSEventCert

	/* opaque pointer to C BTF object */
	btfObj uintptr

	/* YAML Configuration File */
	configFile string

	/* enable CRD */
	enableCRD bool
}

// ObseverSync holds data that are safe to be used in all goroutine contexts.
//
// The ObserverKprobe structure contains internal data that are used in the
// goroutine that executes Start(). Start()  polls for events, process them,
// and forwards them to the registered listeners. The internal data of
// ObserverKprobe are accessed without synchronization and so they must not be
// used by other goroutines.
//
// ObserverSync holds the parts that are safe to be used from other
// goroutines.
type ObserverSync struct {
	/* sensors controller: loading/unloading sensors */
	sensorCtlHandle
	/* stacktrace tree manager: managing stacktrace trees */
	sttManagerHandle
}

func defaultFilter(msg *api.MsgIPv4TcpEventUnix) bool {
	return true
}

// createInitialObserverSensor retruns the observerSensor that is loaded at initialization time
func (k *ObserverKprobe) createInitialObserverSensor() *observerSensor {
	progs := []*bpfLoad{
		&ObserverExecve,
		&ObserverExit,
		&ObserverFork,
		&ObserverCred,
		&ObserverTCPConnect,
		&ObserverTCPConnectRet,
		&ObserverTCPClose,
		&ObserverListen,
	}

	maps := []*ObserverMap{
		&ObserverTCPMonMap,
		&ObserverExecveMap,
		&ObserverSocketMap,
		/* &ObserverTcpMap */
		&ObserverExecveStats,
		&ObserverSocketStats,
		&ObserverTlsStats, // NB: Maybe this should be under k.enableTLS?
	}

	if k.enableTLS {
		progs = append(progs,
			&ObserverSockopsEstablished,
			&ObserverSkmsg,
			&ObserverSkSkbVerdict,
			&ObserverSkSkbParser,
		)

		maps = append(maps,
			&ObserverSockMap,
			&ObserverTLSMap,
		)
	}

	if k.enableTLSTC {
		progs = append(progs,
			&ObserverTLSTCEgress,
			&ObserverTLSTCIngress,
		)

		maps = append(maps,
			&ObserverTCTLSMap,
			&ObserverTLSTailCalls,
		)
	}

	if false {
		maps = append(maps,
			&ObserverCiliumSnat,
		)
	}

	return &observerSensor{
		name:  "__main__",
		progs: progs,
		maps:  maps,
	}
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
	for _, p := range observerAllPrograms {
		if _, err := os.Stat(p.Observer__program); err == nil {
			continue
		}
		logger.GetLogger().WithField("file", p.Observer__program).Info("candidate bpf file does not exist")
		last := strings.Split(p.Observer__program, "/")
		filename := last[len(last)-1]

		path := path.Join(HubbleLib, filename)
		if _, err := os.Stat(path); err == nil {
			p.Observer__program = path
			continue
		}
		logger.GetLogger().WithField("file", path).Info("candidate bpf file does not exist")

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

		// Alternative to auto-discovery and/or command line argument we
		// can also set via environment variable.
		fgsBtfEnv := os.Getenv("FGS_BTF")
		if fgsBtfEnv != "" {
			if _, err := os.Stat(fgsBtfEnv); err != nil {
				return err
			}
			ObserverBTF = fgsBtfEnv
			return nil
		}

		err := unix.Uname(&uname)
		if err != nil {
			return fmt.Errorf("Kernel version lookup (uname -r) failing. Use '--kernel' to set manually: %s\n", err)
		}
		n := bytes.IndexByte(uname.Release[:], 0)
		runFile := path.Join(HubbleLib, "metadata", "vmlinux-"+string(uname.Release[:n]))
		if _, err := os.Stat(runFile); err == nil {
			ObserverBTF = runFile
			return nil
		}
		logger.GetLogger().WithField("file", runFile).Info("candidate btf file does not exist")

		runFile = path.Join(HubbleLib, "btf")
		if _, err := os.Stat(runFile); err == nil {
			ObserverBTF = runFile
			return nil
		}
		logger.GetLogger().WithField("file", runFile).Info("candidate btf file does not exist")

		runFile = path.Join("/sys", "kernel", "btf", "vmlinux")
		if _, err := os.Stat(runFile); err == nil {
			ObserverBTF = runFile
			return nil
		}
		logger.GetLogger().WithField("file", runFile).Info("candidate btf file does not exist")

		return fmt.Errorf("Kernel version '%s' BTF search failed kernel is not included in supported list. Use --btf option to specify BTF path and/or '--kernel' to specify kernel version.", uname.Release[:n])
	} else {
		if err := btfFileExists(ObserverBTF); err != nil {
			return fmt.Errorf("User specified BTF does not exist. %s\n", err)
		}
	}
	return nil
}

func (k *ObserverKprobe) createBTFKprobe() {
	k.btfObj = bpf.GetBTF(ObserverBTF)
}

func (k *ObserverKprobe) getBTFKprobe() uintptr {
	return k.btfObj
}

func (k *ObserverKprobe) ConfigureBTF(ctx context.Context) error {
	// Find BTF metdaata and populate btf opaqu object
	if err := k.observerFindBTF(ctx); err != nil {
		return fmt.Errorf("hubble-fgs, Aborting kernel autodiscovery failed. %s\n", err)
	}
	k.createBTFKprobe()
	return nil
}

func (k *ObserverKprobe) Start(ctx context.Context) error {
	k.createDir()

	// initialize kernel symbol lookup
	ksyms, err := ksyms.NewKsyms(ProcFS)
	if err == nil {
		k.ksyms = ksyms
	} else {
		k.log.Warningf("failed to initialize ksyms: %s", err)
	}

	logger.GetLogger().WithField("metadata", ObserverBTF).Info("Using metadata file")
	if err := k.observerFindProgs(ctx); err != nil {
		return fmt.Errorf("hubble-fgs, Aborting could not find BPF programs. %s\n", err)
	}
	if _, err := k.observerMinReqs(ctx); err != nil {
		return fmt.Errorf("hubble-fgs, Aborting minimum requirements not met. %s\n", err)
	}

	// This is technically not a sensor since we are loading this
	// statically when we start, but it allows us to have a single path for
	// loading bpf programs.
	initialSensor := k.createInitialObserverSensor()
	if err := k.observerLoadSensor(ctx, initialSensor); err != nil {
		return fmt.Errorf("hubble-fgs, Aborting could not load BPF programs. %s\n", err)
	}

	k.initKprobeSensors()

	// Load initial set of generic kprobe sensors */
	if k.configFile != "" {
		genericSensor, err := k.getSensorFromTracingPolicyFname(k.configFile)
		if err != nil {
			return fmt.Errorf("hubble-fgs, failed to initialize generic sensors. %w\n", err)
		}
		if err := k.observerLoadSensor(ctx, genericSensor); err != nil {
			return fmt.Errorf("hubble-fgs, Aborting could not load initial kprobe sensors. %s\n", err)
		}
	}

	// start sensor controller and stt manager
	k.startSensorCtl()
	k.ObserverSync.sttManagerHandle = startSttManager()

	// start CRD watcher
	if k.enableCRD {
		go k.watchTracePolicy()
	}

	k.startUpdateMapMetrics()
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

func (k *ObserverKprobe) removeProgram(prog *bpfLoad) {
	os.Remove(k.bpfDir + prog.observer__prog)
	if prog.probeType == "generic_kprobe" {
		os.Remove(k.bpfDir + prog.observer__prog + "_0")
		os.Remove(k.bpfDir + prog.observer__prog + "_1")
		os.Remove(k.bpfDir + "kprobe_calls")
	}
	if prog.tracefd >= 0 {
		removeTracepoint(prog.tracefd)
		prog.tracefd = -1
	}
}

func (k *ObserverKprobe) RemovePrograms() {
	for _, l := range observerAllPrograms {
		k.removeProgram(l)
	}

	for _, m := range observerAllMaps {
		os.Remove(k.mapDir + m.mapName)
	}
	os.Remove(k.bpfDir)
	os.Remove(k.mapDir)
	if k.btfObj != 0 {
		bpf.FreeBTF(k.btfObj)
		k.btfObj = 0
	}
}

func NewObserverKprobe(bpfDir, mapDir, ciliumDir, interfaces, configFile string, genericTracepoints []GenericTracepointConf,
	tls, tlstc, pretty, crd bool) *ObserverKprobe {
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
		tlsInProgress: make(map[api.MsgTLSIPv4]*MsgTLSEventCert),
		configFile:    configFile,
		enableCRD:     crd,
	}
}

func (k *ObserverKprobe) PrintStats() {
	k.log.Infof("Observer Stats: errors %d lost %d recvd %d filterPass %d filterDrop %d",
		k.errorCntr, k.lostCntr, k.recvCntr, k.filterPass, k.filterDrop)
}

func (k *ObserverKprobe) AttachFilter(f *MsgFilter) {
	k.msgFilter = append(k.msgFilter, f)
}

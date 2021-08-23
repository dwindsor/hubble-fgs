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
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/isovalent/hubble-fgs/pkg/api"
	"github.com/isovalent/hubble-fgs/pkg/bpf"
	"github.com/isovalent/hubble-fgs/pkg/ksyms"
	"github.com/isovalent/hubble-fgs/pkg/logger"
	"github.com/sirupsen/logrus"
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

type ObserverMap struct {
	mapName  string
	mapType  string
	bpf      *BpfLoad
	pinState bpfLoadState
	fd       int
}

var (
	ProcFS        = "/proc/"
	KernelVersion = ""
	SetPidMax     = false

	HubbleLib          string
	ObserverBTF        string
	Verbosity          int
	IgnoreMissingProgs bool

	observerTimeout = 5 * time.Minute
	execTimeout     = 5 * time.Minute
	pollTimeout     = 5000

	eventHandler = make(map[uint8]func(r *bytes.Reader) (interface{}, error))
)

func RegisterEventHandlerAtInit(ev uint8, handler func(r *bytes.Reader) (interface{}, error)) {
	eventHandler[ev] = handler
}

func (k *ObserverKprobe) observerListeners(msg interface{}) {
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
	unix.SockCookie = m.SockCookie
	unix.SocketStats = m.SocketStats

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
		k.observerListeners(msgUnix)
	case api.MSG_OP_CRED:
		m := api.MsgCredEvent{}
		err := binary.Read(r, binary.LittleEndian, &m)
		if err != nil {
			fmt.Printf("api.MSG_OP_CRED binary read failure: %s\n", err)
			break
		}
		msgUnix := msgToCredUnix(&m)
		k.observerListeners(msgUnix)
	case api.MSG_OP_EXIT:
		m := api.MsgExitEvent{}
		err := binary.Read(r, binary.LittleEndian, &m)
		if err != nil {
			fmt.Printf("api.MSG_OP_EXIT binary read failure: %s\n", err)
			break
		}
		msgUnix := msgToExitUnix(&m)
		k.observerListeners(msgUnix)
	case api.MSG_OP_IPV4_TCPCONNECT,
		api.MSG_OP_IPV4_TCPCONNECTRET,
		api.MSG_OP_IPV4_TCPCLOSE,
		api.MSG_OP_IPV4_BIND,
		api.MSG_OP_IPV4_LISTEN,
		api.MSG_OP_IPV4_ACCEPT,
		api.MSG_OP_IPV4_TCPSTATS:
		m := api.MsgIPv4Tcp{}
		err := binary.Read(r, binary.LittleEndian, &m)
		if err != nil {
			break
		}
		msgUnix := msgToTcpUnix(&m)
		k.observerListeners(msgUnix)

	case api.MSG_OP_TEST:
		m := api.MsgTestEvent{}
		err := binary.Read(r, binary.LittleEndian, &m)
		if err != nil {
			break
		}
		msgUnix := msgToTestUnix(&m)
		k.observerListeners(msgUnix)

	case api.MSG_OP_KFREE_SKB:
		m := api.MsgKfreeSkb{}
		err := binary.Read(r, binary.LittleEndian, &m)
		if err != nil {
			k.log.WithError(err).Warnf("Failed to read kfree_skb msg")
			break
		}
		k.handleKfreeSkb(&m)

	default:
		if h, ok := eventHandler[op]; ok {
			if unix, err := h(r); err == nil && unix != nil {
				k.observerListeners(unix)
			}
		} else {
			k.log.Infof("unknown op ignored: %v", op)
		}
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

func (k *ObserverKprobe) __runEvents(stopCtx context.Context) (*bpf.PerCpuEvents, error) {
	e, err := bpf.NewPerCpuEvents(k.perfConfig, k.log)
	if err != nil {
		return nil, fmt.Errorf("failed kprobe events NewPerCpuEvents: %w", err)
	}
	return e, nil
}

func (k *ObserverKprobe) __loopEvents(stopCtx context.Context, e *bpf.PerCpuEvents) error {
	receiveEvent := k.receiveEvent
	observerLost := k.observerLost
	observerError := k.observerError

	k.log.Info("Listening for events...")
	k.observerListeners(&api.MsgFGSReady{})

	for !isCtxDone(stopCtx) {
		todo, err := e.Poll(pollTimeout)
		switch {
		case isCtxDone(stopCtx):
			k.log.Debug("Context cancelled inside __loopEvents")
			return nil

		case err == syscall.EBADF:
			return fmt.Errorf("kprobe events syscall.EBADF: %w", err)

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
	/* Statistics */
	lostCntr   int
	errorCntr  int
	recvCntr   int
	filterPass int
	filterDrop int
	/* Filters */
	msgFilter []*MsgFilter
	log       logrus.FieldLogger

	/* Kernel symbols */
	ksyms *ksyms.Ksyms

	/* Runtime docker Id info */
	dockerIdOffsetWriter int

	/* YAML Configuration File */
	configFile string

	/* enable CRD */
	enableCRD bool

	/* Sensor Controller */
	ObserverSync *ObserverSync

	/* Sock Statistic */
	tcpStatSegRate uint32
}

func defaultFilter(msg *api.MsgIPv4TcpEventUnix) bool {
	return true
}

func (k *ObserverKprobe) Start(ctx context.Context) error {
	// initialize kernel symbol lookup
	ksyms, err := ksyms.NewKsyms(ProcFS)
	if err == nil {
		k.ksyms = ksyms
	} else {
		k.log.Warningf("failed to initialize ksyms: %s", err)
	}

	if err := LoadDefaultSensor(k.bpfDir, k.mapDir, k.ciliumDir, k.configFile, ctx); err != nil {
		return err
	}

	// start sensor controller and stt manager
	k.ObserverSync, err = StartSensorCtl(k.bpfDir, k.mapDir, k.ciliumDir)
	if err != nil {
		return err
	}

	// start CRD watcher
	if k.enableCRD {
		go watchTracePolicy(k.ObserverSync, ctx)
	}

	k.startUpdateMapMetrics()
	if err := k.configureSockStatSampler(k.tcpStatSegRate); err != nil {
		return fmt.Errorf("hubble-fgs, aborting sample config error: %w", err)
	}
	k.populateExecve(ctx)
	k.perfConfig = bpf.DefaultPerfEventConfig()
	if err := k.runEvents(ctx); err != nil {
		return fmt.Errorf("hubble-fgs, aborting runtime error: %w", err)
	}
	return nil
}

func NewObserverKprobe(bpfDir, mapDir, ciliumDir, interfaces, configFile string,
	tls, tlstc, pretty, crd bool, tcpStatRate uint32) *ObserverKprobe {
	return &ObserverKprobe{
		bpfDir:         bpfDir,
		mapDir:         mapDir,
		ciliumDir:      ciliumDir,
		interfaces:     interfaces,
		prettyPrinter:  pretty,
		listeners:      make(map[Listener]struct{}),
		log:            logger.GetLogger(),
		configFile:     configFile,
		enableCRD:      crd,
		tcpStatSegRate: tcpStatRate,
	}
}

func (k *ObserverKprobe) PrintStats() {
	k.log.Infof("Observer Stats: errors %d lost %d recvd %d filterPass %d filterDrop %d",
		k.errorCntr, k.lostCntr, k.recvCntr, k.filterPass, k.filterDrop)
}

func (k *ObserverKprobe) AttachFilter(f *MsgFilter) {
	k.msgFilter = append(k.msgFilter, f)
}

func (k *ObserverKprobe) RemovePrograms() {
	RemovePrograms(k.bpfDir, k.mapDir)
}

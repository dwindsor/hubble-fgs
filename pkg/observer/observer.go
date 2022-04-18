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
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/isovalent/hubble-fgs/pkg/api"
	"github.com/isovalent/hubble-fgs/pkg/bpf"
	"github.com/isovalent/hubble-fgs/pkg/ksyms"
	"github.com/isovalent/hubble-fgs/pkg/logger"
	"github.com/isovalent/hubble-fgs/pkg/metrics"
	"github.com/isovalent/hubble-fgs/pkg/option"
	"github.com/isovalent/hubble-fgs/pkg/reader"
	"github.com/isovalent/hubble-fgs/pkg/sensors"

	"github.com/sirupsen/logrus"
)

const (
	nanoPerSeconds = 1000000000

	TCP_PROC_STATE_LISTEN = 10

	maxMapRetries = 4
	mapRetryDelay = 1

	// Max events to read from each ring in one go. This is used to
	// reduce the likelihood of events being out of order and the
	// limit is required for HTTP/2 parsing to function correctly
	// which relies on frame ordering (it does limited reordering)
	maxEventsPerRing = 4

	perCPUBufferBytes = 65535

	// Use cilium/ebpf to read events from the perf ring. Since we're
	// incrementally rolling this out we're keeping the old code functional
	// in case we need to quickly roll back.
	useCiliumEbpfReader = true
)

var (
	pollTimeout = 5 * time.Second

	eventHandler = make(map[uint8]func(r *bytes.Reader) ([]Event, error))

	observerList []*Observer
)

type Event interface{}

func RegisterEventHandlerAtInit(ev uint8, handler func(r *bytes.Reader) ([]Event, error)) {
	eventHandler[ev] = handler
}

func (k *Observer) observerListeners(msg interface{}) {
	for listener := range k.listeners {
		if err := listener.Notify(msg); err != nil {
			k.log.Debug("Write failure removing Listener")
			k.RemoveListener(listener)
		}
	}
}

func AllListeners(msg interface{}) {
	for _, o := range observerList {
		o.observerListeners(msg)
	}
}

func (k *Observer) AddListener(listener Listener) {
	k.log.WithField("listener", listener).Debug("Add listener")
	k.listeners[listener] = struct{}{}
	k.getRunningProcs(false, true)
}

func (k *Observer) RemoveListener(listener Listener) {
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
		// We always get a null terminated buffer from bpf
		cgroup := reader.FromCString(m.Kube.Docker[:api.DOCKER_ID_LENGTH])
		unix.Kube.Docker, _ = lookupContainerId(cgroup, true, false)
	}
	unix.Parent = m.Parent
	unix.Capabilities = m.Capabilities

	unix.Namespaces.UtsInum = m.Namespaces.UtsInum
	unix.Namespaces.IpcInum = m.Namespaces.IpcInum
	unix.Namespaces.MntInum = m.Namespaces.MntInum
	unix.Namespaces.PidInum = m.Namespaces.PidInum
	unix.Namespaces.PidChildInum = m.Namespaces.PidChildInum
	unix.Namespaces.NetInum = m.Namespaces.NetInum
	unix.Namespaces.TimeInum = m.Namespaces.TimeInum
	unix.Namespaces.TimeChildInum = m.Namespaces.TimeChildInum
	unix.Namespaces.CgroupInum = m.Namespaces.CgroupInum
	unix.Namespaces.UserInum = m.Namespaces.UserInum

	return unix
}

func msgToCredUnix(m *api.MsgCredEvent) *api.MsgCredEventUnix {
	return m
}

func msgToExitUnix(m *api.MsgExitEvent) *api.MsgExitEventUnix {
	return m
}

func MsgToSocketStatsUnix(m *api.MsgSocketStats) api.MsgSocketStatsUnix {
	return api.MsgSocketStatsUnix{
		BytesSubmitted:  0,
		BytesSent:       m.BytesSent,
		BytesConsumed:   0,
		BytesReceived:   m.BytesReceived,
		ConsumedSegs:    0,
		SegsIn:          m.SegsIn,
		SubmittedSegs:   0,
		SegsOut:         m.SegsOut,
		SRtt:            m.SRtt,
		RetransmitSegs:  m.RetransmitSegs,
		RetransmitBytes: m.RetransmitBytes,
		ToZeroWindow:    m.ToZeroWindow,
		SkDrop:          m.SkDrop,
	}
}

func MsgToIPv4Unix(m *api.MsgIPv4Event) *api.MsgIPv4EventUnix {
	unix := &api.MsgIPv4EventUnix{}

	unix.Common = m.Common
	unix.Tuple = m.Tuple
	unix.Return = m.Return
	unix.ProcessKey = m.ProcessKey
	unix.SockCookie = m.SockCookie
	unix.SocketStats = MsgToSocketStatsUnix(&m.SocketStats)
	unix.SocketFlags = m.SocketFlags
	// no need to copy the pad here
	if enableDns {
		unix.SocketFlags |= api.SOCKFLAGS_TYPE_DNSREADY
	}
	return unix
}

func msgToTestUnix(m *api.MsgTestEvent) *api.MsgTestEventUnix {
	return m
}

func nopMsgProcess() api.MsgProcess {
	return api.MsgProcess{
		Filename: "<enomem>",
		Args:     "<enomem>",
	}
}

func execParse(reader *bytes.Reader) (api.MsgProcess, bool, error) {
	proc := api.MsgProcess{}
	exec := api.MsgExec{}

	if err := binary.Read(reader, binary.LittleEndian, &exec); err != nil {
		fmt.Printf("read error!\n")
		return proc, true, err
	}

	proc.Size = exec.Size
	proc.PID = exec.PID
	proc.NSPID = exec.NSPID
	proc.UID = exec.UID
	proc.Flags = exec.Flags
	proc.Ktime = exec.Ktime
	proc.AUID = exec.AUID

	size := exec.Size - api.MSG_SIZEOF_EXECVE
	if size > api.MSG_SIZEOF_BUFFER-api.MSG_SIZEOF_EXECVE {
		err := fmt.Errorf("msg exec size larger than argsbuffer")
		exec.Size = api.MSG_SIZEOF_EXECVE
		proc.Args = "enomem enomem"
		proc.Filename = "enomem"
		return proc, false, err
	}

	args := make([]byte, size) //+2)
	if err := binary.Read(reader, binary.LittleEndian, &args); err != nil {
		proc.Size = api.MSG_SIZEOF_EXECVE
		proc.Args = "enomem enomem"
		proc.Filename = "enomem"
		return proc, false, err
	}

	cmdArgs := bytes.Split(args, []byte{0x00})
	proc.Filename = string(cmdArgs[0])
	proc.Args = string(bytes.Join(cmdArgs[1:], []byte{0x00}))

	return proc, false, nil
}

var (
	enableDns = false
)

func EnableDns() {
	enableDns = true
}

func (k *Observer) receiveEvent(data []byte, cpu int) {
	var op = data[0]
	var empty bool

	k.recvCntr++
	r := bytes.NewReader(data)

	// Increment the counter for the msg opcode
	metrics.MsgOpsCount.WithLabelValues(api.OpCode(op).String()).Add(1)

	// TODO: Most of these ops can be converted into sensors. Ideally, this
	// switch case shouldn't even exist; it should just do what's already
	// happening inside the default case.

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
			msgUnix.Process = nopMsgProcess()
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
	case api.MSG_OP_IPV4_UDPSTATS:
		m := api.MsgIPv4Event{}
		err := binary.Read(r, binary.LittleEndian, &m)
		if err != nil {
			break
		}
		msgUnix := MsgToIPv4Unix(&m)
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
		// These ops handlers are registered by RegisterEventHandlerAtInit().
		if h, ok := eventHandler[op]; ok {
			if events, err := h(r); err == nil {
				for _, event := range events {
					k.observerListeners(event)
				}
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

	cwd, err := os.Readlink(filepath.Join(option.Config.ProcFS, pidstr, "cwd"))
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

func (k *Observer) observerLost(msg *bpf.PerfEventLost, cpu int) {
	k.lostCntr++
}

func (k *Observer) observerError(msg *bpf.PerfEvent) {
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

func (k *Observer) __runEvents(stopCtx context.Context) (*bpf.PerCpuEvents, error) {
	e, err := bpf.NewPerCpuEvents(k.perfConfig, k.log)
	if err != nil {
		return nil, fmt.Errorf("failed kprobe events NewPerCpuEvents: %w", err)
	}
	return e, nil
}

func (k *Observer) __loopEvents(stopCtx context.Context, e *bpf.PerCpuEvents) error {
	receiveEvent := func(msg *bpf.PerfEventSample, cpu int) { k.receiveEvent(msg.DataDirect(), cpu) }
	observerLost := k.observerLost
	observerError := k.observerError
	pollTimeoutMsec := int(pollTimeout / time.Millisecond)

	k.log.Info("Listening for events...")
	k.observerListeners(&api.MsgFGSReady{})

	for !isCtxDone(stopCtx) {
		_, err := e.Poll(pollTimeoutMsec)
		switch {
		case isCtxDone(stopCtx):
			k.log.Debug("Context cancelled inside __loopEvents")
			return nil

		case errors.Is(err, syscall.EBADF):
			return fmt.Errorf("kprobe events syscall.EBADF: %w", err)

		case err != nil:
			k.log.WithError(err).Debug("kprobe events poll failed")
			continue
		}

		if err := e.ReadAll(maxEventsPerRing, receiveEvent, observerLost, observerError); err != nil {
			k.log.WithError(err).Warn("kprobe events read failed")
		}

		metrics.RingBufPerfEventReceived.WithLabelValues().Set(float64(k.recvCntr))
		metrics.RingBufPerfEventLost.WithLabelValues().Set(float64(k.lostCntr))
		metrics.RingBufPerfEventErrors.WithLabelValues().Set(float64(k.errorCntr))
	}
	return nil
}

func (k *Observer) runEvents(stopCtx context.Context) error {
	e, err := k.__runEvents(stopCtx)
	if err != nil {
		return err
	}
	defer e.CloseAll()
	k.__loopEvents(stopCtx, e)
	return nil
}

func (k *Observer) runEventsNew(stopCtx context.Context, ready func()) error {
	pinOpts := ebpf.LoadPinOptions{}

	perfMap, err := ebpf.LoadPinnedMap(k.perfConfig.MapName, &pinOpts)
	if err != nil {
		return fmt.Errorf("opening pinned map '%s' failed: %w", k.perfConfig.MapName, err)
	}
	defer perfMap.Close()

	perfReader, err := perf.NewReader(perfMap, perCPUBufferBytes)
	if err != nil {
		return fmt.Errorf("creating perf array reader failed: %w", err)
	}

	// Inform caller that we're about to start processing events.
	k.observerListeners(&api.MsgFGSReady{})
	ready()

	// Listeners are ready and about to start reading from perf reader, tell
	// user everything is ready.
	k.log.Info("Listening for events...")

	// Start reading records from the perf array. Reads until the reader is closed.
	var wg sync.WaitGroup
	wg.Add(1)
	defer wg.Wait()
	go func() {
		defer wg.Done()
		for stopCtx.Err() == nil {
			record, err := perfReader.Read()
			if err != nil {
				// NOTE(JM): Keeping the old behaviour for now and just counting the errors without stopping
				if stopCtx.Err() == nil {
					k.errorCntr++
					metrics.RingBufPerfEventErrors.WithLabelValues().Set(float64(k.errorCntr))
					k.log.WithError(err).Warn("kprobe events read failed")
				}
			} else {
				if len(record.RawSample) > 0 {
					k.receiveEvent(record.RawSample, record.CPU)
					metrics.RingBufPerfEventReceived.WithLabelValues().Set(float64(k.recvCntr))
				}

				if record.LostSamples > 0 {
					k.lostCntr += int(record.LostSamples)
					metrics.RingBufPerfEventLost.WithLabelValues().Set(float64(k.lostCntr))
				}
			}
		}
	}()

	// Wait for context to be cancelled and then stop.
	<-stopCtx.Done()
	return perfReader.Close()
}

func prependPath(s string, b []byte) []byte {
	split := strings.Split(string(b), "\u0000")
	split[0] = s
	fullCmd := strings.Join(split[0:], "\u0000")
	return []byte(fullCmd)
}

func (k *Observer) populateExecve(ctx context.Context) {
	k.getRunningProcs(true, false)
}

type MsgFilterRun func(*api.MsgIPv4EventUnix, *Observer) bool

type MsgFilter struct {
}

// Observer represents the link between the BPF perf ring and the listeners. It
// manages the perf ring and receive events from it. It ensures that the BPF
// event we are receiving from the kernel is complete. The listeners are
// notified of their corresponding events.
type Observer struct {
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

	/* Sock Statistic */
	tcpStatSegRate uint32

	/* SensorManager handles dynamic sensors loading / unloading. */
	SensorManager *sensors.Manager
}

func (k *Observer) Start(ctx context.Context) error {
	// initialize kernel symbol lookup
	ksyms, err := ksyms.NewKsyms(option.Config.ProcFS)
	if err == nil {
		k.ksyms = ksyms
	} else {
		k.log.Warningf("failed to initialize ksyms: %s", err)
	}

	if err := sensors.LoadDefault(ctx, k.bpfDir, k.mapDir, k.ciliumDir, k.configFile); err != nil {
		return err
	}

	k.startUpdateMapMetrics()
	k.populateExecve(ctx)

	if err := sensors.LoadConfig(ctx, k.bpfDir, k.mapDir, k.ciliumDir, k.configFile); err != nil {
		return err
	}

	if k.SensorManager == nil {
		if err := k.InitSensorManager(); err != nil {
			return err
		}
	}

	// start CRD watcher
	if k.enableCRD {
		go watchTracePolicy(ctx, k.SensorManager)
	}

	k.perfConfig = bpf.DefaultPerfEventConfig()
	if useCiliumEbpfReader {
		err = k.runEventsNew(ctx, func() {})
	} else {
		err = k.runEvents(ctx)
	}
	if err != nil {
		return fmt.Errorf("hubble-fgs, aborting runtime error: %w", err)
	}
	return nil
}

// InitSensorManager starts the sensor controller and stt manager.
func (k *Observer) InitSensorManager() error {
	var err error
	k.SensorManager, err = sensors.StartSensorManager(k.bpfDir, k.mapDir, k.ciliumDir)
	return err
}

func NewObserver(bpfDir, mapDir, ciliumDir, interfaces, configFile string,
	pretty, crd bool, tcpStatRate uint32) *Observer {
	o := &Observer{
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
	observerList = append(observerList, o)
	return o
}

func (k *Observer) PrintStats() {
	k.log.Infof("Observer Stats: errors %d lost %d recvd %d filterPass %d filterDrop %d",
		k.errorCntr, k.lostCntr, k.recvCntr, k.filterPass, k.filterDrop)
}

func (k *Observer) AttachFilter(f *MsgFilter) {
	k.msgFilter = append(k.msgFilter, f)
}

func (k *Observer) RemovePrograms() {
	RemovePrograms(k.bpfDir, k.mapDir)
}

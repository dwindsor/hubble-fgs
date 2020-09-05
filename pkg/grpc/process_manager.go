package grpc

import (
	"encoding/base64"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	v1 "github.com/cilium/hubble/pkg/api/v1"
	"github.com/cilium/hubble/pkg/cilium"
	"github.com/covalentio/hubble-fgs/api/v1/fgs"
	"github.com/covalentio/hubble-fgs/pkg/api"
	fgsAPI "github.com/covalentio/hubble-fgs/pkg/api"
	"github.com/covalentio/hubble-fgs/pkg/filters"
	"github.com/covalentio/hubble-fgs/pkg/logger"
	"github.com/covalentio/hubble-fgs/pkg/metrics"
	"github.com/covalentio/hubble-fgs/pkg/reader"
	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/golang/protobuf/ptypes/wrappers"
	lru "github.com/hashicorp/golang-lru"
	"github.com/sirupsen/logrus"
	coreV1 "k8s.io/api/core/v1"
)

type listener interface {
	notify(res *fgs.GetEventsResponse)
}

type notifier interface {
	addListener(listener listener)
	removeListener(listener listener)
}

// ProcessManager maintains a cache of processes from fgs exec events.
type ProcessManager struct {
	log   logrus.FieldLogger
	cache *lru.Cache
	// pidMap is a map from PID to the most recent exec ID for the PID. This is used to find the parent
	// of exec events without clone flag.
	pidMap   map[uint32]string
	nodeName string
	watcher  K8sResourceWatcher
	// synchronize access to the listeners map.
	mux         sync.Mutex
	listeners   map[listener]struct{}
	ciliumState *cilium.State
}

// NewProcessManager returns a pointer to an initialized ProcessManager struct.
func NewProcessManager(
	log logrus.FieldLogger,
	processCacheSize int,
	watcher K8sResourceWatcher,
	ciliumState *cilium.State,
) (*ProcessManager, error) {
	processCache, err := lru.New(processCacheSize)
	if err != nil {
		return nil, err
	}
	pm := &ProcessManager{
		log:         log,
		cache:       processCache,
		pidMap:      make(map[uint32]string),
		nodeName:    os.Getenv("NODE_NAME"),
		watcher:     watcher,
		ciliumState: ciliumState,
		listeners:   make(map[listener]struct{}),
	}
	update := func() {
		metrics.ExecveMapSize.WithLabelValues("processLru", strconv.Itoa(int(processCacheSize))).Set(float64(pm.cache.Len()))
	}
	ticker := time.NewTicker(60 * time.Second)
	go func() {
		for {
			select {
			case <-ticker.C:
				update()
			}
		}
	}()
	return pm, nil
}

func (pm *ProcessManager) handleTLSMessage(msg *api.MsgTLSEvent) *fgs.GetEventsResponse {
	var res *fgs.GetEventsResponse
	switch msg.Common.Op {
	case api.MSG_OP_TLS:
		res = &fgs.GetEventsResponse{
			Event:    &fgs.GetEventsResponse_Tls{Tls: pm.GetTLS(msg)},
			NodeName: pm.nodeName,
			Time:     ktimeToProto(0), // tbd
		}
	default:
		pm.log.WithField("message", msg).Warn("Unhandled event")
	}
	return res
}

func (pm *ProcessManager) handleExecveMessage(msg *api.MsgExecveEventUnix) *fgs.GetEventsResponse {
	var res *fgs.GetEventsResponse
	switch msg.Common.Op {
	case api.MSG_OP_EXECVE:
		proc := pm.Add(msg)
		res = &fgs.GetEventsResponse{
			Event:    &fgs.GetEventsResponse_ProcessExec{ProcessExec: pm.GetProcessExec(proc)},
			NodeName: pm.nodeName,
			Time:     ktimeToProto(msg.Process.Ktime),
		}
	default:
		pm.log.WithField("message", msg).Warn("Unhandled event")
	}
	return res
}

func (pm *ProcessManager) handleExitMessage(msg *api.MsgExitEventUnix) *fgs.GetEventsResponse {
	var res *fgs.GetEventsResponse
	switch msg.Common.Op {
	case api.MSG_OP_EXIT:
		res = &fgs.GetEventsResponse{
			Event:    &fgs.GetEventsResponse_ProcessExit{ProcessExit: pm.GetProcessExit(msg)},
			NodeName: pm.nodeName,
			Time:     ktimeToProto(0), // tbd
		}
	default:
		pm.log.WithField("message", msg).Warn("Unhandled event")
	}
	return res
}

func (pm *ProcessManager) handleTestMessage(msg *api.MsgTestEventUnix) *fgs.GetEventsResponse {
	var res *fgs.GetEventsResponse
	switch msg.Common.Op {
	case api.MSG_OP_TEST:
		res = &fgs.GetEventsResponse{
			Event:    &fgs.GetEventsResponse_Test{Test: &fgs.Test{}},
			NodeName: pm.nodeName,
			Time:     ktimeToProto(0), // tbd
		}
	default:
		pm.log.WithField("message", msg).Warn("Unhandled event")
	}
	return res
}

func (pm *ProcessManager) handleTCPMessage(msg *api.MsgIPv4TcpEventUnix) *fgs.GetEventsResponse {
	var res *fgs.GetEventsResponse
	switch msg.Common.Op {
	case api.MSG_OP_IPV4_TCPCONNECTRET:
		res = &fgs.GetEventsResponse{
			Event:    &fgs.GetEventsResponse_ProcessConnect{ProcessConnect: pm.GetProcessConnect(msg)},
			NodeName: pm.nodeName,
			Time:     ktimeToProto(msg.ProcessKey.Ktime),
		}
	case api.MSG_OP_IPV4_TCPCLOSE:
		res = &fgs.GetEventsResponse{
			Event:    &fgs.GetEventsResponse_ProcessClose{ProcessClose: pm.GetProcessClose(msg)},
			NodeName: pm.nodeName,
			Time:     ktimeToProto(msg.ProcessKey.Ktime),
		}
	case api.MSG_OP_IPV4_LISTEN:
		res = &fgs.GetEventsResponse{
			Event:    &fgs.GetEventsResponse_ProcessListen{ProcessListen: pm.GetProcessListen(msg)},
			NodeName: pm.nodeName,
			Time:     ktimeToProto(msg.ProcessKey.Ktime),
		}
	case api.MSG_OP_IPV4_ACCEPT:
		res = &fgs.GetEventsResponse{
			Event:    &fgs.GetEventsResponse_ProcessAccept{ProcessAccept: pm.GetProcessAccept(msg)},
			NodeName: pm.nodeName,
			Time:     ktimeToProto(msg.ProcessKey.Ktime),
		}
	default:
		pm.log.WithField("message", msg).Warn("Unhandled event")
	}
	return res
}

// Notify implements Listener.Notify.
func (pm *ProcessManager) Notify(event interface{}) error {
	var processedEvent *fgs.GetEventsResponse
	switch msg := event.(type) {
	case *api.MsgTLSEvent:
		processedEvent = pm.handleTLSMessage(msg)
	case *api.MsgExecveEventUnix:
		processedEvent = pm.handleExecveMessage(msg)
	case *api.MsgIPv4TcpEventUnix:
		processedEvent = pm.handleTCPMessage(msg)
	case *api.MsgExitEventUnix:
		processedEvent = pm.handleExitMessage(msg)
	case *api.MsgTestEventUnix:
		processedEvent = pm.handleTestMessage(msg)
	default:
		pm.log.WithField("event", event).Warn("unhandled event")
	}
	metrics.ProcessEvent(event, processedEvent)
	if processedEvent != nil {
		pm.notifyListeners(processedEvent)
	}
	return nil
}

// Close implements Listener.Close.
func (pm *ProcessManager) Close() error {
	return nil
}

func ktimeToProto(ktime uint64) *timestamp.Timestamp {
	decodedTime, err := reader.DecodeKtime(int64(ktime))
	if err != nil {
		logrus.WithError(err).WithField("ktime", ktime).Warn("Failed to decode ktime")
		return ptypes.TimestampNow()
	}
	ts, err := ptypes.TimestampProto(decodedTime)
	if err != nil {
		logrus.WithError(err).
			WithField("decoded time", decodedTime).
			Warn("Failed to convert decoded time to protobuf timestamp")
		return ptypes.TimestampNow()

	}
	return ts
}
func (pm *ProcessManager) getParentProcess(pid uint32, ktime uint64) (*fgs.Process, *fgs.Process) {
	var parent, process *fgs.Process

	processID, err := pm.GetProcessID(pid, ktime)
	if err != nil {
		pm.log.WithError(err).WithField("pid", pid).WithField("ktime", ktime).Warn("Listen Failed to get exec process")
	}

	if entry, ok := pm.cache.Get(processID); ok {
		process, _ = entry.(*fgs.Process)
		if !ok {
			pm.log.WithField("process entry", entry).Warn("invalid entry in process cache")
		}
	} else {
		pm.log.WithField("id in event", processID).WithField("pid", pid).WithField("ktime", ktime).Warn("process not found in cache")
		return nil, nil
	}

	if entry, ok := pm.cache.Get(process.ParentExecId); ok {
		parent, ok = entry.(*fgs.Process)
		if !ok {
			pm.log.WithField("process entry", entry).Warn("invalid entry in process cache")
		}
	} else {
		pm.log.WithField("id in event", process.ParentExecId).WithField("pid", pid).WithField("ktime", ktime).Warn("parent process not found in cache")
		return process, nil
	}
	return process, parent
}

func (pm *ProcessManager) getProcessEndpoint(process *fgs.Process) *v1.Endpoint {
	if process.Docker == "" {
		return nil
	}
	pod, _, ok := pm.watcher.FindPod(process.Docker)
	if !ok {
		pm.log.WithField("container id", process.Docker).Trace("failed to get pod")
		return nil
	}
	endpoint, _ := pm.ciliumState.GetEndpointsHandler().GetEndpointByPodName(pod.Namespace, pod.Name)
	return endpoint
}

func (pm *ProcessManager) getProcess(
	process fgsAPI.MsgExecUnix,
	containerID string,
	parent fgsAPI.MsgExecveKey,
) (*fgs.Process, *v1.Endpoint) {
	args, cwd := reader.ArgsDecoder(process.Args, process.Flags)
	var parentExecID string
	var err error
	if parent.Pid != 0 {
		if parentExecID, err = pm.GetExecIDFromKey(&parent); err != nil {
			pm.log.WithError(err).WithField("parent", parent).Warn("Failed to get exec ID for parent")
		}
	}
	execID, err := pm.GetExecID(&process)
	if err != nil {
		pm.log.WithError(err).WithField("process", process).Warn("Failed to get exec ID for process")
	}
	protoPod, endpoint := pm.getPodInfo(containerID, process.Filename, args, process.NSPID)
	return &fgs.Process{
		Pid:          &wrappers.UInt32Value{Value: process.PID},
		Uid:          &wrappers.UInt32Value{Value: process.UID},
		Cwd:          cwd,
		Binary:       process.Filename,
		Arguments:    args,
		Flags:        strings.Join(reader.DecodeCommonFlags(process.Flags), " "),
		StartTime:    ktimeToProto(process.Ktime),
		Auid:         &wrappers.UInt32Value{Value: process.AUID},
		Pod:          protoPod,
		ExecId:       execID,
		Docker:       containerID,
		ParentExecId: parentExecID,
		Refcnt:       1,
	}, endpoint
}

// Add converts an FGS exec event to protobuf format and adds the protobuf message to the cache.
func (pm *ProcessManager) Add(event *fgsAPI.MsgExecveEventUnix) *fgs.Process {
	proc, _ := pm.getProcess(event.Process, event.Kube.Docker, event.Parent)
	pm.cache.Add(proc.ExecId, proc)
	var parentExecID string
	if proc.Pid != nil {
		parentExecID = pm.pidMap[proc.Pid.Value]
		pm.pidMap[proc.Pid.Value] = proc.ExecId
	}
	if strings.Contains(proc.Flags, "clone") || strings.Contains(proc.Flags, "procFS") {
		return proc
	}
	// This means the exec didn't clone. Look up the most recent exec ID for this PID
	// and use that as the parent.
	entry, ok := pm.cache.Get(parentExecID)
	if !ok {
		metrics.ErrorCount.WithLabelValues(string(metrics.NoParentNoClone)).Inc()
		pm.log.WithFields(logrus.Fields{
			"parent exec id": parentExecID,
			"process":        proc,
		}).Debug("parent not found in cache")
		return proc
	}
	parent, ok := entry.(*fgs.Process)
	if !ok {
		pm.log.WithField("parent process entry", parent).Warn("invalid entry in process cache")
		return proc
	}
	if parent.ExecId == proc.ExecId {
		pm.log.WithFields(logrus.Fields{
			"parent":  parent,
			"current": proc,
		}).Warn("parent and current process has the same exec ID")
		return proc
	}
	proc.ParentExecId = parent.ExecId
	return proc
}

// getAncestors builds an ancestor list by traversing the parent exec IDs.
func (pm *ProcessManager) getAncestors(proc *fgs.Process) []*fgs.Process {
	var ancestors []*fgs.Process
	for parentExecID := proc.ParentExecId; parentExecID != ""; {
		val, ok := pm.cache.Get(parentExecID)
		if !ok {
			pm.log.WithField("id in event", parentExecID).Debug("parent not found in cache")
			break
		}
		entry, ok := val.(*fgs.Process)
		if !ok {
			break
		}
		ancestors = append(ancestors, entry)
		parentExecID = entry.ParentExecId
	}
	return ancestors
}

func (pm *ProcessManager) GetProcessID(pid uint32, ktime uint64) (string, error) {
	builder := strings.Builder{}
	encoder := base64.NewEncoder(base64.StdEncoding, &builder)
	if _, err := encoder.Write([]byte(fmt.Sprintf("%s:%d:%d", pm.nodeName, ktime, pid))); err != nil {
		return "", err
	}
	if err := encoder.Close(); err != nil {
		return "", err
	}
	return builder.String(), nil
}

// GetExecID returns the exec ID of a given process.
func (pm *ProcessManager) GetExecID(proc *fgsAPI.MsgExecUnix) (string, error) {
	return pm.GetProcessID(proc.PID, proc.Ktime)
}

func (pm *ProcessManager) GetExecIDFromKey(key *fgsAPI.MsgExecveKey) (string, error) {
	return pm.GetProcessID(key.Pid, key.Ktime)
}

// GetProcessExec returns Exec protobuf message for a given process, including the ancestor list.
func (pm *ProcessManager) GetProcessExec(
	proc *fgs.Process,
) *fgs.ProcessExec {
	var parent *fgs.Process
	ancestors := pm.getAncestors(proc)
	if len(ancestors) >= 1 {
		parent = ancestors[0]
		ancestors = ancestors[1:]
		parent.Refcnt++
		for _, a := range ancestors {
			a.Refcnt++
		}
	}
	return &fgs.ProcessExec{
		Process:   proc,
		Parent:    parent,
		Ancestors: ancestors,
	}
}

// GetProcessListen returns Listen protobuf message for a given process, including the ancestor list.
func (pm *ProcessManager) GetProcessListen(
	event *fgsAPI.MsgIPv4TcpEventUnix,
) *fgs.ProcessListen {
	var port *wrappers.UInt32Value
	if event.Tuple.SPort != 0 {
		port = &wrappers.UInt32Value{
			Value: uint32(reader.GetSport(event.Tuple.SPort)),
		}
	}
	process, parent := pm.getParentProcess(event.ProcessKey.Pid, event.ProcessKey.Ktime)
	if process != nil {
		process.Refcnt++
	}
	if parent != nil {
		process.Refcnt++
	}
	return &fgs.ProcessListen{
		Process: process,
		Parent:  parent,
		Ip:      reader.GetIP(event.Tuple.SAddr, 0).String(),
		Port:    port,
	}
}

// GetProcessExit returns Exit protobuf message for a given process.
func (pm *ProcessManager) GetProcessExit(event *fgsAPI.MsgExitEventUnix) *fgs.ProcessExit {
	process, parent := pm.getParentProcess(event.ProcessKey.Pid, event.ProcessKey.Ktime)
	if process == nil {
		process = &fgs.Process{
			Pid:       &wrappers.UInt32Value{Value: event.ProcessKey.Pid},
			StartTime: ktimeToProto(event.ProcessKey.Ktime),
		}
	} else {
		process.Refcnt--
		if process.Refcnt == 0 {
			pm.cache.Remove(process)
		}
	}
	if parent != nil {
		parent.Refcnt--
		if parent.Refcnt == 0 {
			pm.cache.Remove(parent)
		}
	}
	return &fgs.ProcessExit{
		Process: process,
		Parent:  parent,
	}
}

// GetTLS converts TLSEvent from hubble-fgs to protobuf message.
func (pm *ProcessManager) GetTLS(event *fgsAPI.MsgTLSEvent) *fgs.Tls {
	var sourcePort, destinationPort *wrappers.UInt32Value
	if event.Tuple.SPort != 0 {
		sourcePort = &wrappers.UInt32Value{
			Value: uint32(event.Tuple.SPort),
		}
	}
	if event.Tuple.DPort != 0 {
		destinationPort = &wrappers.UInt32Value{
			Value: uint32(event.Tuple.DPort),
		}
	}

	processID, err := pm.GetProcessID(event.ProcessKey.Pid, event.ProcessKey.Ktime)
	if err != nil {
		pm.log.WithError(err).Warn("TLS Failed to get exec process", event.ProcessKey.Pid)
	}
	var proc *fgs.Process
	if entry, ok := pm.cache.Get(processID); ok {
		proc, ok = entry.(*fgs.Process)
		if !ok {
			pm.log.WithField("process entry", entry).Warn("invalid entry in process cache")
		}
	} else {
		pm.log.WithField("id in TLS event", processID).Warn("process not found in cache")
	}
	typeSNI, nameSNI := reader.GetTLSSNI(event.ClientHello.SNI)
	return &fgs.Tls{
		Process:           proc,
		SourceIp:          reader.GetIP(event.Tuple.SAddr, event.Common.Op).String(),
		SourcePort:        sourcePort,
		DestinationIp:     reader.GetIP(event.Tuple.DAddr, event.Common.Op).String(),
		DestinationPort:   destinationPort,
		NegotiatedVersion: reader.GetTLSSupportedVersions(event.ServerHello.SupportedVersions, 0),
		SupportedVersions: reader.GetTLSSupportedVersions(event.ClientHello.SupportedVersions, 1),
		SniName:           nameSNI,
		SniType:           typeSNI,
		Cipher:            reader.GetTLSCipher(api.SwapByte(event.ServerHello.Cipher)),
		ClientFlags:       reader.GetTLSFlags(event.ClientHello.Flags),
		ServerFlags:       reader.GetTLSFlags(event.ServerHello.Flags),
		ClientVersion:     reader.GetTLSVersion(event.ClientHello.Version),
		ServerVersion:     reader.GetTLSVersion(event.ServerHello.Version),
		ClientAlert:       reader.GetTLSAlert(event.ClientHello.AlertLevel, event.ClientHello.AlertDescription),
		ServerAlert:       reader.GetTLSAlert(event.ServerHello.AlertLevel, event.ServerHello.AlertDescription),
		ClientSession:     reader.GetTLSSession(event.ClientHello.Session),
		ServerSession:     reader.GetTLSSession(event.ServerHello.Session),
	}
}

// GetProcessClose converts KprobeEvent from hubble-fgs to protobuf message.
func (pm *ProcessManager) GetProcessClose(event *fgsAPI.MsgIPv4TcpEventUnix) *fgs.ProcessClose {
	var sourcePort, destinationPort *wrappers.UInt32Value
	if event.Tuple.SPort != 0 {
		sourcePort = &wrappers.UInt32Value{
			Value: uint32(reader.GetSport(event.Tuple.SPort)),
		}
	}
	if event.Tuple.DPort != 0 {
		destinationPort = &wrappers.UInt32Value{
			Value: uint32(fgsAPI.SwapByte(event.Tuple.DPort)),
		}
	}

	process, parent := pm.getParentProcess(event.ProcessKey.Pid, event.ProcessKey.Ktime)
	if process == nil {
		process = &fgs.Process{
			Pid:       &wrappers.UInt32Value{Value: event.ProcessKey.Pid},
			StartTime: ktimeToProto(event.ProcessKey.Ktime),
		}
	} else {
		process.Refcnt--
		if process.Refcnt == 0 {
			pm.cache.Remove(process)
		}
	}
	if parent == nil {
		parent = &fgs.Process{}
	} else {
		parent.Refcnt--
		if parent.Refcnt == 0 {
			pm.cache.Remove(parent)
		}
	}
	endpoint := pm.getProcessEndpoint(process)

	destinationIP := reader.GetIP(event.Tuple.DAddr, event.Common.Op)
	var destinationNames []string
	if endpoint != nil {
		destinationNames = pm.ciliumState.GetFQDNCache().GetNamesOf(endpoint.ID, destinationIP)
	}
	return &fgs.ProcessClose{
		Process:          process,
		Parent:           parent,
		SourceIp:         reader.GetIP(event.Tuple.SAddr, event.Common.Op).String(),
		SourcePort:       sourcePort,
		DestinationIp:    destinationIP.String(),
		DestinationPort:  destinationPort,
		DestinationNames: destinationNames,
	}
}

// GetProcessConnect converts KprobeEvent from hubble-fgs to protobuf message.
func (pm *ProcessManager) GetProcessConnect(event *fgsAPI.MsgIPv4TcpEventUnix) *fgs.ProcessConnect {
	var sourcePort, destinationPort *wrappers.UInt32Value
	if event.Tuple.SPort != 0 {
		sourcePort = &wrappers.UInt32Value{
			Value: uint32(reader.GetSport(event.Tuple.SPort)),
		}
	}
	if event.Tuple.DPort != 0 {
		destinationPort = &wrappers.UInt32Value{
			Value: uint32(fgsAPI.SwapByte(event.Tuple.DPort)),
		}
	}

	process, parent := pm.getParentProcess(event.ProcessKey.Pid, event.ProcessKey.Ktime)
	if process == nil {
		process = &fgs.Process{
			Pid:       &wrappers.UInt32Value{Value: event.ProcessKey.Pid},
			StartTime: ktimeToProto(event.ProcessKey.Ktime),
		}
	} else {
		process.Refcnt++
	}
	if parent == nil {
		parent = &fgs.Process{}
	} else {
		parent.Refcnt++
	}
	endpoint := pm.getProcessEndpoint(process)

	destinationIP := reader.GetIP(event.Tuple.DAddr, event.Common.Op)
	var destinationNames []string
	if endpoint != nil {
		destinationNames = pm.ciliumState.GetFQDNCache().GetNamesOf(endpoint.ID, destinationIP)
	}
	return &fgs.ProcessConnect{
		Process:          process,
		Parent:           parent,
		SourceIp:         reader.GetIP(event.Tuple.SAddr, event.Common.Op).String(),
		SourcePort:       sourcePort,
		DestinationIp:    destinationIP.String(),
		DestinationPort:  destinationPort,
		DestinationNames: destinationNames,
	}
}

// GetProcessAccept converts KprobeEvent from hubble-fgs to protobuf message.
func (pm *ProcessManager) GetProcessAccept(event *fgsAPI.MsgIPv4TcpEventUnix) *fgs.ProcessAccept {
	var sourcePort, destinationPort *wrappers.UInt32Value
	if event.Tuple.SPort != 0 {
		sourcePort = &wrappers.UInt32Value{
			Value: uint32(reader.GetSport(event.Tuple.SPort)),
		}
	}
	if event.Tuple.DPort != 0 {
		destinationPort = &wrappers.UInt32Value{
			Value: uint32(fgsAPI.SwapByte(event.Tuple.DPort)),
		}
	}

	process, parent := pm.getParentProcess(event.ProcessKey.Pid, event.ProcessKey.Ktime)
	if process == nil {
		process = &fgs.Process{
			Pid:       &wrappers.UInt32Value{Value: event.ProcessKey.Pid},
			StartTime: ktimeToProto(event.ProcessKey.Ktime),
		}
	} else {
		process.Refcnt++
	}
	if parent == nil {
		parent = &fgs.Process{}
	} else {
		parent.Refcnt++
	}
	endpoint := pm.getProcessEndpoint(process)

	destinationIP := reader.GetIP(event.Tuple.DAddr, event.Common.Op)
	var destinationNames []string
	if endpoint != nil {
		destinationNames = pm.ciliumState.GetFQDNCache().GetNamesOf(endpoint.ID, destinationIP)
	}
	return &fgs.ProcessAccept{
		Process:          process,
		Parent:           parent,
		SourceIp:         reader.GetIP(event.Tuple.SAddr, event.Common.Op).String(),
		SourcePort:       sourcePort,
		DestinationIp:    destinationIP.String(),
		DestinationPort:  destinationPort,
		DestinationNames: destinationNames,
	}
}

func (pm *ProcessManager) getPodInfo(containerID string, binary string, args string, nspid uint32) (*fgs.Pod, *v1.Endpoint) {
	if containerID == "" {
		return nil, nil
	}
	pod, container, ok := pm.watcher.FindPod(containerID)
	if !ok {
		pm.log.WithField("container id", containerID).Trace("failed to get pod")
		return nil, nil
	}
	var startTime *timestamp.Timestamp
	livenessProbe, readinessProbe := getProbes(pod, container)
	maybeExecProbe := filters.MaybeExecProbe(binary, args, livenessProbe) ||
		filters.MaybeExecProbe(binary, args, readinessProbe)
	var err error
	if container.State.Running != nil {
		if startTime, err = ptypes.TimestampProto(container.State.Running.StartedAt.Time); err != nil {
			pm.log.WithField("container", container).Warn("failed to convert start time")
		}
	}
	endpoint, ok := pm.ciliumState.GetEndpointsHandler().GetEndpointByPodName(pod.Namespace, pod.Name)
	var labels []string
	if ok {
		labels = endpoint.Labels
	}

	// Don't set container PIDs if it's zero.
	var containerPID *wrappers.UInt32Value
	if nspid > 0 {
		containerPID = &wrappers.UInt32Value{
			Value: nspid,
		}
	}
	return &fgs.Pod{
		Namespace: pod.Namespace,
		Name:      pod.Name,
		Labels:    labels,
		Container: &fgs.Container{
			Id:   container.ContainerID,
			Pid:  containerPID,
			Name: container.Name,
			Image: &fgs.Image{
				Id:   container.ImageID,
				Name: container.Image,
			},
			StartTime:      startTime,
			MaybeExecProbe: maybeExecProbe,
		},
	}, endpoint
}

func getExecCommand(probe *coreV1.Probe) []string {
	if probe != nil && probe.Exec != nil {
		return probe.Exec.Command
	}
	return nil
}

func getProbes(pod *coreV1.Pod, containerStatus *coreV1.ContainerStatus) ([]string, []string) {
	for _, container := range pod.Spec.Containers {
		if container.Name == containerStatus.Name {
			return getExecCommand(container.LivenessProbe), getExecCommand(container.ReadinessProbe)
		}
	}
	return nil, nil
}

func (pm *ProcessManager) addListener(listener listener) {
	logger.GetLogger().WithField("getEventsListener", listener).Debug("Adding a getEventsListener")
	pm.mux.Lock()
	defer pm.mux.Unlock()
	pm.listeners[listener] = struct{}{}
}

func (pm *ProcessManager) removeListener(listener listener) {
	logger.GetLogger().WithField("getEventsListener", listener).Debug("Removing a getEventsListener")
	pm.mux.Lock()
	defer pm.mux.Unlock()
	delete(pm.listeners, listener)
}

func (pm *ProcessManager) notifyListeners(event *fgs.GetEventsResponse) {
	pm.mux.Lock()
	defer pm.mux.Unlock()
	for l := range pm.listeners {
		l.notify(event)
	}
}

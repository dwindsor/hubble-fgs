package grpc

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"sync"

	v1 "github.com/cilium/hubble/pkg/api/v1"
	"github.com/cilium/hubble/pkg/cilium"
	"github.com/covalentio/hubble-fgs/api/v1/fgs"
	"github.com/covalentio/hubble-fgs/pkg/api"
	fgsAPI "github.com/covalentio/hubble-fgs/pkg/api"
	"github.com/covalentio/hubble-fgs/pkg/filters"
	"github.com/covalentio/hubble-fgs/pkg/logger"
	"github.com/covalentio/hubble-fgs/pkg/metrics"
	"github.com/covalentio/hubble-fgs/pkg/reader"
	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/golang/protobuf/ptypes/wrappers"
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
	cache *processCache
	// pidMap is a map from PID to the most recent exec ID for the PID. This is used to find the parent
	// of exec events without clone flag.
	pidMap   map[uint32]string
	nodeName string
	watcher  K8sResourceWatcher
	// synchronize access to the listeners map.
	mux               sync.Mutex
	listeners         map[listener]struct{}
	ciliumState       *cilium.State
	enableProcessCred bool
}

// NewProcessManager returns a pointer to an initialized ProcessManager struct.
func NewProcessManager(
	log logrus.FieldLogger,
	processCacheSize int,
	watcher K8sResourceWatcher,
	ciliumState *cilium.State,
	enableProcessCred bool,
) (*ProcessManager, error) {
	cache, err := newProcessCache(log, processCacheSize)
	if err != nil {
		return nil, err
	}

	return &ProcessManager{
		log:               log,
		cache:             cache,
		pidMap:            make(map[uint32]string),
		nodeName:          os.Getenv("NODE_NAME"),
		watcher:           watcher,
		ciliumState:       ciliumState,
		listeners:         make(map[listener]struct{}),
		enableProcessCred: enableProcessCred,
	}, nil
}

func (pm *ProcessManager) handleTLSMessage(msg *api.MsgTLSEvent) *fgs.GetEventsResponse {
	var res *fgs.GetEventsResponse
	switch msg.Common.Op {
	case api.MSG_OP_TLS:
		res = &fgs.GetEventsResponse{
			Event:    &fgs.GetEventsResponse_Tls{Tls: pm.GetTLS(msg)},
			NodeName: pm.nodeName,
			Time:     ktimeToProto(msg.Common.Ktime),
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
			Time:     ktimeToProto(msg.Common.Ktime),
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
			Time:     ktimeToProto(msg.Common.Ktime),
		}
	default:
		pm.log.WithField("message", msg).Warn("Unhandled event")
	}
	return res
}

func (pm *ProcessManager) handleCredMessage(msg *api.MsgCredEventUnix) *fgs.GetEventsResponse {
	if !pm.enableProcessCred {
		return nil
	}
	var res *fgs.GetEventsResponse
	switch msg.Common.Op {
	case api.MSG_OP_CRED:
		res = &fgs.GetEventsResponse{
			Event:    &fgs.GetEventsResponse_ProcessCred{ProcessCred: pm.GetProcessCred(msg)},
			NodeName: pm.nodeName,
			Time:     ktimeToProto(msg.Common.Ktime),
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
			Time:     ktimeToProto(msg.Common.Ktime),
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
			Time:     ktimeToProto(msg.Common.Ktime),
		}
	case api.MSG_OP_IPV4_TCPCLOSE:
		res = &fgs.GetEventsResponse{
			Event:    &fgs.GetEventsResponse_ProcessClose{ProcessClose: pm.GetProcessClose(msg)},
			NodeName: pm.nodeName,
			Time:     ktimeToProto(msg.Common.Ktime),
		}
	case api.MSG_OP_IPV4_LISTEN:
		res = &fgs.GetEventsResponse{
			Event:    &fgs.GetEventsResponse_ProcessListen{ProcessListen: pm.GetProcessListen(msg)},
			NodeName: pm.nodeName,
			Time:     ktimeToProto(msg.Common.Ktime),
		}
	case api.MSG_OP_IPV4_ACCEPT:
		res = &fgs.GetEventsResponse{
			Event:    &fgs.GetEventsResponse_ProcessAccept{ProcessAccept: pm.GetProcessAccept(msg)},
			NodeName: pm.nodeName,
			Time:     ktimeToProto(msg.Common.Ktime),
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
	case *api.MsgCredEventUnix:
		processedEvent = pm.handleCredMessage(msg)
	case *api.MsgTestEventUnix:
		processedEvent = pm.handleTestMessage(msg)
	default:
		pm.log.WithField("event", event).Warn("unhandled event")
		metrics.ErrorCount.WithLabelValues(string(metrics.UnhandledEvent)).Inc()
		return nil
	}
	if processedEvent != nil {
		metrics.ProcessEvent(event, processedEvent)
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
	var process, parent *fgs.Process
	procInternal, parentInternal := pm.getParentProcessInternal(pid, ktime)
	if procInternal != nil {
		process = procInternal.process
	}
	if parentInternal != nil {
		parent = parentInternal.process
	}
	return process, parent
}

func (pm *ProcessManager) getParentProcessInternal(pid uint32, ktime uint64) (*processInternal, *processInternal) {
	var parent, process *processInternal
	var err error

	processID, err := pm.GetProcessID(pid, ktime)
	if err != nil {
		pm.log.WithError(err).WithField("pid", pid).WithField("ktime", ktime).Warn("Listen Failed to get exec process")
	}

	if process, err = pm.cache.get(processID); err != nil {
		pm.log.WithField("id in event", processID).WithField("pid", pid).WithField("ktime", ktime).Debug("process not found in cache")
		return nil, nil
	}

	if parent, err = pm.cache.get(process.process.ParentExecId); err != nil {
		pm.log.WithField("id in event", process.process.ParentExecId).WithField("pid", pid).WithField("ktime", ktime).Debug("parent process not found in cache")
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

func getCapabilitiesTypes(capInt uint64) []fgs.CapabilitiesType {
	var caps []fgs.CapabilitiesType
	for i := uint64(0); i < 64; i++ {
		if (1<<i)&capInt != 0 {
			e := fgs.CapabilitiesType(i)
			caps = append(caps, e)
		}
	}
	return caps
}

func (pm *ProcessManager) getCapabilities(caps fgsAPI.MsgCapabilities) *fgs.Capabilities {
	return &fgs.Capabilities{
		Permitted:   getCapabilitiesTypes(caps.Permitted),
		Effective:   getCapabilitiesTypes(caps.Effective),
		Inheritable: getCapabilitiesTypes(caps.Inheritable),
	}
}

func (pm *ProcessManager) getProcess(
	process fgsAPI.MsgExecUnix,
	containerID string,
	parent fgsAPI.MsgExecveKey,
	capabilities fgsAPI.MsgCapabilities,
) (*processInternal, *v1.Endpoint) {
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
	caps := pm.getCapabilities(capabilities)
	return &processInternal{
		process: &fgs.Process{
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
		},
		capabilities: caps,
	}, endpoint
}

// Add converts an FGS exec event to protobuf format and adds the protobuf message to the cache.
func (pm *ProcessManager) Add(event *fgsAPI.MsgExecveEventUnix) *processInternal {
	proc, _ := pm.getProcess(event.Process, event.Kube.Docker, event.Parent, event.Capabilities)
	pm.cache.add(proc)
	var parentExecID string
	if proc.process.Pid != nil {
		parentExecID = pm.pidMap[proc.process.Pid.Value]
		pm.pidMap[proc.process.Pid.Value] = proc.process.ExecId
	}
	if strings.Contains(proc.process.Flags, "clone") || strings.Contains(proc.process.Flags, "procFS") {
		return proc
	}
	// This means the exec didn't clone. Look up the most recent exec ID for this PID
	// and use that as the parent.
	parent, err := pm.cache.get(parentExecID)
	if err != nil {
		metrics.ErrorCount.WithLabelValues(string(metrics.NoParentNoClone)).Inc()
		pm.log.WithFields(logrus.Fields{
			"parent exec id": parentExecID,
			"process":        proc,
		}).Debug("parent not found in cache")
		return proc
	}
	if parent.process.ExecId == proc.process.ExecId {
		pm.log.WithFields(logrus.Fields{
			"parent":  parent,
			"current": proc,
		}).Warn("parent and current process has the same exec ID")
		return proc
	}
	proc.process.ParentExecId = parent.process.ExecId
	return proc
}

// getAncestors builds an ancestor list by traversing the parent exec IDs.
func (pm *ProcessManager) getAncestors(proc *fgs.Process) []*processInternal {
	var ancestors []*processInternal
	for parentExecID := proc.ParentExecId; parentExecID != ""; {
		entry, err := pm.cache.get(parentExecID)
		if err != nil {
			pm.log.WithField("id in event", parentExecID).Debug("parent not found in cache")
			break
		}
		ancestors = append(ancestors, entry)
		parentExecID = entry.process.ParentExecId
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

func copyProcess(process *fgs.Process) *fgs.Process {
	if process == nil {
		return nil
	}
	return proto.Clone(process).(*fgs.Process)
}

// GetProcessExec returns Exec protobuf message for a given process, including the ancestor list.
func (pm *ProcessManager) GetProcessExec(
	proc *processInternal,
) *fgs.ProcessExec {
	var parent *processInternal
	var fgsAncestors []*fgs.Process

	ancestors := pm.getAncestors(proc.process)
	if len(ancestors) >= 1 {
		parent = ancestors[0]
		ancestors = ancestors[1:]
		pm.cache.refInc(parent)
		for _, a := range ancestors {
			pm.cache.refInc(a)
		}
	}
	// Set the cap field only if --enable-process-cred flag is set.
	var fgsParent, fgsProcess *fgs.Process
	if pm.enableProcessCred {
		fgsProcess = copyProcess(proc.process)
		fgsProcess.Cap = proc.capabilities
	} else {
		fgsProcess = proc.process
	}
	if parent != nil {
		fgsParent = parent.process
	}
	for _, a := range ancestors {
		fgsAncestors = append(fgsAncestors, a.process)
	}
	// If this is not a clone we need to decrement parent refcnt because
	// the parent has been replaced and will not get its own exit event.
	// The new process will hold needed refcnts until it is destroyed.
	if strings.Contains(proc.process.Flags, "clone") == false &&
		strings.Contains(proc.process.Flags, "procFS") == false &&
		parent != nil {
		pm.cache.refDec(parent)
		ancestors := pm.getAncestors(fgsParent)
		if len(ancestors) >= 1 {
			ancestors = ancestors[0:]
			for _, a := range ancestors {
				pm.cache.refDec(a)
			}
		}
	}
	return &fgs.ProcessExec{
		Process:   fgsProcess,
		Parent:    fgsParent,
		Ancestors: fgsAncestors,
	}
}

// GetProcessListen returns Listen protobuf message for a given process, including the ancestor list.
func (pm *ProcessManager) GetProcessListen(
	event *fgsAPI.MsgIPv4TcpEventUnix,
) *fgs.ProcessListen {
	var fgsProcess, fgsParent *fgs.Process
	var port *wrappers.UInt32Value

	if event.Tuple.SPort != 0 {
		port = &wrappers.UInt32Value{
			Value: uint32(reader.GetSport(event.Tuple.SPort)),
		}
	}
	process, parent := pm.getParentProcessInternal(event.ProcessKey.Pid, event.ProcessKey.Ktime)
	if process != nil {
		pm.cache.refInc(process)
		fgsProcess = process.process
	} else {
		fgsProcess = &fgs.Process{
			Pid:       &wrappers.UInt32Value{Value: event.ProcessKey.Pid},
			StartTime: ktimeToProto(event.ProcessKey.Ktime),
		}
	}
	if parent != nil {
		pm.cache.refInc(parent)
		fgsParent = parent.process
	}
	return &fgs.ProcessListen{
		Process: fgsProcess,
		Parent:  fgsParent,
		Ip:      reader.GetIP(event.Tuple.SAddr, 0).String(),
		Port:    port,
	}
}

// GetProcessExit returns Exit protobuf message for a given process.
func (pm *ProcessManager) GetProcessExit(event *fgsAPI.MsgExitEventUnix) *fgs.ProcessExit {
	var fgsProcess, fgsParent *fgs.Process

	process, parent := pm.getParentProcessInternal(event.ProcessKey.Pid, event.ProcessKey.Ktime)
	if process != nil {
		pm.cache.refDec(process)
		fgsProcess = process.process
	} else {
		fgsProcess = &fgs.Process{
			Pid:       &wrappers.UInt32Value{Value: event.ProcessKey.Pid},
			StartTime: ktimeToProto(event.ProcessKey.Ktime),
		}
	}
	if parent != nil {
		pm.cache.refDec(parent)
		fgsParent = parent.process
	}

	ancestors := pm.getAncestors(fgsProcess)
	if len(ancestors) >= 2 {
		ancestors = ancestors[1:]
		for _, a := range ancestors {
			pm.cache.refDec(a)
		}
	}
	return &fgs.ProcessExit{
		Process: fgsProcess,
		Parent:  fgsParent,
	}
}

// GetProcessCred returns Cred protobuf message for a given process.
func (pm *ProcessManager) GetProcessCred(event *fgsAPI.MsgCredEventUnix) *fgs.ProcessCred {
	processInt, parentInt := pm.getParentProcessInternal(event.ProcessKey.Pid, event.ProcessKey.Ktime)
	var process, parent *fgs.Process
	if processInt == nil {
		process = &fgs.Process{
			Pid:       &wrappers.UInt32Value{Value: event.ProcessKey.Pid},
			StartTime: ktimeToProto(event.ProcessKey.Ktime),
		}
	} else {
		// Make a copy of the process and set the cap field.
		process = copyProcess(processInt.process)
		process.Cap = processInt.capabilities
	}
	if parentInt != nil {
		// Make a copy of the parent and set the cap field.
		parent = copyProcess(parentInt.process)
		parent.Cap = parentInt.capabilities
	}
	return &fgs.ProcessCred{
		Process: process,
		Parent:  parent,
		Cap:     pm.getCapabilities(event.Capabilities),
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
	processInt, err := pm.cache.get(processID)
	if err != nil {
		pm.log.WithField("id in TLS event", processID).Debug("process not found in cache")
	} else {
		proc = processInt.process
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
	var fgsParent, fgsProcess *fgs.Process

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

	process, parent := pm.getParentProcessInternal(event.ProcessKey.Pid, event.ProcessKey.Ktime)
	if process == nil {
		fgsProcess = &fgs.Process{
			Pid:       &wrappers.UInt32Value{Value: event.ProcessKey.Pid},
			StartTime: ktimeToProto(event.ProcessKey.Ktime),
		}
	} else {
		fgsProcess = process.process
		pm.cache.refDec(process)
	}
	if parent == nil {
		fgsParent = &fgs.Process{}
	} else {
		fgsParent = parent.process
		pm.cache.refDec(parent)
	}
	endpoint := pm.getProcessEndpoint(fgsProcess)

	destinationIP := reader.GetIP(event.Tuple.DAddr, event.Common.Op)
	var destinationNames []string
	if endpoint != nil {
		destinationNames = pm.ciliumState.GetFQDNCache().GetNamesOf(endpoint.ID, destinationIP)
	}
	return &fgs.ProcessClose{
		Process:          fgsProcess,
		Parent:           fgsParent,
		SourceIp:         reader.GetIP(event.Tuple.SAddr, event.Common.Op).String(),
		SourcePort:       sourcePort,
		DestinationIp:    destinationIP.String(),
		DestinationPort:  destinationPort,
		DestinationNames: destinationNames,
	}
}

// GetProcessConnect converts KprobeEvent from hubble-fgs to protobuf message.
func (pm *ProcessManager) GetProcessConnect(event *fgsAPI.MsgIPv4TcpEventUnix) *fgs.ProcessConnect {
	var fgsProcess, fgsParent *fgs.Process
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

	process, parent := pm.getParentProcessInternal(event.ProcessKey.Pid, event.ProcessKey.Ktime)
	if process == nil {
		fgsProcess = &fgs.Process{
			Pid:       &wrappers.UInt32Value{Value: event.ProcessKey.Pid},
			StartTime: ktimeToProto(event.ProcessKey.Ktime),
		}
	} else {
		fgsProcess = process.process
		pm.cache.refInc(process)
	}
	if parent == nil {
		fgsParent = &fgs.Process{}
	} else {
		fgsParent = parent.process
		pm.cache.refInc(parent)
	}
	endpoint := pm.getProcessEndpoint(fgsProcess)

	destinationIP := reader.GetIP(event.Tuple.DAddr, event.Common.Op)
	var destinationNames []string
	if endpoint != nil {
		destinationNames = pm.ciliumState.GetFQDNCache().GetNamesOf(endpoint.ID, destinationIP)
	}
	return &fgs.ProcessConnect{
		Process:          fgsProcess,
		Parent:           fgsParent,
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
	var fgsParent, fgsProcess *fgs.Process

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

	process, parent := pm.getParentProcessInternal(event.ProcessKey.Pid, event.ProcessKey.Ktime)
	if process == nil {
		fgsProcess = &fgs.Process{
			Pid:       &wrappers.UInt32Value{Value: event.ProcessKey.Pid},
			StartTime: ktimeToProto(event.ProcessKey.Ktime),
		}
	} else {
		fgsProcess = process.process
		pm.cache.refInc(process)
	}
	if parent == nil {
		fgsParent = &fgs.Process{}
	} else {
		fgsParent = parent.process
		pm.cache.refInc(parent)
	}
	endpoint := pm.getProcessEndpoint(fgsProcess)

	destinationIP := reader.GetIP(event.Tuple.DAddr, event.Common.Op)
	var destinationNames []string
	if endpoint != nil {
		destinationNames = pm.ciliumState.GetFQDNCache().GetNamesOf(endpoint.ID, destinationIP)
	}
	return &fgs.ProcessAccept{
		Process:          fgsProcess,
		Parent:           fgsParent,
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

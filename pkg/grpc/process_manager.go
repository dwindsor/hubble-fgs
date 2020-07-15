package grpc

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/covalentio/hubble-fgs/api/v1/fgs"
	"github.com/covalentio/hubble-fgs/pkg/api"
	fgsAPI "github.com/covalentio/hubble-fgs/pkg/api"
	"github.com/covalentio/hubble-fgs/pkg/metrics"
	"github.com/covalentio/hubble-fgs/pkg/reader"
	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/golang/protobuf/ptypes/wrappers"
	lru "github.com/hashicorp/golang-lru"
	"github.com/sirupsen/logrus"
)

// ProcessManager maintains a cache of processes from fgs exec events.
type ProcessManager struct {
	log   logrus.FieldLogger
	cache *lru.Cache
	// pidMap is a map from PID to the most recent exec ID for the PID. This is used to find the parent
	// of exec events without clone flag.
	pidMap   map[uint32]string
	encoder  *json.Encoder
	nodeName string
	watcher  K8sResourceWatcher
}

// NewProcessManager returns a pointer to an initialized ProcessManager struct.
func NewProcessManager(
	log logrus.FieldLogger,
	encoder *json.Encoder,
	processCacheSize int,
	watcher K8sResourceWatcher,
) (*ProcessManager, error) {
	processCache, err := lru.New(processCacheSize)
	if err != nil {
		return nil, err
	}
	return &ProcessManager{
		log:      log,
		cache:    processCache,
		pidMap:   make(map[uint32]string),
		encoder:  encoder,
		nodeName: os.Getenv("NODE_NAME"),
		watcher:  watcher,
	}, nil
}

func (pm *ProcessManager) handleTCPMessage(msg *api.MsgIPv4TcpConnectUnix) *fgs.GetEventsResponse {
	var res *fgs.GetEventsResponse
	switch msg.Common.Op {
	case api.MSG_OP_IPV4_TCPCONNECTRET:
		res = &fgs.GetEventsResponse{
			Event:    &fgs.GetEventsResponse_ProcessConnect{ProcessConnect: pm.GetProcessConnect(msg)},
			NodeName: pm.nodeName,
			Time:     ktimeToProto(msg.Pid.Curr.Ktime),
		}
	case api.MSG_OP_IPV4_LISTEN:
		res = &fgs.GetEventsResponse{
			Event:    &fgs.GetEventsResponse_ProcessListen{ProcessListen: pm.GetProcessListen(msg)},
			NodeName: pm.nodeName,
			Time:     ktimeToProto(msg.Pid.Curr.Ktime),
		}
	case api.MSG_OP_EXECVE:
		proc := pm.Add(msg)
		res = &fgs.GetEventsResponse{
			Event:    &fgs.GetEventsResponse_ProcessExec{ProcessExec: pm.GetProcessExec(proc)},
			NodeName: pm.nodeName,
			Time:     ktimeToProto(msg.Pid.Curr.Ktime),
		}
	default:
		pm.log.WithField("message", msg).Warn("Unhandled event")
	}
	return res
}

// Notify implements Listener.Notify.
func (pm *ProcessManager) Notify(event interface{}) error {
	var processedEvent interface{}
	switch msg := event.(type) {
	case *api.MsgIPv4TcpConnectUnix:
		processedEvent = pm.handleTCPMessage(msg)
	default:
		processedEvent = event
	}
	metrics.ProcessEvent(processedEvent)
	if processedEvent != nil {
		if err := pm.encoder.Encode(processedEvent); err != nil {
			pm.log.WithError(err).WithField("msg", processedEvent).Warn("failed to encode")
		}
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

func (pm *ProcessManager) getProcess(
	process fgsAPI.MsgExecUnix,
	containerID string,
	parent fgsAPI.MsgExecUnix,
) *fgs.Process {
	args, cwd := reader.ArgsDecoder(process.Args, process.Flags)
	var parentExecID string
	var err error
	if parent.PID != 0 {
		if parentExecID, err = pm.GetExecID(&parent); err != nil {
			pm.log.WithError(err).WithField("parent", parent).Warn("Failed to get exec ID for parent")
		}
	}
	execID, err := pm.GetExecID(&process)
	if err != nil {
		pm.log.WithError(err).WithField("process", process).Warn("Failed to get exec ID for process")
	}
	return &fgs.Process{
		Pid:          &wrappers.UInt32Value{Value: process.PID},
		Uid:          &wrappers.UInt32Value{Value: process.UID},
		Cwd:          cwd,
		Binary:       process.Filename,
		Arguments:    args,
		Flags:        reader.DecodeCommonFlags(process.Flags),
		StartTime:    ktimeToProto(process.Ktime),
		Auid:         &wrappers.UInt32Value{Value: process.AUID},
		Pod:          pm.getPodInfo(containerID, &process),
		ExecId:       execID,
		ParentExecId: parentExecID,
	}
}

// Add converts an FGS exec event to protobuf format and adds the protobuf message to the cache.
func (pm *ProcessManager) Add(event *fgsAPI.MsgIPv4TcpConnectUnix) *fgs.Process {
	proc := pm.getProcess(event.Pid.Curr, event.Kube.Docker, event.Pid.Parent)
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
		pm.log.WithFields(logrus.Fields{
			"parent exec id": parentExecID,
			"process":        proc,
		}).Warn("parent not found in cache")
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

// GetExecID returns the exec ID of a given process.
func (pm *ProcessManager) GetExecID(proc *fgsAPI.MsgExecUnix) (string, error) {
	builder := strings.Builder{}
	encoder := base64.NewEncoder(base64.StdEncoding, &builder)
	if _, err := encoder.Write([]byte(fmt.Sprintf("%s:%d:%d", pm.nodeName, proc.Ktime, proc.PID))); err != nil {
		return "", err
	}
	if err := encoder.Close(); err != nil {
		return "", err
	}
	return builder.String(), nil
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
	}
	return &fgs.ProcessExec{
		Process:   proc,
		Parent:    parent,
		Ancestors: ancestors,
	}
}

// GetProcessListen returns Listen protobuf message for a given process, including the ancestor list.
func (pm *ProcessManager) GetProcessListen(
	event *fgsAPI.MsgIPv4TcpConnectUnix,
) *fgs.ProcessListen {
	var port *wrappers.UInt32Value
	if event.Tuple.SPort != 0 {
		port = &wrappers.UInt32Value{
			Value: uint32(reader.GetSport(event.Tuple.SPort)),
		}
	}
	return &fgs.ProcessListen{
		Process: pm.getProcess(event.Pid.Curr, event.Kube.Docker, event.Pid.Parent),
		Parent:  pm.getProcess(event.Pid.Parent, "" /* no container ID for parent */, fgsAPI.MsgExecUnix{} /* no exec info for parent of parent */),
		Ip:      reader.GetIP(event.Tuple.SAddr, event.Common.Op).String(),
		Port:    port,
	}
}

// GetProcessConnect converts KprobeEvent from hubble-fgs to protobuf message.
func (pm *ProcessManager) GetProcessConnect(event *fgsAPI.MsgIPv4TcpConnectUnix) *fgs.ProcessConnect {
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
	return &fgs.ProcessConnect{
		Process:         pm.getProcess(event.Pid.Curr, event.Kube.Docker, event.Pid.Parent),
		Parent:          pm.getProcess(event.Pid.Parent, "" /* no container ID for parent */, fgsAPI.MsgExecUnix{} /* no exec info for parent of parent */),
		SourceIp:        reader.GetIP(event.Tuple.SAddr, event.Common.Op).String(),
		SourcePort:      sourcePort,
		DestinationIp:   reader.GetIP(event.Tuple.DAddr, event.Common.Op).String(),
		DestinationPort: destinationPort,
	}
}

func (pm *ProcessManager) getPodInfo(containerID string, process *fgsAPI.MsgExecUnix) *fgs.Pod {
	if containerID == "" {
		return nil
	}
	pod, container, ok := pm.watcher.FindPod(containerID)
	if !ok {
		pm.log.WithField("container id", containerID).Trace("failed to get pod")
		return nil
	}
	var startTime *timestamp.Timestamp
	var err error
	if container.State.Running != nil {
		if startTime, err = ptypes.TimestampProto(container.State.Running.StartedAt.Time); err != nil {
			pm.log.WithField("container", container).Warn("failed to convert start time")
		}
	}
	// Don't set container PIDs if it's zero.
	var containerPID *wrappers.UInt32Value
	if process.NSPID > 0 {
		containerPID = &wrappers.UInt32Value{
			Value: process.NSPID,
		}
	}
	return &fgs.Pod{
		Namespace: pod.Namespace,
		Name:      pod.Name,
		Container: &fgs.Container{
			Id:   container.ContainerID,
			Pid:  containerPID,
			Name: container.Name,
			Image: &fgs.Image{
				Id:   container.ImageID,
				Name: container.Image,
			},
			StartTime: startTime,
		},
	}
}

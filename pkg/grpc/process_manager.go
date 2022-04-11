//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package grpc

import (
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	v1 "github.com/cilium/hubble/pkg/api/v1"
	"github.com/cilium/hubble/pkg/cilium"
	"github.com/isovalent/hubble-fgs/api/v1/fgs"
	"github.com/isovalent/hubble-fgs/pkg/api"
	fgsAPI "github.com/isovalent/hubble-fgs/pkg/api"
	"github.com/isovalent/hubble-fgs/pkg/filters"
	"github.com/isovalent/hubble-fgs/pkg/logger"
	"github.com/isovalent/hubble-fgs/pkg/metrics"
	"github.com/isovalent/hubble-fgs/pkg/reader"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"
	coreV1 "k8s.io/api/core/v1"
)

var hostNamespace *fgs.Namespaces

type listener interface {
	notify(res *fgs.GetEventsResponse)
}

type notifier interface {
	addListener(listener listener)
	removeListener(listener listener)
}

// ProcessManager maintains a cache of processes from fgs exec events.
type ProcessManager struct {
	log        logrus.FieldLogger
	cache      *processCache
	eventCache *eventCache
	nodeName   string
	watcher    K8sResourceWatcher
	// synchronize access to the listeners map.
	mux                    sync.Mutex
	listeners              map[listener]struct{}
	ciliumState            *cilium.State
	enableProcessCred      bool
	enableProcessNs        bool
	enableEventCache       bool
	enableCilium           bool
	enableProcessAncestors bool
	dns                    *dnsCache
}

// getNodeNameForExport returns node name string for JSON export. It uses NODE_NAME
// env variable by default, which is also used by k8s watcher to watch for local pods:
//
//   https://github.com/isovalent/hubble-fgs/blob/a7be620c9fecdc2b693e3633506aca35d46cd3b2/pkg/grpc/watcher.go#L32
//
// Set HUBBLE_NODE_NAME to override the node_name field for JSON export.
func getNodeNameForExport() string {
	nodeName := os.Getenv("HUBBLE_NODE_NAME")
	if nodeName != "" {
		return nodeName
	}
	return os.Getenv("NODE_NAME")
}

// NewProcessManager returns a pointer to an initialized ProcessManager struct.
func NewProcessManager(
	log logrus.FieldLogger,
	processCacheSize int,
	watcher K8sResourceWatcher,
	ciliumState *cilium.State,
	enableProcessCred bool,
	enableProcessNs bool,
	enableEventCache bool,
	enableCilium bool,
	enableProcessAncestors bool,
) (*ProcessManager, error) {
	cache, err := newProcessCache(log, processCacheSize)
	if err != nil {
		return nil, err
	}

	dnsCache, err := newDnsCache()
	if err != nil {
		return nil, fmt.Errorf("failed to create DNS cache %w", err)
	}

	pm := &ProcessManager{
		log:                    log,
		cache:                  cache,
		nodeName:               getNodeNameForExport(),
		watcher:                watcher,
		ciliumState:            ciliumState,
		listeners:              make(map[listener]struct{}),
		enableProcessCred:      enableProcessCred,
		enableProcessNs:        enableProcessNs,
		enableEventCache:       enableEventCache,
		enableCilium:           enableCilium,
		enableProcessAncestors: enableProcessAncestors,
		dns:                    dnsCache,
	}

	if enableEventCache {
		pm.eventCache = newEventCache(log, pm)
	}

	pm.log.WithField("enableCilium", enableCilium).WithFields(logrus.Fields{
		"enableEventCache":  enableEventCache,
		"enableProcessCred": enableProcessCred,
		"enableProcessNs":   enableProcessNs,
		"processCacheSize":  processCacheSize,
	}).Info("Starting process manager")
	return pm, nil
}

// We handle two race conditions here one where the event races with
// an FGS execve event and the other -- much more common -- where we
// race with K8s watcher.
// case 1 (execve race):
//  Its possible to receive this FGS event before the process event cache
//  has been populated with a FGS execve event. In this case we need to
//  cache the event until the process cache is populated.
// case 2 (k8s watcher race):
//  Its possible to receive an event before the k8s watcher receives the
//  podInfo event and populates the local cache. If we expect podInfo,
//  indicated by having a nonZero dockerID we cache the event until the
//  podInfo arrives.
func (pm *ProcessManager) processCacheNeeded(proc *fgs.Process) bool {
	return pm.enableEventCache && (proc == nil || (proc.Docker != "" && proc.Pod == nil))
}

func (pm *ProcessManager) handleIpMessage(msg *api.MsgIPv4EventUnix) *fgs.GetEventsResponse {
	var res *fgs.GetEventsResponse
	switch msg.Common.Op {
	case api.MSG_OP_IPV4_TCPCONNECTRET,
		api.MSG_OP_IPV4_UDPCONNECT:
		cnct := pm.GetProcessConnect(msg)
		if cnct != nil {
			res = &fgs.GetEventsResponse{
				Event:    &fgs.GetEventsResponse_ProcessConnect{ProcessConnect: cnct},
				NodeName: pm.nodeName,
				Time:     ktimeToProto(msg.Common.Ktime),
			}
		}
	case api.MSG_OP_IPV4_TCPCLOSE,
		api.MSG_OP_IPV4_UDPCLOSE:
		c := pm.GetProcessClose(msg)
		if c != nil {
			res = &fgs.GetEventsResponse{
				Event:    &fgs.GetEventsResponse_ProcessClose{ProcessClose: c},
				NodeName: pm.nodeName,
				Time:     ktimeToProto(msg.Common.Ktime),
			}
		}
	case api.MSG_OP_IPV4_LISTEN:
		l := pm.GetProcessListen(msg)
		if l != nil {
			res = &fgs.GetEventsResponse{
				Event:    &fgs.GetEventsResponse_ProcessListen{ProcessListen: l},
				NodeName: pm.nodeName,
				Time:     ktimeToProto(msg.Common.Ktime),
			}
		}
	case api.MSG_OP_IPV4_ACCEPT:
		a := pm.GetProcessAccept(msg)
		if a != nil {
			res = &fgs.GetEventsResponse{
				Event:    &fgs.GetEventsResponse_ProcessAccept{ProcessAccept: a},
				NodeName: pm.nodeName,
				Time:     ktimeToProto(msg.Common.Ktime),
			}
		}

	case api.MSG_OP_IPV4_TCPSTATS, api.MSG_OP_IPV4_UDPSTATS:
		s := pm.GetProcessSockStats(msg)
		if s != nil {
			res = &fgs.GetEventsResponse{
				Event:    &fgs.GetEventsResponse_ProcessSockstats{ProcessSockstats: s},
				NodeName: pm.nodeName,
				Time:     ktimeToProto(msg.Common.Ktime),
			}
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
	case *api.MsgFGSReady:
		// pass
	case *api.MsgTLSEventUnix:
		processedEvent = pm.handleTLSMessage(msg)
	case *api.MsgHttpEventUnix:
		processedEvent = pm.handleHttpMessage(msg)
	case *api.MsgExecveEventUnix:
		processedEvent = pm.handleExecveMessage(msg)
	case *api.MsgIPv4EventUnix:
		processedEvent = pm.HandleIpMessage(msg)
	case *api.MsgProcessNetworkBurstEventUnix:
		processedEvent = pm.handleProcessNetworkBurstMessage(msg)
	case *api.MsgInterfaceEventUnix:
		processedEvent = pm.handleInterfaceMessage(msg)
	case *api.MsgIPv4DnsUnix:
		processedEvent = pm.handleDnsMessage(msg)
	case *api.MsgExitEventUnix:
		processedEvent = pm.handleExitMessage(msg)
	case *api.MsgCredEventUnix:
		processedEvent = pm.handleCredMessage(msg)
	case *api.MsgKfreeSkbUnix:
		processedEvent = pm.handleKfreeSkbMessage(msg)
	case *api.MsgGenericKprobeUnix:
		processedEvent = pm.handleGenericKprobeMessage(msg)
	case *api.MsgGenericTracepointUnix:
		processedEvent = pm.handleGenericTracepointMessage(msg)
	case *api.MsgTestEventUnix:
		processedEvent = pm.handleTestMessage(msg)

	default:
		pm.log.WithField("event", event).Warnf("unhandled event of type %T", msg)
		metrics.ErrorCount.WithLabelValues(string(metrics.UnhandledEvent)).Inc()
		return nil
	}
	if processedEvent != nil {
		pm.notifyListeners(event, processedEvent)
	}
	return nil
}

// Close implements Listener.Close.
func (pm *ProcessManager) Close() error {
	return nil
}

func ktimeToProto(ktime uint64) *timestamppb.Timestamp {
	return ktimeToProtoOpt(ktime, true)
}

func ktimeToProtoOpt(ktime uint64, monotonic bool) *timestamppb.Timestamp {
	decodedTime, err := reader.DecodeKtime(int64(ktime), monotonic)
	if err != nil {
		logrus.WithError(err).WithField("ktime", ktime).Warn("Failed to decode ktime")
		return timestamppb.Now()
	}
	return timestamppb.New(decodedTime)
}

func (pm *ProcessManager) getParentProcessInternal(pid uint32, ktime uint64) (*ProcessInternal, *ProcessInternal) {
	var parent, process *ProcessInternal
	var err error

	processID := pm.GetProcessID(pid, ktime)

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

func createHostNs(ns string) *fgs.Namespace {
	return &fgs.Namespace{
		Inum:   reader.GetPidNsInode(1, ns),
		IsHost: true,
	}
}

func getHostNamespace() *fgs.Namespaces {
	if hostNamespace == nil {
		hostNamespace = &fgs.Namespaces{
			Uts:             createHostNs("uts"),
			Ipc:             createHostNs("ipc"),
			Mnt:             createHostNs("mnt"),
			Pid:             createHostNs("pid"),
			PidForChildren:  createHostNs("pid_for_children"),
			Net:             createHostNs("net"),
			Time:            createHostNs("time"),
			TimeForChildren: createHostNs("time_for_children"),
			Cgroup:          createHostNs("cgroup"),
			User:            createHostNs("user"),
		}
	}
	return hostNamespace
}

func (pm *ProcessManager) getNamespaces(ns fgsAPI.MsgNamespaces) *fgs.Namespaces {
	hostNs := getHostNamespace()
	retVal := &fgs.Namespaces{
		Uts: &fgs.Namespace{
			Inum:   ns.UtsInum,
			IsHost: hostNs.Uts.Inum == ns.UtsInum,
		},
		Ipc: &fgs.Namespace{
			Inum:   ns.IpcInum,
			IsHost: hostNs.Ipc.Inum == ns.IpcInum,
		},
		Mnt: &fgs.Namespace{
			Inum:   ns.MntInum,
			IsHost: hostNs.Mnt.Inum == ns.MntInum,
		},
		Pid: &fgs.Namespace{
			Inum:   ns.PidInum,
			IsHost: hostNs.Pid.Inum == ns.PidInum,
		},
		PidForChildren: &fgs.Namespace{
			Inum:   ns.PidChildInum,
			IsHost: hostNs.PidForChildren.Inum == ns.PidChildInum,
		},
		Net: &fgs.Namespace{
			Inum:   ns.NetInum,
			IsHost: hostNs.Net.Inum == ns.NetInum,
		},
		Time: &fgs.Namespace{
			Inum:   ns.TimeInum,
			IsHost: hostNs.Time.Inum == ns.TimeInum,
		},
		TimeForChildren: &fgs.Namespace{
			Inum:   ns.TimeChildInum,
			IsHost: hostNs.TimeForChildren.Inum == ns.TimeChildInum,
		},
		Cgroup: &fgs.Namespace{
			Inum:   ns.CgroupInum,
			IsHost: hostNs.Cgroup.Inum == ns.CgroupInum,
		},
		User: &fgs.Namespace{
			Inum:   ns.UserInum,
			IsHost: hostNs.User.Inum == ns.UserInum,
		},
	}

	// this kernel does not support time namespace
	if retVal.Time.Inum == 0 {
		retVal.Time = nil
		retVal.TimeForChildren = nil
	}

	return retVal
}

func getBinaryAbsolutePath(binary string, cwd string) string {
	if filepath.IsAbs(binary) {
		return binary
	}
	return filepath.Join(cwd, binary)
}

func (pm *ProcessManager) getProcess(
	process fgsAPI.MsgProcess,
	containerID string,
	parent fgsAPI.MsgExecveKey,
	capabilities fgsAPI.MsgCapabilities,
	namespaces fgsAPI.MsgNamespaces,
) (*ProcessInternal, *v1.Endpoint) {
	args, cwd := reader.ArgsDecoder(process.Args, process.Flags)
	var parentExecID string
	if parent.Pid != 0 {
		parentExecID = pm.GetExecIDFromKey(&parent)
	}
	execID := pm.GetExecID(&process)
	protoPod, endpoint := pm.getPodInfo(containerID, process.Filename, args, process.NSPID)
	caps := pm.getCapabilities(capabilities)
	ns := pm.getNamespaces(namespaces)
	return &ProcessInternal{
		process: &fgs.Process{
			Pid:          &wrapperspb.UInt32Value{Value: process.PID},
			Uid:          &wrapperspb.UInt32Value{Value: process.UID},
			Cwd:          reader.MarkUnresolvedPathComponentsCwd(cwd, process.Flags),
			Binary:       getBinaryAbsolutePath(process.Filename, cwd),
			Arguments:    args,
			Flags:        strings.Join(reader.DecodeCommonFlags(process.Flags), " "),
			StartTime:    ktimeToProtoOpt(process.Ktime, (process.Flags&api.EventProcFS) == 0),
			Auid:         &wrapperspb.UInt32Value{Value: process.AUID},
			Pod:          protoPod,
			ExecId:       execID,
			Docker:       containerID,
			ParentExecId: parentExecID,
			Refcnt:       0,
		},
		capabilities: caps,
		namespaces:   ns,
		refcnt:       1,
	}, endpoint
}

// Add converts an FGS exec event to protobuf format and adds the protobuf message to the cache.
func (pm *ProcessManager) Add(event *fgsAPI.MsgExecveEventUnix) *ProcessInternal {
	proc, _ := pm.getProcess(event.Process, event.Kube.Docker, event.Parent, event.Capabilities, event.Namespaces)
	pm.cache.add(proc)
	var parentExecID string
	if proc.process.Pid != nil {
		parentExecID = pm.cache.getFromPidMap(proc.process.Pid.Value)
		pm.cache.addToPidMap(proc.process.Pid.Value, proc.process.ExecId)
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
func (pm *ProcessManager) getAncestors(proc *fgs.Process) []*ProcessInternal {
	var ancestors []*ProcessInternal
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

func (pm *ProcessManager) GetProcessID(pid uint32, ktime uint64) string {
	return base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%d:%d", pm.nodeName, ktime, pid)))
}

// GetExecID returns the exec ID of a given process.
func (pm *ProcessManager) GetExecID(proc *fgsAPI.MsgProcess) string {
	return pm.GetProcessID(proc.PID, proc.Ktime)
}

func (pm *ProcessManager) GetExecIDFromKey(key *fgsAPI.MsgExecveKey) string {
	return pm.GetProcessID(key.Pid, key.Ktime)
}

func (pm *ProcessManager) getPodInfoOfIp(ip net.IP) *fgs.Pod {
	ipcacheEntry, ok := pm.ciliumState.GetIPCache().GetIPIdentity(ip)
	if !ok {
		return nil
	}
	return &fgs.Pod{
		Namespace: ipcacheEntry.Namespace,
		Name:      ipcacheEntry.PodName,
		Labels:    nil,
		Container: nil,
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
	var startTime *timestamppb.Timestamp
	livenessProbe, readinessProbe := getProbes(pod, container)
	maybeExecProbe := filters.MaybeExecProbe(binary, args, livenessProbe) ||
		filters.MaybeExecProbe(binary, args, readinessProbe)
	if container.State.Running != nil {
		startTime = timestamppb.New(container.State.Running.StartedAt.Time)
	}
	endpoint, ok := pm.ciliumState.GetEndpointsHandler().GetEndpointByPodName(pod.Namespace, pod.Name)
	var labels []string
	if ok {
		labels = endpoint.Labels
	}

	// Don't set container PIDs if it's zero.
	var containerPID *wrapperspb.UInt32Value
	if nspid > 0 {
		containerPID = &wrapperspb.UInt32Value{
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

func (pm *ProcessManager) notifyListeners(original interface{}, processed *fgs.GetEventsResponse) {
	pm.mux.Lock()
	defer pm.mux.Unlock()
	for l := range pm.listeners {
		l.notify(processed)
	}
	metrics.ProcessEvent(original, processed)
}

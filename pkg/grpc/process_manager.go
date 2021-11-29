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
package grpc

import (
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

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
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"
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
	log        logrus.FieldLogger
	cache      *processCache
	eventCache *eventCache
	nodeName   string
	watcher    K8sResourceWatcher
	// synchronize access to the listeners map.
	mux               sync.Mutex
	listeners         map[listener]struct{}
	ciliumState       *cilium.State
	enableProcessCred bool
	enableEventCache  bool
	enableCilium      bool
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
	enableEventCache bool,
	enableCilium bool,
) (*ProcessManager, error) {
	cache, err := newProcessCache(log, processCacheSize)
	if err != nil {
		return nil, err
	}
	pm := &ProcessManager{
		log:               log,
		cache:             cache,
		nodeName:          getNodeNameForExport(),
		watcher:           watcher,
		ciliumState:       ciliumState,
		listeners:         make(map[listener]struct{}),
		enableProcessCred: enableProcessCred,
		enableEventCache:  enableEventCache,
		enableCilium:      enableCilium,
	}

	if enableEventCache {
		pm.eventCache = newEventCache(log, pm)
	}
	pm.log.WithField("enableCilium", enableCilium).WithFields(logrus.Fields{
		"enableEventCache":  enableEventCache,
		"enableProcessCred": enableProcessCred,
		"processCacheSize":  processCacheSize,
	}).Info("Starting process manager")
	return pm, nil
}

func (pm *ProcessManager) handleTLSMessage(msg *api.MsgTLSEventUnix) *fgs.GetEventsResponse {
	var res *fgs.GetEventsResponse
	switch msg.Common.Op {
	case api.MSG_OP_TLS:
		t := pm.GetTLS(msg)
		if t != nil {
			res = &fgs.GetEventsResponse{
				Event:    &fgs.GetEventsResponse_Tls{Tls: t},
				NodeName: pm.nodeName,
				Time:     ktimeToProto(msg.Common.Ktime),
			}
		}
	default:
		pm.log.WithField("message", msg).Warn("Unhandled event")
	}
	return res
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

func (pm *ProcessManager) GetHttp(event *fgsAPI.MsgHttpEventUnix) *fgs.ProcessHttp {
	var proc *fgs.Process
	var code uint32

	fgsHttpResponse := &fgs.HttpResponse{}
	fgsHttpRequest := &fgs.HttpRequest{}

	processID := pm.GetProcessID(event.ProcessKey.Pid, event.ProcessKey.Ktime)
	processInt, err := pm.cache.get(processID)
	if err != nil {
		pm.log.WithField("id in HTTP event", processID).Debug("process not found in cache")
	} else {
		proc = processInt.process

	}
	fgsTuple := pm.__getProcessTuple(&event.Tuple, 0, event.Common.Op)

	if len(event.Request.Code) != 0 {
		code, err = reader.GetHttpCode(event.Request.Code)
		if err != nil {
			pm.log.WithField("Unknown Response Code", event.Request.Code).Info("unknown code")
		}

		length, err := reader.GetHttpContentLength(event.Request.RespContentLength)
		if err != nil {
			pm.log.WithError(err).WithField("RespContentLength", event.Request.RespContentLength).Info("Response Content-Length strconv error")
		}

		fgsHttpResponse = &fgs.HttpResponse{
			Timestamp:     ktimeToProto(event.Common.Ktime),
			Version:       event.Request.RespVersion,
			Code:          code,
			Reason:        event.Request.Reason,
			ContentLength: &wrapperspb.UInt32Value{Value: uint32(length)},
			Flags:         strings.Join(reader.HttpErrorFlags(event.Request.FlagsResponse), " "),
		}
	}

	length, err := reader.GetHttpContentLength(event.Request.ContentLength)
	if err != nil {
		pm.log.WithError(err).WithField("ContentLength", event.Request.ContentLength).Info("Request Content-Length strconv error")
	}

	if len(event.Request.Method) != 0 {
		fgsHttpRequest = &fgs.HttpRequest{
			Timestamp:     ktimeToProto(event.Request.Ktime),
			Method:        event.Request.Method,
			Uri:           event.Request.Uri,
			Version:       event.Request.Protocol,
			Host:          event.Request.Host,
			Agent:         event.Request.UserAgent,
			ContentLength: &wrapperspb.UInt32Value{Value: uint32(length)},
			Flags:         strings.Join(reader.HttpErrorFlags(event.Request.Flags), " "),
		}
	}

	fgsHttp := &fgs.HttpInfo{
		Request:  fgsHttpRequest,
		Response: fgsHttpResponse,
	}

	if len(event.Request.Code) != 0 &&
		len(event.Request.Method) != 0 {
		l := reader.DiffKtime(event.Request.Ktime, event.Common.Ktime)
		nano := l.Nanoseconds()
		sec := nano / int64(time.Second)
		remainder := nano % int64(time.Second)
		fgsHttp.Latency = &durationpb.Duration{
			Seconds: sec,
			Nanos:   int32(remainder),
		}
	}

	fgsEvent := &fgs.ProcessHttp{
		Process: proc,
		Socket:  fgsTuple,
		Http:    fgsHttp,
	}

	// When CiliumAPI is enable annotate data with Cilium info. If the data
	// is missing and enableEventCache is enabled we push event into the
	// cache where a retry will happen.
	if pm.enableCilium && proc != nil {
		destinationIP := reader.GetIP(event.Tuple.DAddr, api.MSG_OP_HTTP)
		endpoint := pm.getProcessEndpoint(proc)
		if endpoint != nil {
			fgsEvent.DestinationNames = pm.ciliumState.GetFQDNCache().GetNamesOf(endpoint.ID, destinationIP)
			fgsEvent.DestinationPod = pm.getPodInfoOfIp(destinationIP)
		} else if pm.enableEventCache {
			pm.eventCache.add(fgsEvent, ktimeToProto(event.Common.Ktime), event)
			return nil
		}
	}
	if pm.processCacheNeeded(proc) {
		pm.eventCache.add(fgsEvent, ktimeToProto(event.Common.Ktime), event)
		return nil
	}
	return fgsEvent
}

func (pm *ProcessManager) handleHttpMessage(msg *api.MsgHttpEventUnix) *fgs.GetEventsResponse {
	var res *fgs.GetEventsResponse
	switch msg.Common.Op {
	case api.MSG_OP_HTTP:
		t := pm.GetHttp(msg)
		if t != nil {
			res = &fgs.GetEventsResponse{
				Event:    &fgs.GetEventsResponse_ProcessHttp{ProcessHttp: t},
				NodeName: pm.nodeName,
				Time:     ktimeToProto(msg.Common.Ktime),
			}
		}
	default:
		pm.log.WithField("message", msg).Warn("Unhandled event")
	}
	return res
}

func (pm *ProcessManager) GetDns(event *fgsAPI.MsgIPv4DnsUnix) *fgs.ProcessDns {
	var proc *fgs.Process

	processID := pm.GetProcessID(event.ProcessKey.Pid, event.ProcessKey.Ktime)
	processInt, err := pm.cache.get(processID)
	if err != nil {
		pm.log.WithField("id in DNS event", processID).Debug("process not found in cache")
	} else {
		proc = processInt.process

	}
	fgsTuple := pm.__getProcessTuple(&event.Tuple, 0, event.Common.Op)

	fgsDns := &fgs.DnsInfo{
		Rcode:         int32(event.Dns.RCode),
		Ips:           event.Dns.IPs,
		Names:         event.Dns.Names,
		QuestionTypes: event.Dns.QuestionTypes,
		AnswerTypes:   event.Dns.AnswerTypes,
	}

	fgsEvent := &fgs.ProcessDns{
		Process: proc,
		Socket:  fgsTuple,
		Dns:     fgsDns,
	}

	// When CiliumAPI is enable annotate data with Cilium info. If the data
	// is missing and enableEventCache is enabled we push event into the
	// cache where a retry will happen.
	if pm.enableCilium && proc != nil {
		destinationIP := reader.GetIP(event.Tuple.DAddr, api.MSG_OP_IPV4_DNS)
		endpoint := pm.getProcessEndpoint(proc)
		if endpoint != nil {
			fgsEvent.DestinationNames = pm.ciliumState.GetFQDNCache().GetNamesOf(endpoint.ID, destinationIP)
			fgsEvent.DestinationPod = pm.getPodInfoOfIp(destinationIP)
		} else if pm.enableEventCache {
			pm.eventCache.add(fgsEvent, ktimeToProto(event.Common.Ktime), event)
			return nil
		}
	}
	if pm.processCacheNeeded(proc) {
		pm.eventCache.add(fgsEvent, ktimeToProto(event.Common.Ktime), event)
		return nil
	}
	return fgsEvent
}

func (pm *ProcessManager) handleDnsMessage(msg *api.MsgIPv4DnsUnix) *fgs.GetEventsResponse {
	var res *fgs.GetEventsResponse
	switch msg.Common.Op {
	case api.MSG_OP_IPV4_DNS:
		t := pm.GetDns(msg)
		if t != nil {
			res = &fgs.GetEventsResponse{
				Event:    &fgs.GetEventsResponse_ProcessDns{ProcessDns: t},
				NodeName: pm.nodeName,
				Time:     ktimeToProto(msg.Common.Ktime),
			}
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
		procEvent := pm.GetProcessExec(proc)
		if pm.processCacheNeeded(procEvent.Process) {
			pm.eventCache.addProc(procEvent, ktimeToProto(msg.Common.Ktime), msg)
		} else {
			res = &fgs.GetEventsResponse{
				Event:    &fgs.GetEventsResponse_ProcessExec{ProcessExec: procEvent},
				NodeName: pm.nodeName,
				Time:     ktimeToProto(msg.Common.Ktime),
			}
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
		e := pm.GetProcessExit(msg)
		if e != nil {
			res = &fgs.GetEventsResponse{
				Event:    &fgs.GetEventsResponse_ProcessExit{ProcessExit: e},
				NodeName: pm.nodeName,
				Time:     ktimeToProto(msg.Common.Ktime),
			}
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
		event := pm.GetProcessCred(msg)
		if event != nil {
			res = &fgs.GetEventsResponse{
				Event:    &fgs.GetEventsResponse_ProcessCred{ProcessCred: event},
				NodeName: pm.nodeName,
				Time:     ktimeToProto(msg.Common.Ktime),
			}
		}
	default:
		pm.log.WithField("message", msg).Warn("Unhandled event")
	}
	return res
}

func (pm *ProcessManager) handleKfreeSkbMessage(msg *api.MsgKfreeSkbUnix) *fgs.GetEventsResponse {
	var res *fgs.GetEventsResponse
	switch msg.Common.Op {
	case api.MSG_OP_KFREE_SKB:
		pm.log.Warn("TODO: handle kfree_skb message")

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
			Event: &fgs.GetEventsResponse_Test{Test: &fgs.Test{
				Arg0: msg.Arg0,
				Arg1: msg.Arg1,
				Arg2: msg.Arg2,
				Arg3: msg.Arg3,
			}},
			NodeName: pm.nodeName,
			Time:     ktimeToProto(msg.Common.Ktime),
		}
	default:
		pm.log.WithField("message", msg).Warn("Unhandled event")
	}
	return res
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
	case api.MSG_OP_IPV4_TCPCLOSE:
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

func (pm *ProcessManager) GetProcessKprobe(event *api.MsgGenericKprobeUnix) *fgs.ProcessKprobe {
	var fgsParent, fgsProcess *fgs.Process
	var fgsArgs []*fgs.KprobeArgument
	var fgsReturnArg *fgs.KprobeArgument

	process, parent := pm.getParentProcessInternal(event.ProcessKey.Pid, event.ProcessKey.Ktime)
	if process == nil {
		fgsProcess = &fgs.Process{
			Pid:       &wrapperspb.UInt32Value{Value: event.ProcessKey.Pid},
			StartTime: ktimeToProto(event.ProcessKey.Ktime),
		}
	} else {
		fgsProcess = process.process
	}
	if parent == nil {
		fgsParent = &fgs.Process{}
	} else {
		fgsParent = parent.process
	}

	for _, arg := range event.Args {
		a := &fgs.KprobeArgument{}
		switch e := arg.(type) {
		case api.MsgGenericKprobeArgInt:
			a.Arg = &fgs.KprobeArgument_IntArg{IntArg: e.Value}
		case api.MsgGenericKprobeArgSize:
			a.Arg = &fgs.KprobeArgument_SizeArg{SizeArg: e.Value}
		case api.MsgGenericKprobeArgString:
			a.Arg = &fgs.KprobeArgument_StringArg{StringArg: e.Value}
		case api.MsgGenericKprobeArgSock:
			sockArg := &fgs.KprobeSock{
				Family:   reader.InetFamily(e.Family),
				Type:     reader.InetType(e.Type),
				Protocol: reader.InetProtocol(e.Protocol),
				Mark:     e.Mark,
				Priority: e.Priority,
			}
			a.Arg = &fgs.KprobeArgument_SockArg{SockArg: sockArg}
		case api.MsgGenericKprobeArgSkb:
			skbArg := &fgs.KprobeSkb{
				Hash:        e.Hash,
				Len:         e.Len,
				Priority:    e.Priority,
				Mark:        e.Mark,
				Saddr:       e.Saddr,
				Daddr:       e.Daddr,
				Sport:       e.Sport,
				Dport:       e.Dport,
				Proto:       e.Proto,
				SecPathLen:  e.SecPathLen,
				SecPathOlen: e.SecPathOLen,
			}
			a.Arg = &fgs.KprobeArgument_SkbArg{SkbArg: skbArg}
		case api.MsgGenericKprobeArgBytes:
			if e.OrigSize > uint64(len(e.Value)) {
				a.Arg = &fgs.KprobeArgument_TruncatedBytesArg{&fgs.KprobeTruncatedBytes{
					OrigSize: e.OrigSize,
					BytesArg: e.Value,
				}}
			} else {
				a.Arg = &fgs.KprobeArgument_BytesArg{BytesArg: e.Value}
			}
		case api.MsgGenericKprobeArgFile:
			fileArg := &fgs.KprobeFile{
				Path: strings.TrimSuffix(reader.SwapPath(e.Value), "/"),
			}
			a.Arg = &fgs.KprobeArgument_FileArg{FileArg: fileArg}
		case api.MsgGenericKprobeArgPath:
			pathArg := &fgs.KprobePath{
				Path: reader.SwapPath(e.Value),
			}
			a.Arg = &fgs.KprobeArgument_PathArg{PathArg: pathArg}
		default:
			pm.log.WithField("arg", e).Warnf("unexpected type: %T", e)
		}
		if arg.IsReturnArg() {
			fgsReturnArg = a
		} else {
			fgsArgs = append(fgsArgs, a)
		}
	}

	fgsEvent := &fgs.ProcessKprobe{
		Process:      fgsProcess,
		Parent:       fgsParent,
		FunctionName: event.FuncName,
		Args:         fgsArgs,
		Return:       fgsReturnArg,
		Action:       reader.KprobeAction(event.Action),
	}

	if pm.processCacheNeeded(fgsProcess) {
		pm.eventCache.add(fgsEvent, ktimeToProto(event.Common.Ktime), event)
		return nil
	}
	return fgsEvent
}

func (pm *ProcessManager) GetInterfaceStats(msg *api.MsgInterfaceEventUnix) *fgs.InterfaceStats {
	fgsEvent := &fgs.InterfaceStats{
		InterfaceName:    msg.Iface.Name,
		InterfaceIfindex: uint32(msg.Iface.Index),
		BytesSent:        msg.Stats.BytesSent,
		BytesReceived:    msg.Stats.BytesReceived,
		PacketsSent:      msg.Stats.PacketsSent,
		PacketsReceived:  msg.Stats.PacketsReceived,
		TxErrors:         msg.Stats.TxErrors,
		RxErrors:         msg.Stats.RxErrors,
		TxDrops:          msg.Stats.TxDrops,
		RxDrops:          msg.Stats.RxDrops,
	}
	return fgsEvent
}

func (pm *ProcessManager) handleInterfaceMessage(msg *api.MsgInterfaceEventUnix) *fgs.GetEventsResponse {
	var res *fgs.GetEventsResponse
	switch msg.Common.Op {
	case api.MSG_OP_INTERFACE_STATS:
		stats := pm.GetInterfaceStats(msg)
		if stats != nil {
			res = &fgs.GetEventsResponse{
				Event:    &fgs.GetEventsResponse_InterfaceStats{InterfaceStats: stats},
				NodeName: pm.nodeName,
				Time:     ktimeToProto(msg.Common.Ktime),
			}
		}
	default:
		pm.log.WithField("message", msg).Warn("Unhandled event")
	}
	return res
}

func (pm *ProcessManager) handleGenericKprobeMessage(msg *api.MsgGenericKprobeUnix) *fgs.GetEventsResponse {
	k := pm.GetProcessKprobe(msg)
	if k == nil {
		return nil
	}
	return &fgs.GetEventsResponse{
		Event:    &fgs.GetEventsResponse_ProcessKprobe{ProcessKprobe: k},
		NodeName: pm.nodeName,
		Time:     ktimeToProto(msg.Common.Ktime),
	}
}

func (pm *ProcessManager) handleGenericTracepointMessage(msg *api.MsgGenericTracepointUnix) *fgs.GetEventsResponse {
	var fgsParent, fgsProcess *fgs.Process

	process, parent := pm.getParentProcessInternal(msg.ProcessKey.Pid, msg.ProcessKey.Ktime)
	if process == nil {
		fgsProcess = &fgs.Process{
			Pid:       &wrapperspb.UInt32Value{Value: msg.ProcessKey.Pid},
			StartTime: ktimeToProto(msg.ProcessKey.Ktime),
		}
	} else {
		fgsProcess = process.process
	}
	if parent == nil {
		fgsParent = &fgs.Process{}
	} else {
		fgsParent = parent.process
	}

	var fgsArgs []*fgs.KprobeArgument
	for _, arg := range msg.Args {
		switch v := arg.(type) {
		case uint64:
			fgsArgs = append(fgsArgs, &fgs.KprobeArgument{Arg: &fgs.KprobeArgument_SizeArg{
				SizeArg: v,
			}})
		case string:
			fgsArgs = append(fgsArgs, &fgs.KprobeArgument{Arg: &fgs.KprobeArgument_StringArg{
				StringArg: v,
			}})

		case []byte:
			fgsArgs = append(fgsArgs, &fgs.KprobeArgument{Arg: &fgs.KprobeArgument_BytesArg{
				BytesArg: v,
			}})

		default:
			logger.GetLogger().Warnf("handleGenericTracepointMessage: unhandled value: %+v (%T)", arg, arg)
		}
	}

	fgsEvent := &fgs.ProcessTracepoint{
		Process: fgsProcess,
		Parent:  fgsParent,
		Subsys:  msg.Subsys,
		Event:   msg.Event,
		Args:    fgsArgs,
	}

	if pm.processCacheNeeded(fgsProcess) {
		pm.eventCache.add(fgsEvent, ktimeToProto(msg.Common.Ktime), msg)
		return nil
	}

	return &fgs.GetEventsResponse{
		Event:    &fgs.GetEventsResponse_ProcessTracepoint{ProcessTracepoint: fgsEvent},
		NodeName: pm.nodeName,
		Time:     ktimeToProto(msg.Common.Ktime),
	}
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
		processedEvent = pm.handleIpMessage(msg)
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
	decodedTime, err := reader.DecodeKtime(int64(ktime))
	if err != nil {
		logrus.WithError(err).WithField("ktime", ktime).Warn("Failed to decode ktime")
		return timestamppb.Now()
	}
	return timestamppb.New(decodedTime)
}

func (pm *ProcessManager) getParentProcessInternal(pid uint32, ktime uint64) (*processInternal, *processInternal) {
	var parent, process *processInternal
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

func (pm *ProcessManager) getProcessEndpoint(process *fgs.Process) *v1.Endpoint {
	if process == nil {
		return nil
	}
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

func getBinaryAbsolutePath(binary string, cwd string) string {
	if filepath.IsAbs(binary) {
		return binary
	}
	return filepath.Join(cwd, binary)
}

func (pm *ProcessManager) getProcess(
	process fgsAPI.MsgExecUnix,
	containerID string,
	parent fgsAPI.MsgExecveKey,
	capabilities fgsAPI.MsgCapabilities,
) (*processInternal, *v1.Endpoint) {
	args, cwd := reader.ArgsDecoder(process.Args, process.Flags)
	var parentExecID string
	if parent.Pid != 0 {
		parentExecID = pm.GetExecIDFromKey(&parent)
	}
	execID := pm.GetExecID(&process)
	protoPod, endpoint := pm.getPodInfo(containerID, process.Filename, args, process.NSPID)
	caps := pm.getCapabilities(capabilities)
	return &processInternal{
		process: &fgs.Process{
			Pid:          &wrapperspb.UInt32Value{Value: process.PID},
			Uid:          &wrapperspb.UInt32Value{Value: process.UID},
			Cwd:          cwd,
			Binary:       getBinaryAbsolutePath(process.Filename, cwd),
			Arguments:    args,
			Flags:        strings.Join(reader.DecodeCommonFlags(process.Flags), " "),
			StartTime:    ktimeToProto(process.Ktime),
			Auid:         &wrapperspb.UInt32Value{Value: process.AUID},
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

func (pm *ProcessManager) GetProcessID(pid uint32, ktime uint64) string {
	return base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%d:%d", pm.nodeName, ktime, pid)))
}

// GetExecID returns the exec ID of a given process.
func (pm *ProcessManager) GetExecID(proc *fgsAPI.MsgExecUnix) string {
	return pm.GetProcessID(proc.PID, proc.Ktime)
}

func (pm *ProcessManager) GetExecIDFromKey(key *fgsAPI.MsgExecveKey) string {
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
		// If we have a docker link, but the pod info lookup
		// failed then this is a nested docker environment. In
		// this case inherit the pod-info from our ancestors.
		if fgsProcess.Docker != "" &&
			fgsProcess.Pod == nil &&
			a.process.Pod != nil {
			pod := *a.process.Pod
			fgsProcess.Pod = &pod
		}
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
	event *fgsAPI.MsgIPv4EventUnix,
) *fgs.ProcessListen {
	var fgsProcess, fgsParent *fgs.Process
	var port *wrapperspb.UInt32Value

	if event.Tuple.SPort != 0 {
		port = &wrapperspb.UInt32Value{
			Value: uint32(reader.GetSport(event.Tuple.SPort)),
		}
	}
	process, parent := pm.getParentProcessInternal(event.ProcessKey.Pid, event.ProcessKey.Ktime)
	if process != nil {
		pm.cache.refInc(process)
		fgsProcess = process.process
	} else {
		fgsProcess = &fgs.Process{
			Pid:       &wrapperspb.UInt32Value{Value: event.ProcessKey.Pid},
			StartTime: ktimeToProto(event.ProcessKey.Ktime),
		}
	}
	if parent != nil {
		pm.cache.refInc(parent)
		fgsParent = parent.process
	}
	fgsEvent := &fgs.ProcessListen{
		Process: fgsProcess,
		Parent:  fgsParent,
		Ip:      reader.GetIP(event.Tuple.SAddr, 0).String(),
		Port:    port,

		Protocol: reader.MsgToProtocol(event),
	}

	if event.SockCookie != 0 {
		fgsEvent.SockCookie = event.SockCookie
	}

	if pm.processCacheNeeded(fgsProcess) {
		pm.eventCache.add(fgsEvent, ktimeToProto(event.Common.Ktime), event)
		return nil
	}
	return fgsEvent
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
			Pid:       &wrapperspb.UInt32Value{Value: event.ProcessKey.Pid},
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
	fgsEvent := &fgs.ProcessExit{
		Process: fgsProcess,
		Parent:  fgsParent,
	}
	if pm.processCacheNeeded(fgsProcess) {
		pm.eventCache.add(fgsEvent, ktimeToProto(event.Common.Ktime), event)
		return nil
	}
	return fgsEvent
}

// GetProcessCred returns Cred protobuf message for a given process.
func (pm *ProcessManager) GetProcessCred(event *fgsAPI.MsgCredEventUnix) *fgs.ProcessCred {
	processInt, parentInt := pm.getParentProcessInternal(event.ProcessKey.Pid, event.ProcessKey.Ktime)
	var process, parent *fgs.Process
	if processInt == nil {
		process = &fgs.Process{
			Pid:       &wrapperspb.UInt32Value{Value: event.ProcessKey.Pid},
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
	fgsEvent := &fgs.ProcessCred{
		Process: process,
		Parent:  parent,
		Cap:     pm.getCapabilities(event.Capabilities),
	}
	if pm.processCacheNeeded(process) {
		pm.eventCache.add(fgsEvent, ktimeToProto(event.Common.Ktime), event)
		return nil
	}
	return fgsEvent
}

// Translate internal uint32 error codes into gRPC visible error codes
func getTLSCertificateErrorCode(err uint32) fgs.TlsCertificateError {
	switch err {
	case api.TlsCertificateErrorNone:
		return fgs.TlsCertificateError_TLS_CERT_ERROR_UNDEF
	case api.TlsCertificateErrorBadHeader:
		return fgs.TlsCertificateError_TLS_CERT_ERROR_BAD_HEADER

	case api.TlsCertificateErrorLengthRead:
		return fgs.TlsCertificateError_TLS_CERT_ERROR_LENGTH_READ
	case api.TlsCertificateErrorMissingError:
		return fgs.TlsCertificateError_TLS_CERT_ERROR_MISSING_ERROR
	case api.TlsCertificateErrorCertRead:
		return fgs.TlsCertificateError_TLS_CERT_ERROR_CERT_READ
	case api.TlsCertificateErrorCertPartial:
		return fgs.TlsCertificateError_TLS_CERT_ERROR_CERT_PARTIAL
	case api.TlsCertificateErrorParseX509:
		return fgs.TlsCertificateError_TLS_CERT_ERROR_PARSE_X509
	case api.TlsCertificateErrorSpuriousCerts:
		return fgs.TlsCertificateError_TLS_CERT_ERROR_SPURIOUS_CERTS
	}
	return fgs.TlsCertificateError_TLS_CERT_ERROR_UNKNOWN
}

// GetTLS converts TLSEvent from hubble-fgs to protobuf message.
func (pm *ProcessManager) GetTLS(event *fgsAPI.MsgTLSEventUnix) *fgs.Tls {
	var sourcePort, destinationPort *wrapperspb.UInt32Value
	if event.Tuple.SPort != 0 {
		sourcePort = &wrapperspb.UInt32Value{
			Value: uint32(event.Tuple.SPort),
		}
	}
	if event.Tuple.DPort != 0 {
		destinationPort = &wrapperspb.UInt32Value{
			Value: uint32(fgsAPI.SwapByte(event.Tuple.DPort)),
		}
	}

	processID := pm.GetProcessID(event.ProcessKey.Pid, event.ProcessKey.Ktime)
	var proc *fgs.Process
	processInt, err := pm.cache.get(processID)
	if err != nil {
		pm.log.WithField("id in TLS event", processID).Debug("process not found in cache")
		proc = nil
	} else {
		proc = processInt.process
	}
	typeSNI, nameSNI := reader.GetTLSSNI(event.ClientHello.SNI)
	fgsEvent := &fgs.Tls{
		Process:             proc,
		SourceIp:            reader.GetIP(event.Tuple.SAddr, event.Common.Op).String(),
		SourcePort:          sourcePort,
		DestinationIp:       reader.GetIP(event.Tuple.DAddr, event.Common.Op).String(),
		DestinationPort:     destinationPort,
		NegotiatedVersion:   reader.GetTLSSupportedVersions(event.ServerHello.SupportedVersions[:], false),
		SupportedVersions:   reader.GetTLSSupportedVersions(event.ClientHello.SupportedVersions[:], true),
		SniName:             nameSNI,
		SniType:             typeSNI,
		Cipher:              reader.GetTLSCipher(api.SwapByte(event.ServerHello.Cipher)),
		ClientFlags:         reader.GetTLSFlags(event.ClientHello.Flags),
		ServerFlags:         reader.GetTLSFlags(event.ServerHello.Flags),
		ClientVersion:       reader.GetTLSVersion(event.ClientHello.Version),
		ServerVersion:       reader.GetTLSVersion(event.ServerHello.Version),
		ClientAlert:         reader.GetTLSAlert(event.ClientHello.AlertLevel, event.ClientHello.AlertDescription),
		ServerAlert:         reader.GetTLSAlert(event.ServerHello.AlertLevel, event.ServerHello.AlertDescription),
		ClientSession:       reader.GetTLSSession(event.ClientHello.Session),
		ServerSession:       reader.GetTLSSession(event.ServerHello.Session),
		Certificates:        event.ServerCert.Certificates,
		CertificateError:    getTLSCertificateErrorCode(event.ServerCert.Error),
		ParserInternalState: event.ServerCert.ParserState.String(),
	}
	if pm.processCacheNeeded(proc) {
		pm.eventCache.add(fgsEvent, ktimeToProto(event.Common.Ktime), event)
		return nil
	}
	return fgsEvent
}

func (pm *ProcessManager) __getProcessTuple(tuple *fgsAPI.MsgIPv4Tuple, cookie uint64, op uint8) *fgs.SockInfo {
	var sourcePort, destinationPort *wrapperspb.UInt32Value

	if tuple.SPort != 0 {
		sourcePort = &wrapperspb.UInt32Value{
			Value: uint32(reader.GetSport(tuple.SPort)),
		}
	}
	if tuple.DPort != 0 {
		destinationPort = &wrapperspb.UInt32Value{
			Value: uint32(fgsAPI.SwapByte(tuple.DPort)),
		}
	}

	destinationIP := reader.GetIP(tuple.DAddr, op)

	return &fgs.SockInfo{
		SourcePort:      sourcePort,
		SourceIp:        reader.GetIP(tuple.SAddr, op).String(),
		DestinationIp:   destinationIP.String(),
		DestinationPort: destinationPort,
		SockCookie:      cookie,

		Protocol: reader.MsgOpToProtocol(op),
	}
}

func (pm *ProcessManager) getProcessTuple(event *fgsAPI.MsgIPv4EventUnix) *fgs.SockInfo {
	return pm.__getProcessTuple(&event.Tuple, event.SockCookie, event.Common.Op)
}

// GetProcessSockStats converts KprobeEvent from hubble-fgs to protobuf message.
func (pm *ProcessManager) GetProcessSockStats(event *fgsAPI.MsgIPv4EventUnix) *fgs.ProcessSockStats {
	var fgsParent, fgsProcess *fgs.Process

	process, parent := pm.getParentProcessInternal(event.ProcessKey.Pid, event.ProcessKey.Ktime)
	if process == nil {
		fgsProcess = &fgs.Process{
			Pid:       &wrapperspb.UInt32Value{Value: event.ProcessKey.Pid},
			StartTime: ktimeToProto(event.ProcessKey.Ktime),
		}
	} else {
		fgsProcess = process.process
	}
	if parent == nil {
		fgsParent = &fgs.Process{}
	} else {
		fgsParent = parent.process
	}

	fgsTuple := pm.getProcessTuple(event)
	fgsSocketStats := reader.GetSocketStats(&event.SocketStats)

	fgsEvent := &fgs.ProcessSockStats{
		Process: fgsProcess,
		Parent:  fgsParent,
		Socket:  fgsTuple,
		Stats:   fgsSocketStats,
	}

	if pm.processCacheNeeded(fgsProcess) {
		pm.eventCache.add(fgsEvent, ktimeToProto(event.Common.Ktime), event)
		return nil
	}
	return fgsEvent
}

// GetProcessClose converts KprobeEvent from hubble-fgs to protobuf message.
func (pm *ProcessManager) GetProcessClose(event *fgsAPI.MsgIPv4EventUnix) *fgs.ProcessClose {
	var sourcePort, destinationPort *wrapperspb.UInt32Value
	var fgsParent, fgsProcess *fgs.Process

	if event.Tuple.SPort != 0 {
		sourcePort = &wrapperspb.UInt32Value{
			Value: uint32(reader.GetSport(event.Tuple.SPort)),
		}
	}
	if event.Tuple.DPort != 0 {
		destinationPort = &wrapperspb.UInt32Value{
			Value: uint32(fgsAPI.SwapByte(event.Tuple.DPort)),
		}
	}

	process, parent := pm.getParentProcessInternal(event.ProcessKey.Pid, event.ProcessKey.Ktime)
	if process == nil {
		fgsProcess = &fgs.Process{
			Pid:       &wrapperspb.UInt32Value{Value: event.ProcessKey.Pid},
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

	destinationIP := reader.GetIP(event.Tuple.DAddr, event.Common.Op)
	socketStats := reader.GetSocketStats(&event.SocketStats)

	fgsEvent := &fgs.ProcessClose{
		Process:         fgsProcess,
		Parent:          fgsParent,
		SourceIp:        reader.GetIP(event.Tuple.SAddr, event.Common.Op).String(),
		SourcePort:      sourcePort,
		DestinationIp:   destinationIP.String(),
		DestinationPort: destinationPort,
		Stats:           socketStats,
		Protocol:        reader.MsgToProtocol(event),
	}

	if event.SockCookie != 0 {
		fgsEvent.SockCookie = event.SockCookie
	}

	// When CiliumAPI is enable annotate data with Cilium info. If the data
	// is missing and enableEventCache is enabled we push event into the
	// cache where a retry will happen.
	if pm.enableCilium && fgsProcess != nil {
		destinationIP := reader.GetIP(event.Tuple.DAddr, api.MSG_OP_HTTP)
		endpoint := pm.getProcessEndpoint(fgsProcess)
		if endpoint != nil {
			fgsEvent.DestinationNames = pm.ciliumState.GetFQDNCache().GetNamesOf(endpoint.ID, destinationIP)
			fgsEvent.DestinationPod = pm.getPodInfoOfIp(destinationIP)
		} else if pm.enableEventCache {
			pm.eventCache.add(fgsEvent, ktimeToProto(event.Common.Ktime), event)
			return nil
		}
	}
	if pm.processCacheNeeded(fgsProcess) {
		pm.eventCache.add(fgsEvent, ktimeToProto(event.Common.Ktime), event)
		return nil
	}
	return fgsEvent
}

// GetProcessConnect converts KprobeEvent from hubble-fgs to protobuf message.
func (pm *ProcessManager) GetProcessConnect(event *fgsAPI.MsgIPv4EventUnix) *fgs.ProcessConnect {
	var fgsProcess, fgsParent *fgs.Process
	var sourcePort, destinationPort *wrapperspb.UInt32Value

	if event.Tuple.SPort != 0 {
		sourcePort = &wrapperspb.UInt32Value{
			Value: uint32(reader.GetSport(event.Tuple.SPort)),
		}
	}
	if event.Tuple.DPort != 0 {
		destinationPort = &wrapperspb.UInt32Value{
			Value: uint32(fgsAPI.SwapByte(event.Tuple.DPort)),
		}
	}

	process, parent := pm.getParentProcessInternal(event.ProcessKey.Pid, event.ProcessKey.Ktime)
	if process == nil {
		fgsProcess = &fgs.Process{
			Pid:       &wrapperspb.UInt32Value{Value: event.ProcessKey.Pid},
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

	destinationIP := reader.GetIP(event.Tuple.DAddr, event.Common.Op)
	fgsEvent := &fgs.ProcessConnect{
		Process:         fgsProcess,
		Parent:          fgsParent,
		SourceIp:        reader.GetIP(event.Tuple.SAddr, event.Common.Op).String(),
		SourcePort:      sourcePort,
		DestinationIp:   destinationIP.String(),
		DestinationPort: destinationPort,
		SockCookie:      event.SockCookie,
		Protocol:        reader.MsgToProtocol(event),
	}

	if event.SockCookie != 0 {
		fgsEvent.SockCookie = event.SockCookie
	}

	// When CiliumAPI is enable annotate data with Cilium info. If the data
	// is missing and enableEventCache is enabled we push event into the
	// cache where a retry will happen.
	if pm.enableCilium && fgsProcess != nil {
		destinationIP := reader.GetIP(event.Tuple.DAddr, api.MSG_OP_HTTP)
		endpoint := pm.getProcessEndpoint(fgsProcess)
		if endpoint != nil {
			fgsEvent.DestinationNames = pm.ciliumState.GetFQDNCache().GetNamesOf(endpoint.ID, destinationIP)
			fgsEvent.DestinationPod = pm.getPodInfoOfIp(destinationIP)
		} else if pm.enableEventCache {
			pm.eventCache.add(fgsEvent, ktimeToProto(event.Common.Ktime), event)
			return nil
		}
	}
	if pm.processCacheNeeded(fgsProcess) {
		pm.eventCache.add(fgsEvent, ktimeToProto(event.Common.Ktime), event)
		return nil
	}
	return fgsEvent
}

// GetProcessAccept converts KprobeEvent from hubble-fgs to protobuf message.
func (pm *ProcessManager) GetProcessAccept(event *fgsAPI.MsgIPv4EventUnix) *fgs.ProcessAccept {
	var sourcePort, destinationPort *wrapperspb.UInt32Value
	var fgsParent, fgsProcess *fgs.Process

	if event.Tuple.SPort != 0 {
		sourcePort = &wrapperspb.UInt32Value{
			Value: uint32(reader.GetSport(event.Tuple.SPort)),
		}
	}
	if event.Tuple.DPort != 0 {
		destinationPort = &wrapperspb.UInt32Value{
			Value: uint32(fgsAPI.SwapByte(event.Tuple.DPort)),
		}
	}

	process, parent := pm.getParentProcessInternal(event.ProcessKey.Pid, event.ProcessKey.Ktime)
	if process == nil {
		fgsProcess = &fgs.Process{
			Pid:       &wrapperspb.UInt32Value{Value: event.ProcessKey.Pid},
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

	destinationIP := reader.GetIP(event.Tuple.DAddr, event.Common.Op)
	fgsEvent := &fgs.ProcessAccept{
		Process:         fgsProcess,
		Parent:          fgsParent,
		SourceIp:        reader.GetIP(event.Tuple.SAddr, event.Common.Op).String(),
		SourcePort:      sourcePort,
		DestinationIp:   destinationIP.String(),
		DestinationPort: destinationPort,

		Protocol: reader.MsgToProtocol(event),
	}

	if event.SockCookie != 0 {
		fgsEvent.SockCookie = event.SockCookie
	}

	// When CiliumAPI is enable annotate data with Cilium info. If the data
	// is missing and enableEventCache is enabled we push event into the
	// cache where a retry will happen.
	if pm.enableCilium && fgsProcess != nil {
		destinationIP := reader.GetIP(event.Tuple.DAddr, api.MSG_OP_HTTP)
		endpoint := pm.getProcessEndpoint(fgsProcess)
		if endpoint != nil {
			fgsEvent.DestinationNames = pm.ciliumState.GetFQDNCache().GetNamesOf(endpoint.ID, destinationIP)
			fgsEvent.DestinationPod = pm.getPodInfoOfIp(destinationIP)
		} else if pm.enableEventCache {
			pm.eventCache.add(fgsEvent, ktimeToProto(event.Common.Ktime), event)
			return nil
		}
	}
	if pm.processCacheNeeded(fgsProcess) {
		pm.eventCache.add(fgsEvent, ktimeToProto(event.Common.Ktime), event)
		return nil
	}

	return fgsEvent
}

func (pm *ProcessManager) getPodInfoOfIp(ip net.IP) *fgs.Pod {
	endpoint, ok := pm.ciliumState.GetEndpointsHandler().GetEndpoint(ip)
	if !ok {
		return nil
	}
	return &fgs.Pod{
		Namespace: endpoint.PodNamespace,
		Name:      endpoint.PodName,
		Labels:    endpoint.Labels,
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

package httpproto

import (
	"strings"
	"time"

	"github.com/cilium/hubble/pkg/cilium"
	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/ktime"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/process"
	"github.com/cilium/tetragon/pkg/reader/node"
	api "github.com/isovalent/hubble-fgs/pkg/api/httpapi"
	"github.com/isovalent/hubble-fgs/pkg/api/ops"
	"github.com/isovalent/hubble-fgs/pkg/dns"
	"github.com/isovalent/hubble-fgs/pkg/eventcache"
	"github.com/isovalent/hubble-fgs/pkg/grpc/sockinfo"
	"github.com/isovalent/hubble-fgs/pkg/podinfo"
	"github.com/isovalent/hubble-fgs/pkg/reader/network"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var (
	nodeName = node.GetNodeNameForExport()
)

type Grpc struct {
	dnsCache     *dns.Cache
	ciliumState  *cilium.State
	eventCache   *eventcache.Cache
	enableCilium bool
}

func (http *Grpc) GetHttp(event *api.MsgHttpEventUnix) *tetragon.ProcessHttp {
	var proc *tetragon.Process
	var code uint32
	var err error

	fgsHttpResponse := &tetragon.HttpResponse{}
	fgsHttpRequest := &tetragon.HttpRequest{}

	processID := process.GetProcessID(event.ProcessKey.Pid, event.ProcessKey.Ktime)
	processInt, err := process.Get(processID)
	if err != nil {
		logger.GetLogger().WithField("id in HTTP event", processID).Debug("process not found in cache")
	} else {
		proc = processInt.UnsafeGetProcess()

	}
	fgsTuple := sockinfo.GetTupleV4(&event.Tuple, 0, event.Common.Op)

	if len(event.Request.Code) != 0 {
		code, err = GetHttpCode(event.Request.Code)
		if err != nil {
			logger.GetLogger().WithField("Unknown Response Code", event.Request.Code).Info("unknown code")
		}

		length, err := GetHttpContentLength(event.Request.RespContentLength)
		if err != nil {
			logger.GetLogger().WithError(err).WithField("RespContentLength", event.Request.RespContentLength).Info("Response Content-Length strconv error")
		}

		fgsHttpResponse = &tetragon.HttpResponse{
			Timestamp:        ktime.ToProto(event.Common.Ktime),
			Version:          event.Request.RespVersion,
			Code:             code,
			Reason:           event.Request.Reason,
			ContentLength:    &wrapperspb.UInt32Value{Value: uint32(length)},
			Flags:            strings.Join(HttpErrorFlags(event.Request.FlagsResponse), " "),
			TransferEncoding: event.Request.RespTransferEncoding,
		}
	}

	length, err := GetHttpContentLength(event.Request.ContentLength)
	if err != nil {
		logger.GetLogger().WithError(err).WithField("ContentLength", event.Request.ContentLength).Info("Request Content-Length strconv error")
	}

	if len(event.Request.Method) != 0 {
		fgsHttpRequest = &tetragon.HttpRequest{
			Timestamp:        ktime.ToProto(event.Request.Ktime),
			Method:           event.Request.Method,
			Uri:              event.Request.Uri,
			Version:          event.Request.Protocol,
			Host:             event.Request.Host,
			Agent:            event.Request.UserAgent,
			ContentLength:    &wrapperspb.UInt32Value{Value: uint32(length)},
			Flags:            strings.Join(HttpErrorFlags(event.Request.Flags), " "),
			TransferEncoding: event.Request.TransferEncoding,
		}
	}

	fgsHttp := &tetragon.HttpInfo{
		Request:  fgsHttpRequest,
		Response: fgsHttpResponse,
	}

	if len(event.Request.Code) != 0 &&
		len(event.Request.Method) != 0 {
		l := ktime.DiffKtime(event.Request.Ktime, event.Common.Ktime)
		nano := l.Nanoseconds()
		sec := nano / int64(time.Second)
		remainder := nano % int64(time.Second)
		fgsHttp.Latency = &durationpb.Duration{
			Seconds: sec,
			Nanos:   int32(remainder),
		}
	}

	fgsEvent := &tetragon.ProcessHttp{
		Process: proc,
		Socket:  fgsTuple,
		Http:    fgsHttp,
	}

	fgsEvent.Socket.DestinationNames, _ = sockinfo.GetProcessIp(proc, fgsEvent.Socket.DestinationIp, http.dnsCache, http.ciliumState)

	// When CiliumAPI is enable annotate data with Cilium info. If the data
	// is missing and enableEventCache is enabled we push event into the
	// cache where a retry will happen.
	if http.enableCilium && proc != nil {
		destinationIP := network.GetIPv4(event.Tuple.DAddr, ops.MSG_OP_HTTP)
		fgsEvent.DestinationPod = podinfo.GetPodInfoOfIp(destinationIP)
	}
	if http.eventCache.Needed(proc) {
		http.eventCache.Add(processInt, fgsEvent, ktime.ToProto(event.Common.Ktime), event)
		return nil
	}
	if processInt != nil {
		fgsEvent.Process = processInt.GetProcessCopy()
	}
	return fgsEvent
}

func (http *Grpc) HandleHttpMessage(msg *api.MsgHttpEventUnix) *tetragon.GetEventsResponse {
	var res *tetragon.GetEventsResponse
	switch msg.Common.Op {
	case ops.MSG_OP_HTTP:
		t := http.GetHttp(msg)
		if t != nil {
			res = &tetragon.GetEventsResponse{
				Event:    &tetragon.GetEventsResponse_ProcessHttp{ProcessHttp: t},
				NodeName: nodeName,
				Time:     ktime.ToProto(msg.Common.Ktime),
			}
		}
	default:
		logger.GetLogger().WithField("message", msg).Warn("HandleHttpMessage: Unhandled event")
	}
	return res
}

func New(cilium *cilium.State, dnsCache *dns.Cache, cache *eventcache.Cache, ciliumEnable bool) *Grpc {
	return &Grpc{
		ciliumState:  cilium,
		dnsCache:     dnsCache,
		eventCache:   cache,
		enableCilium: ciliumEnable,
	}
}

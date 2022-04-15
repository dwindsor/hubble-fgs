package grpc

import (
	"strings"
	"time"

	"github.com/isovalent/hubble-fgs/api/v1/fgs"
	"github.com/isovalent/hubble-fgs/pkg/api"
	fgsAPI "github.com/isovalent/hubble-fgs/pkg/api"
	"github.com/isovalent/hubble-fgs/pkg/ktime"
	"github.com/isovalent/hubble-fgs/pkg/podinfo"
	"github.com/isovalent/hubble-fgs/pkg/process"
	"github.com/isovalent/hubble-fgs/pkg/reader"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func (pm *ProcessManager) GetHttp(event *fgsAPI.MsgHttpEventUnix) *fgs.ProcessHttp {
	var proc *fgs.Process
	var code uint32
	var err error

	fgsHttpResponse := &fgs.HttpResponse{}
	fgsHttpRequest := &fgs.HttpRequest{}

	processID := process.GetProcessID(event.ProcessKey.Pid, event.ProcessKey.Ktime)
	processInt, err := process.Get(processID)
	if err != nil {
		pm.log.WithField("id in HTTP event", processID).Debug("process not found in cache")
	} else {
		proc = processInt.UnsafeGetProcess()

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
			Timestamp:        ktime.ToProto(event.Common.Ktime),
			Version:          event.Request.RespVersion,
			Code:             code,
			Reason:           event.Request.Reason,
			ContentLength:    &wrapperspb.UInt32Value{Value: uint32(length)},
			Flags:            strings.Join(reader.HttpErrorFlags(event.Request.FlagsResponse), " "),
			TransferEncoding: event.Request.RespTransferEncoding,
		}
	}

	length, err := reader.GetHttpContentLength(event.Request.ContentLength)
	if err != nil {
		pm.log.WithError(err).WithField("ContentLength", event.Request.ContentLength).Info("Request Content-Length strconv error")
	}

	if len(event.Request.Method) != 0 {
		fgsHttpRequest = &fgs.HttpRequest{
			Timestamp:        ktime.ToProto(event.Request.Ktime),
			Method:           event.Request.Method,
			Uri:              event.Request.Uri,
			Version:          event.Request.Protocol,
			Host:             event.Request.Host,
			Agent:            event.Request.UserAgent,
			ContentLength:    &wrapperspb.UInt32Value{Value: uint32(length)},
			Flags:            strings.Join(reader.HttpErrorFlags(event.Request.Flags), " "),
			TransferEncoding: event.Request.TransferEncoding,
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

	fgsEvent.DestinationNames, _ = pm.getProcessIp(proc, fgsEvent.Socket.DestinationIp)

	// When CiliumAPI is enable annotate data with Cilium info. If the data
	// is missing and enableEventCache is enabled we push event into the
	// cache where a retry will happen.
	if pm.enableCilium && proc != nil {
		destinationIP := reader.GetIP(event.Tuple.DAddr, api.MSG_OP_HTTP)
		fgsEvent.DestinationPod = podinfo.GetPodInfoOfIp(destinationIP)
	}
	if pm.processCacheNeeded(proc) {
		pm.eventCache.Add(processInt, fgsEvent, ktime.ToProto(event.Common.Ktime), event)
		return nil
	}
	if processInt != nil {
		fgsEvent.Process = processInt.GetProcessCopy()
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
				Time:     ktime.ToProto(msg.Common.Ktime),
			}
		}
	default:
		pm.log.WithField("message", msg).Warn("Unhandled event")
	}
	return res
}

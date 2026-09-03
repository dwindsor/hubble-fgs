// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package httpproto

import (
	"strings"
	"time"

	"github.com/cilium/tetragon/pkg/eventcache"
	"github.com/cilium/tetragon/pkg/ktime"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/process"
	"github.com/cilium/tetragon/pkg/reader/notify"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/cilium/tetragon/api/v1/tetragon"

	"github.com/cilium/tetragon/pkg/option"

	"github.com/isovalent/hubble-fgs/pkg/api/httpapi"
	"github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	"github.com/isovalent/hubble-fgs/pkg/api/ops"
	"github.com/isovalent/hubble-fgs/pkg/dns"
	"github.com/isovalent/hubble-fgs/pkg/grpc/sockinfo"
	"github.com/isovalent/hubble-fgs/pkg/metrics/eventmetrics"
	"github.com/isovalent/hubble-fgs/pkg/podinfo"
	"github.com/isovalent/hubble-fgs/pkg/protoutils"
)

func GetHttp(event *MsgHttpEventUnix) *tetragon.ProcessHttp {
	var proc *tetragon.Process
	var code uint32
	var err error
	var processInt *process.ProcessInternal

	fgsHttpResponse := &tetragon.HttpResponse{}
	fgsHttpRequest := &tetragon.HttpRequest{}

	processID := process.GetProcessID(event.Msg.ProcessKey.Pid, event.Msg.ProcessKey.Ktime)
	if !option.Config.DisableProcessCache {
		processInt, _ = process.Get(processID)
	}
	if processInt == nil {
		proc = &tetragon.Process{
			Pid:       &wrapperspb.UInt32Value{Value: event.Msg.ProcessKey.Pid},
			StartTime: ktime.ToProto(event.Msg.ProcessKey.Ktime),
		}
		logger.GetLogger().Debug("process not found in cache", "id in HTTP event", processID)
	} else {
		proc = processInt.UnsafeGetProcess()

	}
	fgsTuple := sockinfo.GetTuple(&event.Msg.Tuple, 0, event.Msg.Common.Op)

	if len(event.Request.Code) != 0 {
		code, err = GetHttpCode(event.Request.Code)
		if err != nil {
			logger.GetLogger().Info("unknown code", "Unknown Response Code", event.Request.Code)
		}

		length, err := GetHttpContentLength(event.Request.RespContentLength)
		if err != nil {
			logger.GetLogger().Info("Response Content-Length strconv error", logfields.Error, err, "RespContentLength", event.Request.RespContentLength)
		}

		fgsHttpResponse = &tetragon.HttpResponse{
			Timestamp:        ktime.ToProto(event.Msg.Common.Ktime),
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
		logger.GetLogger().Info("Request Content-Length strconv error", logfields.Error, err, "ContentLength", event.Request.ContentLength)
	}

	if len(event.Request.Method) != 0 {
		fgsHttpRequest = &tetragon.HttpRequest{
			Timestamp:        ktime.ToProto(event.Request.Ktime),
			Method:           protoutils.SanitizeString(event.Request.Method),
			Uri:              protoutils.SanitizeString(event.Request.Uri),
			Version:          event.Request.Protocol,
			Host:             protoutils.SanitizeString(event.Request.Host),
			Agent:            protoutils.SanitizeString(event.Request.UserAgent),
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
		l := ktime.DiffKtime(event.Request.Ktime, event.Msg.Common.Ktime)
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

	fgsEvent.Socket.DestinationNames, err = dns.Get().LookupDomains(fgsEvent.Socket.DestinationIp)
	if err != nil {
		logger.GetLogger().Warn("DNS cache lookup failure", logfields.Error, err)
	}

	// When CiliumAPI is enable annotate data with Cilium info. If the data
	// is missing and enableEventCache is enabled we push event into the
	// cache where a retry will happen.
	if proc != nil {
		destinationIP := networkapi.GetIP(event.Msg.Tuple.DAddr, ops.MSG_OP_HTTP, event.Msg.Tuple.IPv6 != 0)
		// We want to continue populating this deprecated field for now
		fgsEvent.DestinationPod = podinfo.GetPodInfoOfIp(destinationIP) //nolint:staticcheck
	}
	ec := eventcache.Get()
	if ec != nil && ec.Needed(proc) {
		ec.Add(nil, fgsEvent, event.Msg.Common.Ktime, event.Msg.ProcessKey.Ktime, event)
		return nil
	}
	eventmetrics.HandleHttpEvent(fgsEvent)
	return fgsEvent
}

type MsgHttpEventUnix struct {
	Msg     *httpapi.MsgHttpEvent
	Request httpapi.MsgHttpUnix
}

func (msg *MsgHttpEventUnix) RetryInternal(ev notify.Event, timestamp uint64) (*process.ProcessInternal, error) {
	p := ev.GetProcess()
	return eventcache.HandleGenericInternal(ev, p.Pid.Value, nil, timestamp)
}

func (msg *MsgHttpEventUnix) Retry(internal *process.ProcessInternal, ev notify.Event) error {
	return eventcache.HandleGenericEvent(internal, ev, nil)
}

func (msg *MsgHttpEventUnix) Notify() bool {
	return true
}

func (msg *MsgHttpEventUnix) HandleMessage() *tetragon.GetEventsResponse {
	var res *tetragon.GetEventsResponse
	switch msg.Msg.Common.Op {
	case ops.MSG_OP_HTTP:
		t := GetHttp(msg)
		if t != nil {
			res = &tetragon.GetEventsResponse{
				Event: &tetragon.GetEventsResponse_ProcessHttp{ProcessHttp: t},
				Time:  ktime.ToProto(msg.Msg.Common.Ktime),
			}
		}
	default:
		logger.GetLogger().Warn("HandleHttpMessage: Unhandled event", "message", msg)
	}
	return res
}

func (msg *MsgHttpEventUnix) Cast(_ any) notify.Message {
	return &MsgHttpEventUnix{}
}

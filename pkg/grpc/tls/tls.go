package tls

import (
	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/ktime"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/process"
	"github.com/cilium/tetragon/pkg/reader/node"
	"github.com/isovalent/hubble-fgs/pkg/api/ops"
	"github.com/isovalent/hubble-fgs/pkg/api/tlsapi"
	"github.com/isovalent/hubble-fgs/pkg/eventcache"
	"github.com/isovalent/hubble-fgs/pkg/reader/ciphers"
	"github.com/isovalent/hubble-fgs/pkg/reader/network"
	readertls "github.com/isovalent/hubble-fgs/pkg/reader/tls"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var (
	nodeName = node.GetNodeNameForExport()
)

type Grpc struct {
	eventCache *eventcache.Cache
}

// Translate internal uint32 error codes into gRPC visible error codes
func getTLSCertificateErrorCode(err uint32) tetragon.TlsCertificateError {
	switch err {
	case tlsapi.TlsCertificateErrorNone:
		return tetragon.TlsCertificateError_TLS_CERT_ERROR_UNDEF
	case tlsapi.TlsCertificateErrorBadHeader:
		return tetragon.TlsCertificateError_TLS_CERT_ERROR_BAD_HEADER

	case tlsapi.TlsCertificateErrorLengthRead:
		return tetragon.TlsCertificateError_TLS_CERT_ERROR_LENGTH_READ
	case tlsapi.TlsCertificateErrorMissingError:
		return tetragon.TlsCertificateError_TLS_CERT_ERROR_MISSING_ERROR
	case tlsapi.TlsCertificateErrorCertRead:
		return tetragon.TlsCertificateError_TLS_CERT_ERROR_CERT_READ
	case tlsapi.TlsCertificateErrorCertPartial:
		return tetragon.TlsCertificateError_TLS_CERT_ERROR_CERT_PARTIAL
	case tlsapi.TlsCertificateErrorParseX509:
		return tetragon.TlsCertificateError_TLS_CERT_ERROR_PARSE_X509
	case tlsapi.TlsCertificateErrorSpuriousCerts:
		return tetragon.TlsCertificateError_TLS_CERT_ERROR_SPURIOUS_CERTS
	}
	return tetragon.TlsCertificateError_TLS_CERT_ERROR_UNKNOWN
}

// GetTLS converts TLSEvent from hubble-fgs to protobuf message.
func (tls *Grpc) getTLS(event *tlsapi.MsgTLSEventUnix) *tetragon.Tls {
	var sourcePort, destinationPort *wrapperspb.UInt32Value
	if event.Tuple.SPort != 0 {
		sourcePort = &wrapperspb.UInt32Value{
			Value: uint32(event.Tuple.SPort),
		}
	}
	if event.Tuple.DPort != 0 {
		destinationPort = &wrapperspb.UInt32Value{
			Value: uint32(network.SwapByte(event.Tuple.DPort)),
		}
	}

	processID := process.GetProcessID(event.ProcessKey.Pid, event.ProcessKey.Ktime)
	var proc *tetragon.Process
	processInt, err := process.Get(processID)
	if err != nil {
		logger.GetLogger().WithField("id in TLS event", processID).Debug("process not found in cache")
		proc = nil
	} else {
		proc = processInt.UnsafeGetProcess()
	}
	typeSNI, nameSNI := readertls.GetTLSSNI(event.ClientHello.SNI.Value)
	fgsEvent := &tetragon.Tls{
		Process:             proc,
		SourceIp:            network.GetIPv4(event.Tuple.SAddr, event.Common.Op).String(),
		SourcePort:          sourcePort,
		DestinationIp:       network.GetIPv4(event.Tuple.DAddr, event.Common.Op).String(),
		DestinationPort:     destinationPort,
		NegotiatedVersion:   readertls.GetTLSSupportedVersions(&event.ServerHello.SupportedVersions, false),
		SupportedVersions:   readertls.GetTLSSupportedVersions(&event.ClientHello.SupportedVersions, true),
		SniName:             nameSNI,
		SniType:             typeSNI,
		Cipher:              ciphers.GetTLSCiphers(&event.ServerHello.Cipher),
		ClientFlags:         readertls.GetTLSFlags(event.ClientHello.Flags),
		ServerFlags:         readertls.GetTLSFlags(event.ServerHello.Flags),
		ClientVersion:       readertls.GetTLSVersion(event.ClientHello.Version),
		ServerVersion:       readertls.GetTLSVersion(event.ServerHello.Version),
		ClientAlert:         readertls.GetTLSAlert(event.ClientHello.AlertLevel, event.ClientHello.AlertDescription),
		ServerAlert:         readertls.GetTLSAlert(event.ServerHello.AlertLevel, event.ServerHello.AlertDescription),
		ClientSession:       readertls.GetTLSSession(&event.ClientHello.Session),
		ServerSession:       readertls.GetTLSSession(&event.ServerHello.Session),
		Certificates:        event.ServerCert.Certificates,
		CertificateError:    getTLSCertificateErrorCode(event.ServerCert.Error),
		ParserInternalState: event.ServerCert.ParserState.String(),
	}
	if tls.eventCache.Needed(proc) {
		tls.eventCache.Add(processInt, fgsEvent, ktime.ToProto(event.Common.Ktime), event)
		return nil
	}
	if processInt != nil {
		fgsEvent.Process = processInt.GetProcessCopy()
	}
	return fgsEvent
}

func (tls *Grpc) HandleMessage(msg *tlsapi.MsgTLSEventUnix) *tetragon.GetEventsResponse {
	var res *tetragon.GetEventsResponse
	switch msg.Common.Op {
	case ops.MSG_OP_TLS:
		t := tls.getTLS(msg)
		if t != nil {
			res = &tetragon.GetEventsResponse{
				Event:    &tetragon.GetEventsResponse_Tls{Tls: t},
				NodeName: nodeName,
				Time:     ktime.ToProto(msg.Common.Ktime),
			}
		}
	default:
		logger.GetLogger().WithField("message", msg).Warn("HandleTlsMessage: Unhandled event")
	}
	return res
}

func New(ec *eventcache.Cache) *Grpc {
	return &Grpc{
		eventCache: ec,
	}
}

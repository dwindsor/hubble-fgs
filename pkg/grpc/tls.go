package grpc

import (
	"github.com/isovalent/hubble-fgs/api/v1/fgs"
	"github.com/isovalent/hubble-fgs/pkg/api"
	fgsAPI "github.com/isovalent/hubble-fgs/pkg/api"
	"github.com/isovalent/hubble-fgs/pkg/reader"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

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
	typeSNI, nameSNI := reader.GetTLSSNI(event.ClientHello.SNI.Value)
	fgsEvent := &fgs.Tls{
		Process:             proc,
		SourceIp:            reader.GetIP(event.Tuple.SAddr, event.Common.Op).String(),
		SourcePort:          sourcePort,
		DestinationIp:       reader.GetIP(event.Tuple.DAddr, event.Common.Op).String(),
		DestinationPort:     destinationPort,
		NegotiatedVersion:   reader.GetTLSSupportedVersions(&event.ServerHello.SupportedVersions, false),
		SupportedVersions:   reader.GetTLSSupportedVersions(&event.ClientHello.SupportedVersions, true),
		SniName:             nameSNI,
		SniType:             typeSNI,
		Cipher:              reader.GetTLSCiphers(&event.ServerHello.Cipher),
		ClientFlags:         reader.GetTLSFlags(event.ClientHello.Flags),
		ServerFlags:         reader.GetTLSFlags(event.ServerHello.Flags),
		ClientVersion:       reader.GetTLSVersion(event.ClientHello.Version),
		ServerVersion:       reader.GetTLSVersion(event.ServerHello.Version),
		ClientAlert:         reader.GetTLSAlert(event.ClientHello.AlertLevel, event.ClientHello.AlertDescription),
		ServerAlert:         reader.GetTLSAlert(event.ServerHello.AlertLevel, event.ServerHello.AlertDescription),
		ClientSession:       reader.GetTLSSession(&event.ClientHello.Session),
		ServerSession:       reader.GetTLSSession(&event.ServerHello.Session),
		Certificates:        event.ServerCert.Certificates,
		CertificateError:    getTLSCertificateErrorCode(event.ServerCert.Error),
		ParserInternalState: event.ServerCert.ParserState.String(),
	}
	if pm.processCacheNeeded(proc) {
		pm.eventCache.add(processInt, fgsEvent, ktimeToProto(event.Common.Ktime), event)
		return nil
	}
	if processInt != nil {
		fgsEvent.Process = processInt.GetProcessCopy()
	}
	return fgsEvent
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

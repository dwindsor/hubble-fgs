package tls

import (
	"github.com/cilium/tetragon/pkg/eventcache"
	"github.com/cilium/tetragon/pkg/ktime"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/process"
	"github.com/cilium/tetragon/pkg/reader/notify"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/cilium/tetragon/api/v1/tetragon"

	"github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	"github.com/isovalent/hubble-fgs/pkg/api/ops"
	"github.com/isovalent/hubble-fgs/pkg/api/tlsapi"
	"github.com/isovalent/hubble-fgs/pkg/metrics/eventmetrics"
	"github.com/isovalent/hubble-fgs/pkg/reader/ciphers"
	readertls "github.com/isovalent/hubble-fgs/pkg/reader/tls"
)

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

type MsgTLSEventUnix struct {
	Msg        *tlsapi.MsgTLSEvent
	ServerCert tlsapi.MsgTLSCertificates
}

func ObserverTLSPrinter(msg *MsgTLSEventUnix, log logrus.FieldLogger) {
	op := msg.Msg.Common.Op
	typeSNI, nameSNI := readertls.GetTLSSNI(msg.Msg.ClientHello.SNI.Value)

	log.WithFields(logrus.Fields{
		"op":                           ops.OpCode(op).String(),
		"saddr":                        networkapi.GetIP(msg.Msg.Tuple.SAddr, op, msg.Msg.Tuple.IPv6 != 0).String(),
		"sport":                        networkapi.GetSport(msg.Msg.Tuple.SPort),
		"dport":                        msg.Msg.Tuple.DPort,
		"daddr":                        networkapi.GetIP(msg.Msg.Tuple.DAddr, op, msg.Msg.Tuple.IPv6 != 0).String(),
		"Client-TLS-Version":           readertls.GetTLSVersion(msg.Msg.ClientHello.Version),
		"Server-TLS-Version":           readertls.GetTLSVersion(msg.Msg.ServerHello.Version),
		"SNI-Type":                     typeSNI,
		"SNI-Name":                     nameSNI,
		"Client-TLS-SupportedVersions": readertls.GetTLSSupportedVersions(&msg.Msg.ClientHello.SupportedVersions, true),
		"Server-TLS-SupportedVersions": readertls.GetTLSSupportedVersions(&msg.Msg.ServerHello.SupportedVersions, false),
		"cipher":                       ciphers.GetTLSCiphers(&msg.Msg.ServerHello.Cipher),
	}).Warn()
}

// GetTLS converts TLSEvent from hubble-fgs to protobuf message.
func getTLS(event *MsgTLSEventUnix) *tetragon.Tls {
	var sourcePort, destinationPort *wrapperspb.UInt32Value
	if event.Msg.Tuple.SPort != 0 {
		sourcePort = &wrapperspb.UInt32Value{
			Value: uint32(event.Msg.Tuple.SPort),
		}
	}
	if event.Msg.Tuple.DPort != 0 {
		destinationPort = &wrapperspb.UInt32Value{
			Value: uint32(event.Msg.Tuple.DPort),
		}
	}

	var proc, parent *tetragon.Process
	processInt, parentInt := process.GetParentProcessInternal(event.Msg.ProcessKey.Pid, event.Msg.ProcessKey.Ktime)
	if processInt == nil {
		proc = &tetragon.Process{
			Pid:       &wrapperspb.UInt32Value{Value: event.Msg.ProcessKey.Pid},
			StartTime: ktime.ToProto(event.Msg.ProcessKey.Ktime),
		}
		logger.GetLogger().Debug("process not found in cache", "id in TLS event", process.GetProcessID(event.Msg.ProcessKey.Pid, event.Msg.ProcessKey.Ktime))
	} else {
		proc = processInt.UnsafeGetProcess()
	}
	if parentInt != nil {
		parent = parentInt.UnsafeGetProcess()
	}

	typeSNI, nameSNI := readertls.GetTLSSNI(event.Msg.ClientHello.SNI.Value)

	clientVersion := readertls.GetTLSVersion(event.Msg.ClientHello.Version)
	serverVersion := readertls.GetTLSVersion(event.Msg.ServerHello.Version)
	negotiatedVersion := readertls.GetTLSSupportedVersions(&event.Msg.ServerHello.SupportedVersions, false)
	// For TLS <1.3, this will not be set. So do version discovery here instead.
	if negotiatedVersion == "" {
		negotiatedVersion = readertls.GetTLSNegotitatedVersion12(clientVersion, serverVersion)
	}

	fgsEvent := &tetragon.Tls{
		Process:             proc,
		Parent:              parent,
		SourceIp:            networkapi.GetIP(event.Msg.Tuple.SAddr, event.Msg.Common.Op, event.Msg.Tuple.IPv6 != 0).String(),
		SourcePort:          sourcePort,
		DestinationIp:       networkapi.GetIP(event.Msg.Tuple.DAddr, event.Msg.Common.Op, event.Msg.Tuple.IPv6 != 0).String(),
		DestinationPort:     destinationPort,
		NegotiatedVersion:   negotiatedVersion,
		SupportedVersions:   readertls.GetTLSSupportedVersions(&event.Msg.ClientHello.SupportedVersions, true),
		SniName:             nameSNI,
		SniType:             typeSNI,
		Cipher:              ciphers.GetTLSCiphers(&event.Msg.ServerHello.Cipher),
		ClientFlags:         readertls.GetTLSFlags(event.Msg.ClientHello.Flags),
		ServerFlags:         readertls.GetTLSFlags(event.Msg.ServerHello.Flags),
		ClientVersion:       clientVersion,
		ServerVersion:       serverVersion,
		ClientAlert:         readertls.GetTLSAlert(event.Msg.ClientHello.AlertLevel, event.Msg.ClientHello.AlertDescription),
		ServerAlert:         readertls.GetTLSAlert(event.Msg.ServerHello.AlertLevel, event.Msg.ServerHello.AlertDescription),
		ClientSession:       readertls.GetTLSSession(&event.Msg.ClientHello.Session),
		ServerSession:       readertls.GetTLSSession(&event.Msg.ServerHello.Session),
		Certificates:        event.ServerCert.Certificates,
		CertificateError:    getTLSCertificateErrorCode(event.ServerCert.Error),
		ParserInternalState: event.ServerCert.ParserState.String(),
	}
	ec := eventcache.Get()
	if ec != nil && ec.Needed(proc) || (proc.Pid.Value > 1 && ec.Needed(parent)) {
		ec.Add(nil, fgsEvent, event.Msg.Common.Ktime, event.Msg.ProcessKey.Ktime, event)
		return nil
	}
	eventmetrics.HandleTlsEvent(fgsEvent)
	return fgsEvent
}

func (msg *MsgTLSEventUnix) RetryInternal(ev notify.Event, timestamp uint64) (*process.ProcessInternal, error) {
	p := ev.GetProcess()
	return eventcache.HandleGenericInternal(ev, p.Pid.Value, nil, timestamp)
}

func (msg *MsgTLSEventUnix) Retry(internal *process.ProcessInternal, ev notify.Event) error {
	return eventcache.HandleGenericEvent(internal, ev, nil)
}

func (msg *MsgTLSEventUnix) Notify() bool {
	return true
}

func (msg *MsgTLSEventUnix) HandleMessage() *tetragon.GetEventsResponse {
	var res *tetragon.GetEventsResponse
	switch msg.Msg.Common.Op {
	case ops.MSG_OP_TLS:
		t := getTLS(msg)
		if t != nil {
			res = &tetragon.GetEventsResponse{
				Event: &tetragon.GetEventsResponse_Tls{Tls: t},
				Time:  ktime.ToProto(msg.Msg.Common.Ktime),
			}
		}
	default:
		logger.GetLogger().Warn("HandleTlsMessage: Unhandled event", "message", msg)
	}
	return res
}

func (msg *MsgTLSEventUnix) Cast(_ interface{}) notify.Message {
	return &MsgTLSEventUnix{}
}

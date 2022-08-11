package tls

import (
	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/eventcache"
	"github.com/cilium/tetragon/pkg/ktime"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/process"
	"github.com/cilium/tetragon/pkg/reader/node"
	"github.com/cilium/tetragon/pkg/reader/notify"
	"github.com/isovalent/hubble-fgs/pkg/api/ops"
	"github.com/isovalent/hubble-fgs/pkg/api/tlsapi"
	"github.com/isovalent/hubble-fgs/pkg/metrics/eventmetrics"
	"github.com/isovalent/hubble-fgs/pkg/reader/ciphers"
	"github.com/isovalent/hubble-fgs/pkg/reader/network"
	readertls "github.com/isovalent/hubble-fgs/pkg/reader/tls"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var (
	nodeName = node.GetNodeNameForExport()
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
	Common      processapi.MsgCommon
	Tuple       tlsapi.MsgTLSIPv4
	ClientHello tlsapi.MsgTLS
	ServerHello tlsapi.MsgTLS
	ServerCert  tlsapi.MsgTLSCertificates
	ProcessKey  processapi.MsgExecveKey
}

func ObserverTLSPrinter(msg *MsgTLSEventUnix, log logrus.FieldLogger) {
	op := msg.Common.Op
	typeSNI, nameSNI := readertls.GetTLSSNI(msg.ClientHello.SNI.Value)

	log.WithFields(logrus.Fields{
		"op":                           ops.OpCode(op).String(),
		"saddr":                        network.GetIPv4(msg.Tuple.SAddr, op).String(),
		"sport":                        network.GetSport(msg.Tuple.SPort),
		"dport":                        msg.Tuple.DPort,
		"daddr":                        network.GetIPv4(msg.Tuple.DAddr, op).String(),
		"Client-TLS-Version":           readertls.GetTLSVersion(msg.ClientHello.Version),
		"Server-TLS-Version":           readertls.GetTLSVersion(msg.ServerHello.Version),
		"SNI-Type":                     typeSNI,
		"SNI-Name":                     nameSNI,
		"Client-TLS-SupportedVersions": readertls.GetTLSSupportedVersions(&msg.ClientHello.SupportedVersions, true),
		"Server-TLS-SupportedVersions": readertls.GetTLSSupportedVersions(&msg.ServerHello.SupportedVersions, false),
		"cipher":                       ciphers.GetTLSCiphers(&msg.ServerHello.Cipher),
	}).Warn()
}

// GetTLS converts TLSEvent from hubble-fgs to protobuf message.
func getTLS(event *MsgTLSEventUnix) *tetragon.Tls {
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
		proc = &tetragon.Process{
			Pid:       &wrapperspb.UInt32Value{Value: event.ProcessKey.Pid},
			StartTime: ktime.ToProto(event.ProcessKey.Ktime),
		}
		logger.GetLogger().WithField("id in TLS event", processID).Debug("process not found in cache")
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
	ec := eventcache.Get()
	if ec != nil && ec.Needed(proc) {
		ec.Add(processInt, fgsEvent, event.ProcessKey.Ktime, event)
		return nil
	}
	if processInt != nil {
		fgsEvent.Process = processInt.GetProcessCopy()
	}
	eventmetrics.HandleTlsEvent(fgsEvent)
	return fgsEvent
}

func (msg *MsgTLSEventUnix) RetryInternal(ev notify.Event, timestamp uint64) (*process.ProcessInternal, error) {
	return eventcache.HandleGenericInternal(ev, timestamp)
}

func (msg *MsgTLSEventUnix) Retry(internal *process.ProcessInternal, ev notify.Event) error {
	return eventcache.HandleGenericEvent(internal, ev)
}

func (msg *MsgTLSEventUnix) HandleMessage() *tetragon.GetEventsResponse {
	var res *tetragon.GetEventsResponse
	switch msg.Common.Op {
	case ops.MSG_OP_TLS:
		t := getTLS(msg)
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

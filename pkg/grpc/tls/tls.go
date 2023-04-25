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
	Tuple       tlsapi.MsgTLSIP
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
		"saddr":                        network.GetIP(msg.Tuple.SAddr, op, msg.Tuple.IPv6 != 0).String(),
		"sport":                        network.GetSport(msg.Tuple.SPort),
		"dport":                        msg.Tuple.DPort,
		"daddr":                        network.GetIP(msg.Tuple.DAddr, op, msg.Tuple.IPv6 != 0).String(),
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

	var proc, parent *tetragon.Process
	processInt, parentInt := process.GetParentProcessInternal(event.ProcessKey.Pid, event.ProcessKey.Ktime)
	if processInt == nil {
		proc = &tetragon.Process{
			Pid:       &wrapperspb.UInt32Value{Value: event.ProcessKey.Pid},
			StartTime: ktime.ToProto(event.ProcessKey.Ktime),
		}
		logger.GetLogger().WithField("id in TLS event", process.GetProcessID(event.ProcessKey.Pid, event.ProcessKey.Ktime)).Debug("process not found in cache")
	} else {
		proc = processInt.UnsafeGetProcess()
	}
	if parentInt != nil {
		parent = parentInt.GetProcessCopy()
	}

	typeSNI, nameSNI := readertls.GetTLSSNI(event.ClientHello.SNI.Value)

	clientVersion := readertls.GetTLSVersion(event.ClientHello.Version)
	serverVersion := readertls.GetTLSVersion(event.ServerHello.Version)
	negotiatedVersion := readertls.GetTLSSupportedVersions(&event.ServerHello.SupportedVersions, false)
	// For TLS <1.3, this will not be set. So do version discovery here instead.
	if negotiatedVersion == "" {
		negotiatedVersion = readertls.GetTLSNegotitatedVersion12(clientVersion, serverVersion)
	}

	fgsEvent := &tetragon.Tls{
		Process:             proc,
		Parent:              parent,
		SourceIp:            network.GetIP(event.Tuple.SAddr, event.Common.Op, event.Tuple.IPv6 != 0).String(),
		SourcePort:          sourcePort,
		DestinationIp:       network.GetIP(event.Tuple.DAddr, event.Common.Op, event.Tuple.IPv6 != 0).String(),
		DestinationPort:     destinationPort,
		NegotiatedVersion:   negotiatedVersion,
		SupportedVersions:   readertls.GetTLSSupportedVersions(&event.ClientHello.SupportedVersions, true),
		SniName:             nameSNI,
		SniType:             typeSNI,
		Cipher:              ciphers.GetTLSCiphers(&event.ServerHello.Cipher),
		ClientFlags:         readertls.GetTLSFlags(event.ClientHello.Flags),
		ServerFlags:         readertls.GetTLSFlags(event.ServerHello.Flags),
		ClientVersion:       clientVersion,
		ServerVersion:       serverVersion,
		ClientAlert:         readertls.GetTLSAlert(event.ClientHello.AlertLevel, event.ClientHello.AlertDescription),
		ServerAlert:         readertls.GetTLSAlert(event.ServerHello.AlertLevel, event.ServerHello.AlertDescription),
		ClientSession:       readertls.GetTLSSession(&event.ClientHello.Session),
		ServerSession:       readertls.GetTLSSession(&event.ServerHello.Session),
		Certificates:        event.ServerCert.Certificates,
		CertificateError:    getTLSCertificateErrorCode(event.ServerCert.Error),
		ParserInternalState: event.ServerCert.ParserState.String(),
	}
	ec := eventcache.Get()
	if ec != nil && ec.Needed(proc) || (proc.Pid.Value > 1 && ec.Needed(parent)) {
		ec.Add(nil, fgsEvent, event.Common.Ktime, event.ProcessKey.Ktime, event)
		return nil
	}
	if processInt != nil {
		fgsEvent.Process = processInt.GetProcessCopy()
	}
	eventmetrics.HandleTlsEvent(fgsEvent)
	return fgsEvent
}

func (msg *MsgTLSEventUnix) RetryInternal(ev notify.Event, timestamp uint64) (*process.ProcessInternal, error) {
	p := ev.GetProcess()
	return eventcache.HandleGenericInternal(ev, p.Pid.Value, timestamp)
}

func (msg *MsgTLSEventUnix) Retry(internal *process.ProcessInternal, ev notify.Event) error {
	return eventcache.HandleGenericEvent(internal, ev)
}

func (msg *MsgTLSEventUnix) Notify() bool {
	return true
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

func (msg *MsgTLSEventUnix) Cast(_ interface{}) notify.Message {
	return &MsgTLSEventUnix{}
}

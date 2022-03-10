package udp

import (
	"bytes"
	"encoding/binary"
	"net"
	"unsafe"

	"github.com/isovalent/hubble-fgs/pkg/api"
	"github.com/isovalent/hubble-fgs/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/isovalent/hubble-fgs/pkg/logger"
	"github.com/isovalent/hubble-fgs/pkg/observer"
	"github.com/isovalent/hubble-fgs/pkg/sensors/burstEventsPoll"
	"github.com/yalue/native_endian"

	"golang.org/x/net/dns/dnsmessage"
)

const (
	defaultDnsPort = 53
	maxDnsPorts    = 4
)

func handleUdpPayload(r *bytes.Reader) ([]observer.ObserverEvent, error) {
	m := api.MsgIPv4Event{}
	err := binary.Read(r, native_endian.NativeEndian(), &m)
	if err != nil {
		logger.GetLogger().WithError(err).Warnf("Udp Payload Read error")
		return nil, err
	}
	return handleUdpDns(&m, r)
}

func handleUdpDns(m *api.MsgIPv4Event, r *bytes.Reader) ([]observer.ObserverEvent, error) {
	var p dnsmessage.Parser

	// Annotate msg with user space parser op type
	m.Common.Op = api.MSG_OP_IPV4_DNS

	buf := make([]byte, int(m.Common.Size)-int(unsafe.Sizeof(m)))

	if _, err := r.Read(buf); err != nil {
		logger.GetLogger().WithError(err).Warnf("Read error")
		return nil, err
	}

	var ips []net.IP
	var ipStrings []string
	var aTypes []uint32
	var qTypes []uint32
	var names []string

	hdr, err := p.Start(buf)
	if err != nil {
		logger.GetLogger().WithError(err).Warnf("Start error")
		return nil, err
	}

	qs, err := p.AllQuestions()
	if err != nil {
		logger.GetLogger().WithError(err).Warnf("Questions error")
		return nil, err
	}

	for _, q := range qs {
		names = append(names, q.Name.String())
	}

	for {
		h, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			logger.GetLogger().WithError(err).Warnf("Answer parse error")
			return nil, err
		}

		switch h.Type {
		case dnsmessage.TypeA:
			r, err := p.AResource()
			if err != nil {
				logger.GetLogger().WithError(err).Warnf("Resource parse error")
				return nil, err
			}
			ips = append(ips, r.A[:])
		case dnsmessage.TypeAAAA:
			r, err := p.AAAAResource()
			if err != nil {
				logger.GetLogger().WithError(err).Warnf("AAAA Resource parse error")
				return nil, err
			}
			ips = append(ips, r.AAAA[:])
		default:
			p.SkipAnswer()
		}
		aTypes = append(aTypes, uint32(h.Type))
	}

	for _, ip := range ips {
		ipStrings = append(ipStrings, ip.String())
	}

	msgDns := api.MsgDns{
		Response:      hdr.Response,
		RCode:         uint16(hdr.RCode),
		AnswerTypes:   aTypes,
		QuestionTypes: qTypes,
		Names:         names,
		IPs:           ipStrings,
	}

	msgUnix := &api.MsgIPv4DnsUnix{
		Common:     m.Common,
		Tuple:      m.Tuple,
		Return:     m.Return,
		ProcessKey: m.ProcessKey,
		SockCookie: m.SockCookie,
		Dns:        msgDns,
	}
	return []observer.ObserverEvent{msgUnix}, nil
}

// ParseUdpSpec parses the input yaml/crd and outputs the kernel selectors
// needed for BPF to identify UDP options.
//
func ParseUdpSpec(spec *v1alpha1.TracingPolicySpec) (*udpSensorConfigValue, error) {
	config := udpSensorConfigValue{}
	ParseDnsSpec(&config, spec)
	ParseUdpBurstSpec(&config, spec)

	return &config, nil
}

// ParseDNSSepec parses the input yaml/crd and outputs the kernel selectors
// needed for BPF to identify DNS and run DNS parser on it.
//
// The maximum number of DNS ports is fixed to maxDnsPorts. Changing this requires changing
// the map in bpf_inet.h.
func ParseDnsSpec(config *udpSensorConfigValue, spec *v1alpha1.TracingPolicySpec) {
	if spec.Parser.Dns.Enable {
		// Only consider the first maxDnsPorts ports that are specified
		if len(spec.Parser.Dns.Ports) == 0 {
			config.dnsPorts[0] = defaultDnsPort
		} else if len(spec.Parser.Dns.Ports) <= maxDnsPorts {
			copy(config.dnsPorts[:], spec.Parser.Dns.Ports)
		} else {
			copy(config.dnsPorts[:], spec.Parser.Dns.Ports[0:maxDnsPorts])
		}

		// Enable DNS cache in core, abstraction breaking but
		// fix is to do in kernel BPF parser.
		observer.EnableDns()
		logger.GetLogger().Info("Enable DNS")
	}
}

// ParseUdpBurst parses the input yaml/crd and outputs the kernel selectors
// needed for BPF to identify UDP bursts and run the monitor on it.
func ParseUdpBurstSpec(config *udpSensorConfigValue, spec *v1alpha1.TracingPolicySpec) {
	if spec.Parser.Udp.Burst.Enable && spec.Parser.Udp.Burst.WindowSize > 0 && spec.Parser.Udp.Burst.TriggerPercent > 0 {
		config.watermarkEnable = 1
		// WindowSize is in milliseconds
		config.watermarkAvgWindowSizeMs = uint64(spec.Parser.Udp.Burst.WindowSize)
		// The actual window size we use in calculations is a) in nanoseconds;
		// and b) is 2/3 of the provided window size because the measurement window
		// varies between 1 window (2/3 window size) and 2 windows (4/3 window size), meaning
		// the average measurement window == window size.
		config.watermarkWindowSize = (uint64(spec.Parser.Udp.Burst.WindowSize) * 2 * 1000000) / 3
		// TriggerPercent is the percent above the average; we supply it as a percentage multiplier.
		config.watermarkTriggerPercent = uint64(spec.Parser.Udp.Burst.TriggerPercent) + 100
		go burstEventsPoll.Start(spec)
	} else {
		config.watermarkEnable = 0
		config.watermarkAvgWindowSizeMs = 0
		config.watermarkWindowSize = 0
		config.watermarkTriggerPercent = 0
	}
}

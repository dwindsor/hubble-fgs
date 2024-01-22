package udp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"unsafe"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/sirupsen/logrus"
	"github.com/yalue/native_endian"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/sys/unix"

	"github.com/isovalent/hubble-fgs/pkg/api/dnsapi"
	api "github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	"github.com/isovalent/hubble-fgs/pkg/api/ops"
	"github.com/isovalent/hubble-fgs/pkg/grpc/dnsproto"
	"github.com/isovalent/hubble-fgs/pkg/sensors/ip"
	"github.com/isovalent/hubble-fgs/pkg/sensors/networkWatermarksEvents"
	"github.com/isovalent/hubble-fgs/pkg/sensors/networklatency"
	"github.com/isovalent/hubble-fgs/pkg/sensors/udp/dnsconfig"
)

const (
	defaultDnsPort   = 53
	maxDnsPorts      = 4
	maxSeqCheckPorts = 8
)

func handleUdpPayload(r *bytes.Reader) ([]observer.Event, error) {
	m := api.MsgIPEvent{}
	err := binary.Read(r, native_endian.NativeEndian(), &m)
	if err != nil {
		logger.GetLogger().WithError(err).Warnf("Udp Payload Read error")
		return nil, err
	}
	return handleUdpDns(&m, r)
}

func handleUdpDns(m *api.MsgIPEvent, r *bytes.Reader) ([]observer.Event, error) {
	var p dnsmessage.Parser

	// Annotate msg with user space parser op type
	m.Common.Op = ops.MSG_OP_DNS

	buf := make([]byte, int(m.Common.Size)-int(unsafe.Sizeof(m)))

	if _, err := r.Read(buf); err != nil {
		logger.GetLogger().WithError(err).Warnf("Udp Dns Read error")
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
		qTypes = append(qTypes, uint32(q.Type))
	}

	for {
		h, err := p.AnswerHeader()

		if errors.Is(err, dnsmessage.ErrSectionDone) {
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

	msgDns := dnsapi.MsgDns{
		Response:      hdr.Response,
		RCode:         uint16(hdr.RCode),
		AnswerTypes:   aTypes,
		QuestionTypes: qTypes,
		Names:         names,
		IPs:           ipStrings,
	}

	msgUnix := &dnsproto.MsgDnsUnix{
		Msg: m,
		Dns: msgDns,
	}
	return []observer.Event{msgUnix}, nil
}

// ParseUdpSpec parses the input yaml/crd and outputs the kernel selectors
// needed for BPF to identify UDP options.
func ParseUdpSpec(spec *v1alpha1.TracingPolicySpec) (ConfigValue, networklatency.ProtocolConfig) {
	config := ConfigValue{}
	ParseDnsSpec(&config, spec)
	ParseUdpWatermarksSpec(&config, spec)
	latencyConfig, _ := networklatency.ParseLatencySpec(spec.Parser.Udp.Latency, unix.IPPROTO_UDP)
	ParseSeqCheckSpec(&config, spec)
	ParseDisableSpec(spec)

	return config, latencyConfig
}

// ParseDNSSepec parses the input yaml/crd and outputs the kernel selectors
// needed for BPF to identify DNS and run DNS parser on it.
//
// The maximum number of DNS ports is fixed to maxDnsPorts. Changing this requires changing
// the map in bpf_inet.h.
func ParseDnsSpec(config *ConfigValue, spec *v1alpha1.TracingPolicySpec) {
	if spec.Parser.Dns.Enable {
		// Only consider the first maxDnsPorts ports that are specified
		if len(spec.Parser.Dns.Ports) == 0 {
			config.dnsPorts[0] = defaultDnsPort
		} else if len(spec.Parser.Dns.Ports) <= maxDnsPorts {
			copy(config.dnsPorts[:], spec.Parser.Dns.Ports)
		} else {
			copy(config.dnsPorts[:], spec.Parser.Dns.Ports[0:maxDnsPorts])
		}

		if spec.Parser.Dns.Metrics != nil {
			dnsconfig.MetricsEnabled = spec.Parser.Dns.Metrics.Enable
		} else {
			dnsconfig.MetricsEnabled = true
		}

		// Enable DNS cache in core, abstraction breaking but
		// fix is to do in kernel BPF parser.
		ip.EnableDns()
		logger.GetLogger().Info("Enable DNS")
	} else {
		// If DNS is disabled and udp enabled then we can disable
		// dns caching.
		ip.DisableDns()
	}
}

// ParseUdpWatermarksSpec parses the input yaml/crd and outputs the kernel selectors
// needed for BPF to identify UDP watermarks and run the monitor on it.
func ParseUdpWatermarksSpec(config *ConfigValue, spec *v1alpha1.TracingPolicySpec) {
	if spec.Parser.Udp.Watermarks.Enable && spec.Parser.Udp.Watermarks.WindowSize > 0 && spec.Parser.Udp.Watermarks.BurstTriggerPercent > 0 {
		watermarkEnabled = true
		config.watermarksEnable = 1
		// WindowSize is in milliseconds
		config.watermarksAvgWindowSizeMs = uint64(spec.Parser.Udp.Watermarks.WindowSize)
		// The actual window size we use in calculations is a) in nanoseconds;
		// and b) is 2/3 of the provided window size because the measurement window
		// varies between 1 window (2/3 window size) and 2 windows (4/3 window size), meaning
		// the average measurement window == window size.
		config.watermarksWindowSize = (uint64(spec.Parser.Udp.Watermarks.WindowSize) * 2 * 1000000) / 3
		// BurstTriggerPercent is the percent above the average; we supply it as a percentage multiplier.
		config.watermarksBurstTriggerPercent = uint64(spec.Parser.Udp.Watermarks.BurstTriggerPercent) + 100
		// DipTriggerPercent is the percent below the average; we supply it as a percentage multiplier.
		config.watermarksDipTriggerPercent = 100 - uint64(spec.Parser.Udp.Watermarks.DipTriggerPercent)
		go networkWatermarksEvents.Start(spec, unix.IPPROTO_UDP, false)
	} else if spec.Parser.Udp.Burst.Enable && spec.Parser.Udp.Burst.WindowSize > 0 && spec.Parser.Udp.Burst.TriggerPercent > 0 {
		watermarkEnabled = true
		config.watermarksEnable = 1
		// WindowSize is in milliseconds
		config.watermarksAvgWindowSizeMs = uint64(spec.Parser.Udp.Burst.WindowSize)
		// The actual window size we use in calculations is a) in nanoseconds;
		// and b) is 2/3 of the provided window size because the measurement window
		// varies between 1 window (2/3 window size) and 2 windows (4/3 window size), meaning
		// the average measurement window == window size.
		config.watermarksWindowSize = (uint64(spec.Parser.Udp.Burst.WindowSize) * 2 * 1000000) / 3
		// TriggerPercent is the percent above the average; we supply it as a percentage multiplier.
		config.watermarksBurstTriggerPercent = uint64(spec.Parser.Udp.Burst.TriggerPercent) + 100
		go networkWatermarksEvents.Start(spec, unix.IPPROTO_UDP, true)
	} else {
		config.watermarksEnable = 0
		config.watermarksAvgWindowSizeMs = 0
		config.watermarksWindowSize = 0
		config.watermarksBurstTriggerPercent = 0
		config.watermarksDipTriggerPercent = 0
	}
}

// ParseSeqCheckSpec parses the input yaml/crd and outputs the kernel selectors
// needed for BPF to identify applications with sequence numbers and the ports
// associated with it.
//
// The maximum number of ports is fixed to maxSeqCheckPorts. Changing this requires changing
// the map in bpf_inet.h.
func ParseSeqCheckSpec(config *ConfigValue, spec *v1alpha1.TracingPolicySpec) {
	if spec.Parser.Udp.SeqCheck.Enable && spec.Parser.Udp.SeqCheck.AppId > 0 && len(spec.Parser.Udp.SeqCheck.Ports) > 0 {
		// Only consider the first maxSeqCheckPorts ports that are specified
		if len(spec.Parser.Udp.SeqCheck.Ports) <= maxSeqCheckPorts {
			copy(config.seqCheckPorts[:], spec.Parser.Udp.SeqCheck.Ports)
		} else {
			copy(config.seqCheckPorts[:], spec.Parser.Udp.SeqCheck.Ports[0:maxSeqCheckPorts])
		}
		config.seqCheckAppId = spec.Parser.Udp.SeqCheck.AppId
		logger.GetLogger().WithField("Application ID", spec.Parser.Udp.SeqCheck.AppId).Info("Enable UDP sequence checking")
	} else {
		config.seqCheckAppId = 0
	}
}

func ParseDisableSpec(spec *v1alpha1.TracingPolicySpec) {
	disableConnectEvents = spec.Parser.Udp.DisableEvents.DisableConnect
	disableListenEvents = spec.Parser.Udp.DisableEvents.DisableListen
	disableCloseEvents = spec.Parser.Udp.DisableEvents.DisableClose
	disableStatsEvents = spec.Parser.Udp.DisableEvents.DisableStats
	logger.GetLogger().WithField("disableEvents", spec.Parser.Udp.DisableEvents).Warn("UDP")
	logger.GetLogger().WithFields(logrus.Fields{"disableConnect": disableCloseEvents, "disableListen": disableListenEvents,
		"disableClose": disableCloseEvents, "disableStats": disableStatsEvents}).Info("UDP event types")
}

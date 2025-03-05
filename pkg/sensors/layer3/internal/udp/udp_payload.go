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
	networkapi "github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	"github.com/isovalent/hubble-fgs/pkg/api/ops"
	"github.com/isovalent/hubble-fgs/pkg/grpc/dnsproto"
	"github.com/isovalent/hubble-fgs/pkg/option"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3/dnsconfig"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3/internal/ip"
	"github.com/isovalent/hubble-fgs/pkg/sensors/networkWatermarksEvents"
	"github.com/isovalent/hubble-fgs/pkg/sensors/networklatency"
)

const (
	defaultDnsPort = 53
)

func handleUdpPayload(r *bytes.Reader) ([]observer.Event, error) {
	m := networkapi.MsgIPEvent{}
	err := binary.Read(r, native_endian.NativeEndian(), &m)
	if err != nil {
		logger.GetLogger().WithError(err).Warnf("Udp Payload Read error")
		return nil, err
	}
	return handleUdpDns(&m, r)
}

func handleUdpDns(m *networkapi.MsgIPEvent, r *bytes.Reader) ([]observer.Event, error) {
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
func ParseUdpSpec(spec *v1alpha1.TracingPolicySpec) (networkapi.UdpConfigValue, networklatency.ProtocolConfig) {
	config := networkapi.UdpConfigValue{}
	ParseOptions(&config)
	ParseDnsSpec(&config, spec)
	ParseUdpWatermarksSpec(&config, spec)
	latencyConfig, _ := networklatency.ParseLatencySpec(spec.Parser.Udp.Latency, unix.IPPROTO_UDP)
	ParseSeqCheckSpec(&config, spec)
	ParseDisableSpec(&config, spec)

	return config, latencyConfig
}

// ParseOptions parses the command line options into the config
func ParseOptions(config *networkapi.UdpConfigValue) {
	config.DnsStatsPerSocket = 0
	if option.Config.DNSStatsPerSocket {
		config.DnsStatsPerSocket = 1
	}
}

// ParseDNSSepec parses the input yaml/crd and outputs the kernel selectors
// needed for BPF to identify DNS and run DNS parser on it.
//
// The maximum number of DNS ports is fixed to maxDnsPorts. Changing this requires changing
// the map in bpf_inet.h.
func ParseDnsSpec(config *networkapi.UdpConfigValue, spec *v1alpha1.TracingPolicySpec) {
	// Store DNS ports even if DNS parsing is disabled as these are used for grouping DNS UDP stats.
	// Only consider the first maxDnsPorts ports that are specified
	if len(spec.Parser.Dns.Ports) == 0 {
		config.DnsPorts[0] = defaultDnsPort
	} else if len(spec.Parser.Dns.Ports) <= networkapi.UdpMaxDnsPorts {
		copy(config.DnsPorts[:], spec.Parser.Dns.Ports)
	} else {
		copy(config.DnsPorts[:], spec.Parser.Dns.Ports[0:networkapi.UdpMaxDnsPorts])
	}

	if !spec.Parser.Dns.Enable {
		// If DNS is disabled and udp enabled then we can disable
		// dns caching.
		ip.DisableDns()
		return
	}
	if spec.Parser.Dns.Metrics != nil {
		dnsconfig.MetricsEnabled = spec.Parser.Dns.Metrics.Enable
		dnsconfig.CurrentLabels = dnsconfig.DefaultLabelFilter().WithEnabledLabels(spec.Parser.Dns.Metrics.LabelFilter)
	} else {
		dnsconfig.MetricsEnabled = true
		dnsconfig.CurrentLabels = dnsconfig.DefaultLabelFilter()
	}
	config.DnsReportQuestions = 0
	if spec.Parser.Dns.ReportQuestions {
		config.DnsReportQuestions = 1
	}

	// Enable DNS cache in core, abstraction breaking but
	// fix is to do in kernel BPF parser.
	ip.EnableDns()
	logger.GetLogger().Info("Enable DNS")
}

// ParseUdpWatermarksSpec parses the input yaml/crd and outputs the kernel selectors
// needed for BPF to identify UDP watermarks and run the monitor on it.
func ParseUdpWatermarksSpec(config *networkapi.UdpConfigValue, spec *v1alpha1.TracingPolicySpec) {
	if spec.Parser.Udp.Watermarks.Enable && spec.Parser.Udp.Watermarks.WindowSize > 0 && spec.Parser.Udp.Watermarks.BurstTriggerPercent > 0 {
		WatermarksEnabled = true
		config.WatermarksEnable = 1
		// WindowSize is in milliseconds
		config.WatermarksAvgWindowSizeMs = uint64(spec.Parser.Udp.Watermarks.WindowSize)
		// The actual window size we use in calculations is a) in nanoseconds;
		// and b) is 2/3 of the provided window size because the measurement window
		// varies between 1 window (2/3 window size) and 2 windows (4/3 window size), meaning
		// the average measurement window == window size.
		config.WatermarksWindowSize = (uint64(spec.Parser.Udp.Watermarks.WindowSize) * 2 * 1000000) / 3
		// BurstTriggerPercent is the percent above the average; we supply it as a percentage multiplier.
		config.WatermarksBurstTriggerPercent = uint64(spec.Parser.Udp.Watermarks.BurstTriggerPercent) + 100
		// DipTriggerPercent is the percent below the average; we supply it as a percentage multiplier.
		config.WatermarksDipTriggerPercent = 100 - uint64(spec.Parser.Udp.Watermarks.DipTriggerPercent)
		go networkWatermarksEvents.Start(spec, unix.IPPROTO_UDP, false)
	} else if spec.Parser.Udp.Burst.Enable && spec.Parser.Udp.Burst.WindowSize > 0 && spec.Parser.Udp.Burst.TriggerPercent > 0 {
		WatermarksEnabled = true
		config.WatermarksEnable = 1
		// WindowSize is in milliseconds
		config.WatermarksAvgWindowSizeMs = uint64(spec.Parser.Udp.Burst.WindowSize)
		// The actual window size we use in calculations is a) in nanoseconds;
		// and b) is 2/3 of the provided window size because the measurement window
		// varies between 1 window (2/3 window size) and 2 windows (4/3 window size), meaning
		// the average measurement window == window size.
		config.WatermarksWindowSize = (uint64(spec.Parser.Udp.Burst.WindowSize) * 2 * 1000000) / 3
		// TriggerPercent is the percent above the average; we supply it as a percentage multiplier.
		config.WatermarksBurstTriggerPercent = uint64(spec.Parser.Udp.Burst.TriggerPercent) + 100
		go networkWatermarksEvents.Start(spec, unix.IPPROTO_UDP, true)
	} else {
		config.WatermarksEnable = 0
		config.WatermarksAvgWindowSizeMs = 0
		config.WatermarksWindowSize = 0
		config.WatermarksBurstTriggerPercent = 0
		config.WatermarksDipTriggerPercent = 0
	}
}

// ParseSeqCheckSpec parses the input yaml/crd and outputs the kernel selectors
// needed for BPF to identify applications with sequence numbers and the ports
// associated with it.
//
// The maximum number of ports is fixed to maxSeqCheckPorts. Changing this requires changing
// the map in bpf_inet.h.
func ParseSeqCheckSpec(config *networkapi.UdpConfigValue, spec *v1alpha1.TracingPolicySpec) {
	if spec.Parser.Udp.SeqCheck.Enable && spec.Parser.Udp.SeqCheck.AppId > 0 && len(spec.Parser.Udp.SeqCheck.Ports) > 0 {
		// Only consider the first maxSeqCheckPorts ports that are specified
		if len(spec.Parser.Udp.SeqCheck.Ports) <= networkapi.UdpMaxSeqCheckPorts {
			copy(config.SeqCheckPorts[:], spec.Parser.Udp.SeqCheck.Ports)
		} else {
			copy(config.SeqCheckPorts[:], spec.Parser.Udp.SeqCheck.Ports[0:networkapi.UdpMaxSeqCheckPorts])
		}
		config.SeqCheckAppId = spec.Parser.Udp.SeqCheck.AppId
		logger.GetLogger().WithField("Application ID", spec.Parser.Udp.SeqCheck.AppId).Info("Enable UDP sequence checking")
	} else {
		config.SeqCheckAppId = 0
	}
}

func ParseDisableSpec(config *networkapi.UdpConfigValue, spec *v1alpha1.TracingPolicySpec) {
	DisableConnectEvents = spec.Parser.Udp.DisableEvents.DisableConnect
	DisableListenEvents = spec.Parser.Udp.DisableEvents.DisableListen
	DisableCloseEvents = spec.Parser.Udp.DisableEvents.DisableClose
	DisableStatsEvents = spec.Parser.Udp.DisableEvents.DisableStats
	config.DisableListenEvents = 0
	if DisableListenEvents {
		config.DisableListenEvents = 1
	}
	logger.GetLogger().WithFields(logrus.Fields{"disableConnect": DisableCloseEvents, "disableListen": DisableListenEvents,
		"disableClose": DisableCloseEvents, "disableStats": DisableStatsEvents}).Info("UDP event types")
}

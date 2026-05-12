// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package udp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/yalue/native_endian"
	"golang.org/x/net/dns/dnsmessage"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"

	"github.com/isovalent/hubble-fgs/pkg/api/dnsapi"
	networkapi "github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	"github.com/isovalent/hubble-fgs/pkg/api/ops"
	"github.com/isovalent/hubble-fgs/pkg/grpc/dnsproto"
	"github.com/isovalent/hubble-fgs/pkg/option"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3/dnsconfig"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3/internal/ip"
	"github.com/isovalent/hubble-fgs/pkg/sensors/networkWatermarksEvents"
)

const (
	defaultDnsPort = 53
	// maxDNSAnswers limits DNS answers to prevent memory exhaustion.
	// Based on EDNS max size (4096 bytes) and minimal record size (~20 bytes).
	maxDNSAnswers = 200
)

func handleUdpPayload(r *bytes.Reader) ([]observer.Event, error) {
	m := networkapi.MsgIPEvent{}
	err := binary.Read(r, native_endian.NativeEndian(), &m)
	if err != nil {
		logger.GetLogger().Warn("Udp Payload Read error", logfields.Error, err)
		return nil, err
	}
	return handleUdpDns(&m, r)
}

func parseDNSMessage(buf []byte) (*dnsapi.MsgDns, error) {
	var p dnsmessage.Parser
	var ips []net.IP
	var ipStrings []string
	var aTypes []uint32
	var qTypes []uint32
	var names []string

	hdr, err := p.Start(buf)
	if err != nil {
		return nil, fmt.Errorf("starting DNS parser: %w", err)
	}

	qs, err := p.AllQuestions()
	if err != nil {
		return nil, fmt.Errorf("parsing DNS questions: %w", err)
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
			return nil, fmt.Errorf("parsing DNS answer header: %w", err)
		}

		if len(aTypes) >= maxDNSAnswers {
			return nil, fmt.Errorf("too many DNS answers: limit is %d", maxDNSAnswers)
		}

		switch h.Type {
		case dnsmessage.TypeA:
			r, err := p.AResource()
			if err != nil {
				return nil, fmt.Errorf("parsing A resource: %w", err)
			}
			ips = append(ips, r.A[:])
		case dnsmessage.TypeAAAA:
			r, err := p.AAAAResource()
			if err != nil {
				return nil, fmt.Errorf("parsing AAAA resource: %w", err)
			}
			ips = append(ips, r.AAAA[:])
		default:
			if err := p.SkipAnswer(); err != nil {
				return nil, fmt.Errorf("skipping answer: %w", err)
			}
		}
		aTypes = append(aTypes, uint32(h.Type))
	}

	for _, ip := range ips {
		ipStrings = append(ipStrings, ip.String())
	}

	return &dnsapi.MsgDns{
		Response:      hdr.Response,
		RCode:         uint16(hdr.RCode),
		AnswerTypes:   aTypes,
		QuestionTypes: qTypes,
		Names:         names,
		IPs:           ipStrings,
	}, nil
}

func handleUdpDns(m *networkapi.MsgIPEvent, r *bytes.Reader) ([]observer.Event, error) {
	// Annotate msg with user space parser op type
	m.Common.Op = ops.MSG_OP_DNS

	buf := make([]byte, int(m.Common.Size)-int(unsafe.Sizeof(m)))

	if _, err := r.Read(buf); err != nil {
		logger.GetLogger().Warn("Udp Dns Read error", logfields.Error, err)
		return nil, err
	}

	msgDns, err := parseDNSMessage(buf)
	if err != nil {
		logger.GetLogger().Warn("DNS parser error", logfields.Error, err)
		return nil, fmt.Errorf("parsing DNS message: %w", err)
	}

	msgUnix := &dnsproto.MsgDnsUnix{
		Msg: m,
		Dns: *msgDns,
	}
	return []observer.Event{msgUnix}, nil
}

// ParseUdpSpec parses the input yaml/crd and outputs the kernel selectors
// needed for BPF to identify UDP options.
func ParseUdpSpec(spec *v1alpha1.TracingPolicySpec) networkapi.UdpConfigValue {
	config := networkapi.UdpConfigValue{}
	ParseOptions(&config)
	ParseDnsSpec(&config, spec)
	ParseUdpWatermarksSpec(&config, spec)
	ParseDisableSpec(&config, spec)

	return config
}

// ParseOptions parses the command line options into the config
func ParseOptions(config *networkapi.UdpConfigValue) {
	config.DnsStatsPerSocket = 0
	if option.Config.DNSStatsPerSocket {
		config.DnsStatsPerSocket = 1
	}

	parseDNSPortsOption(config)

	ParseMulticastOptions(config)
}

func parseDNSPortsOption(config *networkapi.UdpConfigValue) {
	if len(option.Config.DNSPorts) > 0 {
		// Values should be validated in validateConfig to fit within
		// uint16 and to not exceed the max number of ports. We can't
		// copy directly because of the type cast.
		for i := range config.DnsPorts {
			if len(option.Config.DNSPorts) <= i {
				break
			}
			config.DnsPorts[i] = uint16(option.Config.DNSPorts[i])
		}
	} else {
		config.DnsPorts[0] = defaultDnsPort
	}
}

func InitDNS() {
	ParseOptions(&Config)
}

// InitKernelDNS is separated from InitDNS because it can be called
// independently when initializing the BPF DNS parser options bundled in the UDP
// options without the rest of the userspace DNS options.
func InitKernelDNS() {
	parseDNSPortsOption(&Config)
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
	if spec.Parser.Udp != nil && spec.Parser.Udp.Watermarks.Enable && spec.Parser.Udp.Watermarks.WindowSize > 0 && spec.Parser.Udp.Watermarks.BurstTriggerPercent > 0 {
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
		go networkWatermarksEvents.Start(time.Duration(spec.Parser.NetworkWatermarksExitGen.Interval)*time.Millisecond, syscall.IPPROTO_UDP, false)
	} else if spec.Parser.Udp != nil && spec.Parser.Udp.Burst.Enable && spec.Parser.Udp.Burst.WindowSize > 0 && spec.Parser.Udp.Burst.TriggerPercent > 0 {
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
		go networkWatermarksEvents.Start(time.Duration(spec.Parser.NetworkWatermarksExitGen.Interval)*time.Millisecond, syscall.IPPROTO_UDP, true)
	} else {
		config.WatermarksEnable = 0
		config.WatermarksAvgWindowSizeMs = 0
		config.WatermarksWindowSize = 0
		config.WatermarksBurstTriggerPercent = 0
		config.WatermarksDipTriggerPercent = 0
	}
}

// ParseMulticastSpec parses the Tetragon config and outputs the kernel selectors
// needed for BPF to identify multicast applications by their ports, and whether to
// detect sequence gaps.
//
// The maximum number of ports is fixed to maxMulticastPorts. Changing this requires changing
// the map in bpf_inet.h.
func ParseMulticastOptions(config *networkapi.UdpConfigValue) {
	if option.Config.MulticastAppID > 0 && len(option.Config.MulticastPorts) > 0 {
		// Only consider the first maxMulticastPorts ports that are specified
		for portIdx, inPort := range option.Config.MulticastPorts {
			if portIdx >= networkapi.UdpMaxMulticastPorts {
				break
			}
			config.MulticastPorts[portIdx] = uint16(inPort)
		}
		config.MulticastAppId = uint64(option.Config.MulticastAppID)
		if option.Config.MulticastSeqCheck {
			config.EnableMulticastSeqCheck = 1
		}
		if option.Config.MulticastSamplePercent > 0 {
			config.MulticastSampleThreshold = uint32(math.Round(option.Config.MulticastSamplePercent * 0xFFFFFFFF / 100))
		}
		logger.GetLogger().Info("Enable UDP multicast observability", "Application", option.Config.MulticastApp,
			"Ports", option.Config.MulticastPorts, "Sequence Checking", option.Config.MulticastSeqCheck,
			"Sample threshold", config.MulticastSampleThreshold)
	} else {
		config.MulticastAppId = 0
		config.EnableMulticastSeqCheck = 0
	}
}

func ParseDisableSpec(config *networkapi.UdpConfigValue, spec *v1alpha1.TracingPolicySpec) {
	if spec.Parser.Udp != nil {
		DisableConnectEvents = spec.Parser.Udp.DisableEvents.DisableConnect
		DisableListenEvents = spec.Parser.Udp.DisableEvents.DisableListen
		DisableCloseEvents = spec.Parser.Udp.DisableEvents.DisableClose
		DisableStatsEvents = spec.Parser.Udp.DisableEvents.DisableStats
	}
	config.DisableListenEvents = 0
	if DisableListenEvents {
		config.DisableListenEvents = 1
	}
	logger.GetLogger().Info("UDP event types", "disableConnect", DisableCloseEvents, "disableListen", DisableListenEvents,
		"disableClose", DisableCloseEvents, "disableStats", DisableStatsEvents)
}

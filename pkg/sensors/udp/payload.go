package udp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"time"
	"unsafe"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/timer"
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
)

const (
	defaultDnsPort    = 53
	maxDnsPorts       = 4
	maxLatencySubnets = 4
	maxLatencyPorts   = 4
)

var (
	clockUpdateTimer   = timer.NewPeriodicTimer("UDP Clock Update Timer", checkClock, true)
	clockCheckInterval = uint32(0)
	clockMaxSkew       = uint32(0)
	latencyInterfaces  []string
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
		Common:     m.Common,
		Tuple:      m.Tuple,
		Return:     m.Return,
		ProcessKey: m.ProcessKey,
		SockCookie: m.SockCookie,
		Dns:        msgDns,
	}
	return []observer.Event{msgUnix}, nil
}

// ParseUdpSpec parses the input yaml/crd and outputs the kernel selectors
// needed for BPF to identify UDP options.
func ParseUdpSpec(spec *v1alpha1.TracingPolicySpec) (*ConfigValue, error) {
	config := ConfigValue{}
	ParseDnsSpec(&config, spec)
	ParseUdpWatermarksSpec(&config, spec)
	ConfigureBootTime(&config)
	ParseLatencySpec(&config, spec)

	return &config, nil
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
		go networkWatermarksEvents.Start(spec, IPPROTO_UDP, false)
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
		go networkWatermarksEvents.Start(spec, IPPROTO_UDP, true)
	} else {
		config.watermarksEnable = 0
		config.watermarksAvgWindowSizeMs = 0
		config.watermarksWindowSize = 0
		config.watermarksBurstTriggerPercent = 0
		config.watermarksDipTriggerPercent = 0
	}
}

// ParseLatencySpec parses the input yaml/crd and outputs the kernel selectors
// needed for BPF to observe UDP latency.
func ParseLatencySpec(config *ConfigValue, spec *v1alpha1.TracingPolicySpec) {
	if spec.Parser.Udp.Latency.Enable {
		config.latencyEnable = 1
		tcCheckInterval = time.Duration(spec.Parser.Udp.Latency.InterfacesCheckInterval) * time.Second
		latencyMin := spec.Parser.Udp.Latency.Min
		latencyMax := spec.Parser.Udp.Latency.Max
		if latencyMax <= latencyMin {
			logger.GetLogger().Warn("Misconfigured UDP latency Histogram: Min value must be less than Max")
			config.latencyEnable = 0
			return
		}
		latencyRange := float64(latencyMax - latencyMin)
		fLatencyMin := float64(latencyMin)
		config.latBucket00 = latencyMin
		config.latBucket01 = uint32((latencyRange * .01) + fLatencyMin)
		config.latBucket10 = uint32((latencyRange * .10) + fLatencyMin)
		config.latBucket25 = uint32((latencyRange * .25) + fLatencyMin)
		config.latBucket50 = uint32((latencyRange * .50) + fLatencyMin)
		config.latBucket75 = uint32((latencyRange * .75) + fLatencyMin)
		config.latBucket90 = uint32((latencyRange * .90) + fLatencyMin)
		config.latBucket99 = uint32((latencyRange * .99) + fLatencyMin)

		if len(spec.Parser.Udp.Latency.MatchSubnets) == 0 {
			// Do not enable latency if subnets not specified as packet mangling
			// has the opportunity to break networks.
			logger.GetLogger().Warn("UDP latency disabled due to no valid subnets")
			config.latencyEnable = 0
			return
		}
		index := 0
		for _, subnet := range spec.Parser.Udp.Latency.MatchSubnets {
			if index >= maxLatencySubnets {
				break
			}
			ip, ipnet, err := net.ParseCIDR(subnet)
			if err != nil {
				logger.GetLogger().WithField("subnet", subnet).Warn("Error parsing UDP latency subnet")
				continue
			}
			if ip.To4() == nil {
				logger.GetLogger().WithField("subnet", subnet).Warn("UDP latency only supported on IPv4")
				continue
			}
			prefixLen, _ := ipnet.Mask.Size()
			if prefixLen == 0 {
				logger.GetLogger().WithField("subnet", subnet).Warn("UDP latency only supports canonical subnets")
				continue
			}
			ipv4 := ipnet.IP.To4()
			config.latencySubnets[index].addr[0] = uint64(binary.LittleEndian.Uint32(ipv4))
			config.latencySubnets[index].ipv6 = 0
			config.latencySubnets[index].prefixLen = uint8(prefixLen)
			logger.GetLogger().Infof("UDP latency subnet: IP=%s/%d", ipv4, config.latencySubnets[index].prefixLen)
			index++
		}
		if index == 0 {
			// Do not enable latency if subnets not specified as packet mangling
			// has the opportunity to break networks.
			logger.GetLogger().Warn("UDP latency disabled due to no valid subnets")
			config.latencyEnable = 0
			return
		}

		logger.GetLogger().WithFields(logrus.Fields{"Min": latencyMin, "Range": latencyRange,
			"bucket00": config.latBucket00,
			"bucket01": config.latBucket01,
			"bucket10": config.latBucket10,
			"bucket25": config.latBucket25,
			"bucket50": config.latBucket50,
			"bucket75": config.latBucket75,
			"bucket90": config.latBucket90,
			"bucket99": config.latBucket99}).Info("Configured UDP latency buckets: ")

		clockCheckInterval = spec.Parser.Udp.Latency.ClockCheckInterval
		clockMaxSkew = spec.Parser.Udp.Latency.ClockMaxSkew

		latencyInterfaces = spec.Parser.Udp.Latency.Interfaces
		config.maxPacketSize = spec.Parser.Udp.Latency.MaxPacketSize

		// MatchPorts are strictly optional, as we have constrained the packet mangling
		// to the specified subnets, or refused to enable latency.
		if len(spec.Parser.Udp.Latency.MatchPorts) == 0 {
			config.latencyPorts[0] = 0
			return
		}
		if len(spec.Parser.Udp.Latency.MatchPorts) <= maxLatencyPorts {
			copy(config.latencyPorts[:], spec.Parser.Udp.Latency.MatchPorts)
		} else {
			copy(config.latencyPorts[:], spec.Parser.Dns.Ports[0:maxLatencyPorts])
		}
	} else {
		config.latencyEnable = 0
		config.latencySubnets[0].addr[0] = 0
		config.latencySubnets[0].ipv6 = 0
		config.latencyPorts[0] = 0
	}
}

// GetBootTime gets the boot time in nanoseconds, which is used in latency calculations
// between nodes.
func GetBootTime() (uint64, error) {
	clk := int32(unix.CLOCK_MONOTONIC)
	currentTime := unix.Timespec{}
	if err := unix.ClockGettime(clk, &currentTime); err != nil {
		return 0, fmt.Errorf("failed to get current monotonic time")
	}
	t := time.Now().Add(-time.Duration(currentTime.Nano()))
	return uint64(t.UnixNano()), nil
}

// ConfigureBootTime sets the boot time in nanoseconds, which is used in latency calculations
// between nodes.
func ConfigureBootTime(config *ConfigValue) {
	t, err := GetBootTime()
	if err != nil {
		logger.GetLogger().WithError(err).Warn("UDP sensor clock error")
		return
	}
	config.bootNs = t
}

// checkClock checks if the difference between the current boot time and the configured
// boot time is more than half a microsecond; if so, it updates the configuration.
func checkClock() {
	udpConfig, err := bpf.OpenMap(filepath.Join(bpf.MapPrefixPath(), UdpConfigMapName))
	if err != nil {
		logger.GetLogger().WithError(err).Warn("UDP checkClock failed to open configuration map")
		return
	}
	defer udpConfig.Close()

	key := &udpSensorConfigKey{
		Zero: uint32(0),
	}

	configValue, err := udpConfig.Lookup(key)
	if err != nil {
		logger.GetLogger().WithError(err).Warn("UDP checkClock failed to read configuration map")
		return
	}
	config := configValue.(*ConfigValue)

	t, err := GetBootTime()
	if err != nil {
		logger.GetLogger().WithError(err).Warn("UDP checkClock failed to get boot time")
		return
	}
	diff := int64(t - config.bootNs)
	if diff < 0 {
		diff = -diff
	}
	// Is the difference more than the max clock skew?
	if diff > int64(clockMaxSkew*1000) {
		old := config.bootNs
		config.bootNs = t
		err = udpConfig.Update(key, config)
		if err != nil {
			logger.GetLogger().WithError(err).Warn("UDP checkClock failed to update configuration map")
			return
		}
		logger.GetLogger().WithFields(logrus.Fields{"From": old, "To": t}).Debug("UDP checkClock updated")
	}
}

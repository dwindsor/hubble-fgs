//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package networklatency

import (
	"encoding/binary"
	"fmt"
	"net"
	"path/filepath"
	"sync"
	"time"
	"unsafe"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/cilium/tetragon/pkg/timer"
	"github.com/isovalent/hubble-fgs/pkg/sensors/program/tc"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

const (
	maxSubnets    = 4
	maxPorts      = 4
	ConfigMapName = "latency_config_map"
)

var (
	enabled              = make(map[uint16]bool)
	clockUpdateTimer     = timer.NewPeriodicTimer("Clock Update Timer", checkClock, true)
	clockCheckInterval   = uint32(0)
	clockMaxSkew         = uint32(0)
	interfaces           = make(map[uint16][]string)
	tcAttachedInterfaces = make(map[*program.Program]map[tc.NamespaceInterface]bool)
	tcAttaching          sync.Mutex
	tcList               []sensors.LoadProbeArgs
	tcCheckTimer         = timer.NewPeriodicTimer("TC Check Timer", runTcCheck, true)
	tcCheckInterval      = time.Duration(0)
	refCnt               = 0
	refCntMu             sync.Mutex
)

func TCEgressTimestamp(protocol uint16) (*program.Program, error) {
	pstr := ""
	switch protocol {
	case unix.IPPROTO_TCP:
		pstr = "tcp"
	case unix.IPPROTO_UDP:
		pstr = "udp"
	default:
		return nil, fmt.Errorf("unsupported protocol")
	}
	p := program.Builder(
		"bpf_timestamp.o",
		"egress_timestamp",
		"classifier/egress_timestamp",
		"classifier_egress_timestamp",
		fmt.Sprintf("%s_tc_egress", pstr),
	)
	return p, nil
}

type SubnetSelector struct {
	addr      [2]uint64
	ipv6      uint8
	prefixLen uint8
	Padding   [6]uint8
}

type configKey struct {
	zero uint32
}

type configValue struct {
	bootNs uint64
	udp    ProtocolConfig
	tcp    ProtocolConfig
}

type ProtocolConfig struct {
	enable        uint8
	Pad1          uint8
	maxPacketSize uint16
	Pad2          uint32
	subnets       [maxSubnets]SubnetSelector
	ports         [maxPorts]uint16
	latBucket00   uint32
	latBucket01   uint32
	latBucket10   uint32
	latBucket25   uint32
	latBucket50   uint32
	latBucket75   uint32
	latBucket90   uint32
	latBucket99   uint32
}

func (k *configKey) String() string             { return fmt.Sprintf("Zero: %d", k.zero) }
func (k *configKey) NewValue() bpf.MapValue     { return &configValue{} }
func (k *configKey) GetKeyPtr() unsafe.Pointer  { return unsafe.Pointer(k) }
func (k *configKey) DeepCopyMapKey() bpf.MapKey { return &configKey{} }

func (v *configValue) String() string {
	return fmt.Sprintf("UDP: {enable: %d, "+
		"maxPacketSize: %d, "+
		"B00: %d, "+
		"B01: %d, "+
		"B10: %d, "+
		"B25: %d, "+
		"B50: %d, "+
		"B75: %d, "+
		"B90: %d, "+
		"B99: %d}, "+
		"TCP: {enable: %d, "+
		"maxPacketSize: %d, "+
		"B00: %d, "+
		"B01: %d, "+
		"B10: %d, "+
		"B25: %d, "+
		"B50: %d, "+
		"B75: %d, "+
		"B90: %d, "+
		"B99: %d}, "+
		"bootNs: %d",
		v.udp.enable, v.udp.maxPacketSize, v.udp.latBucket00, v.udp.latBucket01, v.udp.latBucket10, v.udp.latBucket25,
		v.udp.latBucket50, v.udp.latBucket75, v.udp.latBucket90, v.udp.latBucket99,
		v.tcp.enable, v.tcp.maxPacketSize, v.tcp.latBucket00, v.tcp.latBucket01, v.tcp.latBucket10, v.tcp.latBucket25,
		v.tcp.latBucket50, v.tcp.latBucket75, v.tcp.latBucket90, v.tcp.latBucket99,
		v.bootNs)
}
func (v *configValue) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }
func (v *configValue) DeepCopyMapValue() bpf.MapValue {
	var n = *v
	return &n
}

// ParseLatencySpec parses the input yaml/crd and outputs the kernel selectors
// needed for BPF to observe latency.
func ParseLatencySpec(spec v1alpha1.LatencyPolicySpec, protocol uint16) (ProtocolConfig, error) {
	config := ProtocolConfig{}
	var protoStr string
	switch protocol {
	case unix.IPPROTO_UDP:
		protoStr = "UDP"
	case unix.IPPROTO_TCP:
		protoStr = "TCP"
	default:
		protoStr = "Unknown"
	}
	if spec.Enable {
		config.enable = 1
		enabled[protocol] = true
		if tcCheckInterval == time.Duration(0) || time.Duration(spec.InterfacesCheckInterval)*time.Second < tcCheckInterval {
			tcCheckInterval = time.Duration(spec.InterfacesCheckInterval) * time.Second
		}
		latencyMin := spec.Min
		latencyMax := spec.Max
		if latencyMax <= latencyMin {
			logger.GetLogger().Warnf("Misconfigured %s latency Histogram: Min value must be less than Max", protoStr)
			config.enable = 0
			enabled[protocol] = false
			return config, fmt.Errorf("Misconfigured %s latency Histogram: Min value must be less than Max", protoStr)
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

		if len(spec.MatchSubnets) == 0 {
			// Do not enable latency if subnets not specified as packet mangling
			// has the opportunity to break networks.
			logger.GetLogger().Warnf("%s latency disabled due to no valid subnets", protoStr)
			config.enable = 0
			enabled[protocol] = false
			return config, fmt.Errorf("%s latency disabled due to no valid subnets", protoStr)
		}
		index := 0
		for _, subnet := range spec.MatchSubnets {
			if index >= maxSubnets {
				break
			}
			ip, ipnet, err := net.ParseCIDR(subnet)
			if err != nil {
				logger.GetLogger().WithField("subnet", subnet).Warnf("Error parsing %s latency subnet", protoStr)
				continue
			}
			if ip.To4() == nil {
				logger.GetLogger().WithField("subnet", subnet).Warnf("%s latency only supported on IPv4", protoStr)
				continue
			}
			prefixLen, _ := ipnet.Mask.Size()
			if prefixLen == 0 {
				logger.GetLogger().WithField("subnet", subnet).Warnf("%s latency only supports canonical subnets", protoStr)
				continue
			}
			ipv4 := ipnet.IP.To4()
			config.subnets[index].addr[0] = uint64(binary.LittleEndian.Uint32(ipv4))
			config.subnets[index].ipv6 = 0
			config.subnets[index].prefixLen = uint8(prefixLen)
			logger.GetLogger().Infof("%s latency subnet: IP=%s/%d", protoStr, ipv4, config.subnets[index].prefixLen)
			index++
		}
		if index == 0 {
			// Do not enable latency if subnets not specified as packet mangling
			// has the opportunity to break networks.
			logger.GetLogger().Warnf("%s latency disabled due to no valid subnets", protoStr)
			config.enable = 0
			enabled[protocol] = false
			return config, fmt.Errorf("%s latency disabled due to no valid subnets", protoStr)
		}

		logger.GetLogger().WithFields(logrus.Fields{"Min": latencyMin, "Range": latencyRange,
			"bucket00": config.latBucket00,
			"bucket01": config.latBucket01,
			"bucket10": config.latBucket10,
			"bucket25": config.latBucket25,
			"bucket50": config.latBucket50,
			"bucket75": config.latBucket75,
			"bucket90": config.latBucket90,
			"bucket99": config.latBucket99}).Infof("Configured %s latency buckets: ", protoStr)

		if clockCheckInterval == 0 || spec.ClockCheckInterval < clockCheckInterval {
			clockCheckInterval = spec.ClockCheckInterval
		}
		if clockMaxSkew == 0 || spec.ClockMaxSkew < clockMaxSkew {
			clockMaxSkew = spec.ClockMaxSkew
		}

		interfaces[protocol] = spec.Interfaces
		config.maxPacketSize = spec.MaxPacketSize

		// MatchPorts are strictly optional, as we have constrained the packet mangling
		// to the specified subnets, or refused to enable latency.
		if len(spec.MatchPorts) == 0 {
			config.ports[0] = 0
			return config, nil
		}
		if len(spec.MatchPorts) <= maxPorts {
			copy(config.ports[:], spec.MatchPorts)
		} else {
			copy(config.ports[:], spec.MatchPorts[0:maxPorts])
		}
	} else {
		config.enable = 0
		enabled[protocol] = false
		config.subnets[0].addr[0] = 0
		config.subnets[0].ipv6 = 0
		config.ports[0] = 0
	}
	return config, nil
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

// configureBootTime sets the boot time in nanoseconds, which is used in latency calculations
// between nodes.
func configureBootTime(config configValue) (configValue, error) {
	t, err := GetBootTime()
	if err != nil {
		logger.GetLogger().WithError(err).Warn("sensor clock error")
		return config, err
	}
	config.bootNs = t
	return config, nil
}

// checkClock checks if the difference between the current boot time and the configured
// boot time is more than half a microsecond; if so, it updates the configuration.
func checkClock() {
	m, err := bpf.OpenMap(filepath.Join(bpf.MapPrefixPath(), ConfigMapName))
	if err != nil {
		logger.GetLogger().WithError(err).Warn("checkClock failed to open configuration map")
		return
	}
	defer m.Close()

	key := &configKey{
		zero: uint32(0),
	}

	configMapValue, err := m.Lookup(key)
	if err != nil {
		logger.GetLogger().WithError(err).Warn("checkClock failed to read configuration map")
		return
	}
	config := configMapValue.(*configValue)

	t, err := GetBootTime()
	if err != nil {
		logger.GetLogger().WithError(err).Warn("checkClock failed to get boot time")
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
		err = m.Update(key, config)
		if err != nil {
			logger.GetLogger().WithError(err).Warn("checkClock failed to update configuration map")
			return
		}
		logger.GetLogger().WithFields(logrus.Fields{"From": old, "To": t}).Debug("checkClock updated")
	}
}

func runTcCheck() {
	tcAttaching.Lock()
	defer tcAttaching.Unlock()
	var interfacesToAttach []string
	for _, ifaces := range interfaces {
		interfacesToAttach = append(interfacesToAttach, ifaces...)
	}
	for _, program := range tcList {
		attachedInterfaces, exists := tcAttachedInterfaces[program.Load]
		if !exists {
			logger.GetLogger().WithFields(logrus.Fields{"program.Load": program.Load.Name}).Warn("tcAttachedInterfaces[program.Load] doesn't exist")
			attachedInterfaces = make(map[tc.NamespaceInterface]bool)
		}
		attachedInterfaces, err := tc.LoadTC(program.BPFDir, program.MapDir, program.CiliumDir, program.Load, program.Verbose, interfacesToAttach, attachedInterfaces)
		if err == nil {
			tcAttachedInterfaces[program.Load] = attachedInterfaces
		}
	}
}

func AttachTc(args sensors.LoadProbeArgs) error {
	tcAttaching.Lock()
	var interfacesToAttach []string
	for _, ifaces := range interfaces {
		interfacesToAttach = append(interfacesToAttach, ifaces...)
	}
	attachedInterfaces := make(map[tc.NamespaceInterface]bool)
	attachedInterfaces, err := tc.LoadTC(args.BPFDir, args.MapDir, args.CiliumDir, args.Load, args.Verbose, interfacesToAttach, attachedInterfaces)
	if err == nil {
		tcAttachedInterfaces[args.Load] = attachedInterfaces
		tcList = append(tcList, args)
		tcAttaching.Unlock()
	} else {
		tcAttaching.Unlock()
		return err
	}
	return nil
}

func ConfigureLatency(mapDir string, protocol uint16, config ProtocolConfig) error {
	m, err := bpf.OpenMap(filepath.Join(mapDir, ConfigMapName))
	if err != nil {
		return err
	}
	defer m.Close()

	key := &configKey{
		zero: uint32(0),
	}

	existingMapValue, err := m.Lookup(key)
	if err != nil {
		return err
	}
	latencyConfig := existingMapValue.(*configValue)

	switch protocol {
	case unix.IPPROTO_UDP:
		latencyConfig.udp = config
	case unix.IPPROTO_TCP:
		latencyConfig.tcp = config
	}

	*latencyConfig, _ = configureBootTime(*latencyConfig)

	m.Update(key, latencyConfig)
	logger.GetLogger().Infof("Configured latency: %s", latencyConfig)
	return nil
}

func Start() {
	refCntMu.Lock()
	defer refCntMu.Unlock()
	if tcCheckInterval > 0 {
		tcCheckTimer.Start(tcCheckInterval)
	}
	if clockCheckInterval > 0 && clockMaxSkew > 0 {
		clockUpdateTimer.Start(time.Duration(clockCheckInterval) * time.Second)
	}
	refCnt++
}

func Stop(protocol uint16) {
	refCntMu.Lock()
	defer refCntMu.Unlock()
	tcAttaching.Lock()
	defer tcAttaching.Unlock()

	_, exists := enabled[protocol]
	if exists {
		delete(enabled, protocol)
		delete(interfaces, protocol)
	}

	if refCnt > 0 {
		refCnt--
	}
	if refCnt == 0 {
		tcCheckTimer.Stop()
		clockUpdateTimer.Stop()
		tcAttachedInterfaces = make(map[*program.Program]map[tc.NamespaceInterface]bool)
		tcList = nil
	}
}

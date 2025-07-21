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
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/cilium/tetragon/pkg/timer"
	"github.com/isovalent/hubble-fgs/pkg/common"
	"github.com/isovalent/hubble-fgs/pkg/constants"
	"github.com/isovalent/hubble-fgs/pkg/sensors/program/tc"
)

const (
	maxSubnets    = 4
	maxPorts      = 4
	ConfigMapName = "tg_l3_lat_cfg"
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

	Timestamp = program.Builder(
		"bpf_timestamp.o",
		"egress_timestamp",
		"classifier/egress_timestamp",
		"tg_tc_egress_timestamp",
		"tc_egress",
	)
)

type SubnetSelector struct {
	Addr      [2]uint64
	Ipv6      uint8
	PrefixLen uint8
	Padding   [6]uint8
}

type configKey struct {
	Zero uint32
}

type configValue struct {
	BootNs uint64
	Udp    ProtocolConfig
	Tcp    ProtocolConfig
}

type ProtocolConfig struct {
	Enable        uint8
	Pad1          uint8
	MaxPacketSize uint16
	Pad2          uint32
	Subnets       [maxSubnets]SubnetSelector
	Ports         [maxPorts]uint16
	LatBucket00   uint32
	LatBucket01   uint32
	LatBucket10   uint32
	LatBucket25   uint32
	LatBucket50   uint32
	LatBucket75   uint32
	LatBucket90   uint32
	LatBucket99   uint32
}

func (k *configKey) String() string { return fmt.Sprintf("Zero: %d", k.Zero) }

// ParseLatencySpec parses the input yaml/crd and outputs the kernel selectors
// needed for BPF to observe latency.
func ParseLatencySpec(spec v1alpha1.LatencyPolicySpec, protocol uint16) (ProtocolConfig, error) {
	config := ProtocolConfig{}
	var protoStr string
	switch protocol {
	case syscall.IPPROTO_UDP:
		protoStr = "UDP"
	case syscall.IPPROTO_TCP:
		protoStr = "TCP"
	default:
		protoStr = "Unknown"
	}
	if spec.Enable {
		config.Enable = 1
		enabled[protocol] = true
		if tcCheckInterval == time.Duration(0) || time.Duration(spec.InterfacesCheckInterval)*time.Second < tcCheckInterval {
			tcCheckInterval = time.Duration(spec.InterfacesCheckInterval) * time.Second
		}
		latencyMin := spec.Min
		latencyMax := spec.Max
		if latencyMax <= latencyMin {
			logger.GetLogger().Warn(fmt.Sprintf("Misconfigured %s latency Histogram: Min value must be less than Max", protoStr))
			config.Enable = 0
			enabled[protocol] = false
			return config, fmt.Errorf("misconfigured %s latency Histogram: Min value must be less than Max", protoStr)
		}
		latencyRange := float64(latencyMax - latencyMin)
		fLatencyMin := float64(latencyMin)
		config.LatBucket00 = latencyMin
		config.LatBucket01 = uint32((latencyRange * .01) + fLatencyMin)
		config.LatBucket10 = uint32((latencyRange * .10) + fLatencyMin)
		config.LatBucket25 = uint32((latencyRange * .25) + fLatencyMin)
		config.LatBucket50 = uint32((latencyRange * .50) + fLatencyMin)
		config.LatBucket75 = uint32((latencyRange * .75) + fLatencyMin)
		config.LatBucket90 = uint32((latencyRange * .90) + fLatencyMin)
		config.LatBucket99 = uint32((latencyRange * .99) + fLatencyMin)

		if len(spec.MatchSubnets) == 0 {
			// Do not enable latency if subnets not specified as packet mangling
			// has the opportunity to break networks.
			logger.GetLogger().Warn(protoStr + " latency disabled due to no valid subnets")
			config.Enable = 0
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
				logger.GetLogger().Warn(fmt.Sprintf("Error parsing %s latency subnet", protoStr), "subnet", subnet)
				continue
			}
			if ip.To4() == nil {
				logger.GetLogger().Warn(fmt.Sprintf("%s latency only supported on IPv4", protoStr), "subnet", subnet)
				continue
			}
			prefixLen, _ := ipnet.Mask.Size()
			if prefixLen == 0 {
				logger.GetLogger().Warn(fmt.Sprintf("%s latency only supports canonical subnets", protoStr), "subnet", subnet)
				continue
			}
			ipv4 := ipnet.IP.To4()
			config.Subnets[index].Addr[0] = uint64(binary.LittleEndian.Uint32(ipv4))
			config.Subnets[index].Ipv6 = 0
			config.Subnets[index].PrefixLen = uint8(prefixLen)
			logger.GetLogger().Info(fmt.Sprintf("%s latency subnet: IP=%s/%d", protoStr, ipv4, config.Subnets[index].PrefixLen))
			index++
		}
		if index == 0 {
			// Do not enable latency if subnets not specified as packet mangling
			// has the opportunity to break networks.
			logger.GetLogger().Warn(fmt.Sprintf("%s latency disabled due to no valid subnets", protoStr))
			config.Enable = 0
			enabled[protocol] = false
			return config, fmt.Errorf("%s latency disabled due to no valid subnets", protoStr)
		}

		logger.GetLogger().Info(fmt.Sprintf("Configured %s latency buckets: ", protoStr),
			"Min", latencyMin,
			"Range", latencyRange,
			"bucket00", config.LatBucket00,
			"bucket01", config.LatBucket01,
			"bucket10", config.LatBucket10,
			"bucket25", config.LatBucket25,
			"bucket50", config.LatBucket50,
			"bucket75", config.LatBucket75,
			"bucket90", config.LatBucket90,
			"bucket99", config.LatBucket99)

		if clockCheckInterval == 0 || spec.ClockCheckInterval < clockCheckInterval {
			clockCheckInterval = spec.ClockCheckInterval
		}
		if clockMaxSkew == 0 || spec.ClockMaxSkew < clockMaxSkew {
			clockMaxSkew = spec.ClockMaxSkew
		}

		interfaces[protocol] = spec.Interfaces
		config.MaxPacketSize = spec.MaxPacketSize

		// MatchPorts are strictly optional, as we have constrained the packet mangling
		// to the specified subnets, or refused to enable latency.
		if len(spec.MatchPorts) == 0 {
			config.Ports[0] = 0
			return config, nil
		}
		if len(spec.MatchPorts) <= maxPorts {
			copy(config.Ports[:], spec.MatchPorts)
		} else {
			copy(config.Ports[:], spec.MatchPorts[0:maxPorts])
		}
	} else {
		config.Enable = 0
		enabled[protocol] = false
		config.Subnets[0].Addr[0] = 0
		config.Subnets[0].Ipv6 = 0
		config.Ports[0] = 0
	}
	return config, nil
}

// GetBootTime gets the boot time in nanoseconds, which is used in latency calculations
// between nodes.
func GetBootTime() (uint64, error) {
	clk := int32(constants.CLOCK_MONOTONIC)
	currentTime := syscall.Timespec{}
	if err := common.ClockGettime(clk, &currentTime); err != nil {
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
		logger.GetLogger().Warn("sensor clock error", logfields.Error, err)
		return config, err
	}
	config.BootNs = t
	return config, nil
}

// checkClock checks if the difference between the current boot time and the configured
// boot time is more than half a microsecond; if so, it updates the configuration.
func checkClock() {
	m, err := ebpf.LoadPinnedMap(filepath.Join(bpf.MapPrefixPath(), ConfigMapName), nil)
	if err != nil {
		logger.GetLogger().Warn("checkClock failed to open configuration map", logfields.Error, err)
		return
	}
	defer m.Close()

	key := &configKey{
		Zero: uint32(0),
	}

	var config configValue
	err = m.Lookup(key, &config)
	if err != nil {
		logger.GetLogger().Warn("checkClock failed to read configuration map", logfields.Error, err)
		return
	}

	t, err := GetBootTime()
	if err != nil {
		logger.GetLogger().Warn("checkClock failed to get boot time", logfields.Error, err)
		return
	}
	diff := int64(t - config.BootNs)
	if diff < 0 {
		diff = -diff
	}
	// Is the difference more than the max clock skew?
	if diff > int64(clockMaxSkew*1000) {
		old := config.BootNs
		config.BootNs = t
		err = m.Put(key, &config)
		if err != nil {
			logger.GetLogger().Warn("checkClock failed to update configuration map", logfields.Error, err)
			return
		}
		logger.GetLogger().Debug("checkClock updated", "From", old, "To", t)
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
			logger.GetLogger().Warn("tcAttachedInterfaces[program.Load] doesn't exist", "program.Load", program.Load.Name)
			attachedInterfaces = make(map[tc.NamespaceInterface]bool)
		}
		attachedInterfaces, err := tc.LoadTC(program.BPFDir, program.Load, nil, program.Verbose, interfacesToAttach, attachedInterfaces)
		if err == nil {
			tcAttachedInterfaces[program.Load] = attachedInterfaces
		}
	}
}

func AttachTc(args sensors.LoadProbeArgs) error {
	tcAttaching.Lock()
	defer tcAttaching.Unlock()
	var interfacesToAttach []string
	for _, ifaces := range interfaces {
		interfacesToAttach = append(interfacesToAttach, ifaces...)
	}
	attachedInterfaces := make(map[tc.NamespaceInterface]bool)
	attachedInterfaces, err := tc.LoadTC(args.BPFDir, args.Load, args.Maps, args.Verbose, interfacesToAttach, attachedInterfaces)
	if err == nil {
		tcAttachedInterfaces[args.Load] = attachedInterfaces
		tcList = append(tcList, args)
	} else {
		return err
	}
	return nil
}

func ConfigureLatency(protocol uint16, config ProtocolConfig) error {
	m, err := ebpf.LoadPinnedMap(filepath.Join(bpf.MapPrefixPath(), ConfigMapName), nil)
	if err != nil {
		return err
	}
	defer m.Close()

	key := &configKey{
		Zero: uint32(0),
	}

	var latencyConfig configValue
	err = m.Lookup(key, &latencyConfig)
	if err != nil {
		return err
	}

	switch protocol {
	case syscall.IPPROTO_UDP:
		latencyConfig.Udp = config
	case syscall.IPPROTO_TCP:
		latencyConfig.Tcp = config
	}

	latencyConfig, _ = configureBootTime(latencyConfig)

	m.Put(key, &latencyConfig)
	logger.GetLogger().Info(fmt.Sprintf("Configured latency: %+v", latencyConfig))
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

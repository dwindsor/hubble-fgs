//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package layer3

import (
	"fmt"
	"os"
	"path"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
	"github.com/isovalent/hubble-fgs/pkg/sensors/ip"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3/internal/icmp"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3/internal/rawsock"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3/internal/tcp"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3/internal/udp"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3/tcpconfig"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3/udpconfig"
	"github.com/isovalent/hubble-fgs/pkg/sensors/networklatency"
	"github.com/isovalent/hubble-fgs/pkg/sensors/program/cgroup"
	"golang.org/x/sys/unix"
)

var (
	configured  = false
	tcpEnabled  = false
	udpEnabled  = false
	dnsEnabled  = false
	icmpEnabled = false
	rawEnabled  = false
)

var (
	CgroupProtocolConfigMapName = "tg_cgroup_protocol_cfg_map"
)

func unloadLayer3Sensor() error {
	// We want to make sure we stand configuration up when loading/unloading the sensor.
	configured = false
	if tcpEnabled {
		err := tcp.UnloadSensor()
		if err != nil {
			return err
		}
		tcpEnabled = false
	}
	if udpEnabled {
		err := udp.UnloadSensor()
		if err != nil {
			return err
		}
		udpEnabled = false
	}
	if icmpEnabled {
		err := icmp.UnloadSensor()
		if err != nil {
			return err
		}
		icmpEnabled = false
	}
	if rawEnabled {
		err := rawsock.UnloadSensor()
		if err != nil {
			return err
		}
		rawEnabled = false
	}

	mapDir := bpf.MapPrefixPath()
	cfgMapName := path.Join(path.Dir(mapDir), CgroupProtocolConfigMapName)
	os.Remove(cfgMapName)

	return nil
}

func EnableLayer3(tcpTimestampEnable, cgroup, udpTimestampEnable bool, udpInterval time.Duration, reportRawClose bool) *sensors.Sensor {
	// We want to make sure we stand configuration up when loading/unloading the sensor.
	configured = false

	var progs []*program.Program
	var maps []*program.Map

	if tcpEnabled {
		tcpProgs, tcpMaps := tcp.EnableTcp(tcpTimestampEnable)
		progs = append(progs, tcpProgs...)
		maps = append(maps, tcpMaps...)
	}
	if udpEnabled {
		udpProgs, udpMaps := udp.EnableUdp(cgroup, udpTimestampEnable, udpInterval)
		progs = append(progs, udpProgs...)
		maps = append(maps, udpMaps...)
	}
	if icmpEnabled {
		icmpProgs, icmpMaps := icmp.EnableIcmp()
		progs = append(progs, icmpProgs...)
		maps = append(maps, icmpMaps...)
	}
	if rawEnabled {
		rawProgs, rawMaps := rawsock.EnableRawsock(reportRawClose)
		progs = append(progs, rawProgs...)
		maps = append(maps, rawMaps...)
	}

	l3Sensor := sensors.SensorBuilder("layer3_sensors", progs, maps)
	l3Sensor.PreUnloadHook = unloadLayer3Sensor
	return l3Sensor
}

type l3Sensor struct {
	name string
}

func (l3 *l3Sensor) PolicyHandler(
	policy tracingpolicy.TracingPolicy,
	fid policyfilter.PolicyID,
) (*sensors.Sensor, error) {
	spec := policy.TpSpec()
	if !spec.Parser.Tcp.Enable && !spec.Parser.Udp.Enable && !spec.Parser.Dns.Enable && !spec.Parser.Icmp.Enable && !spec.Parser.Rawsock.Enable {
		return nil, nil
	}

	if fid != policyfilter.NoFilterID {
		return nil, fmt.Errorf("layer3 sensor does not implement policy filtering")
	}

	tcpEnabled = spec.Parser.Tcp.Enable
	udpEnabled = spec.Parser.Udp.Enable
	dnsEnabled = spec.Parser.Dns.Enable
	icmpEnabled = spec.Parser.Icmp.Enable
	rawEnabled = spec.Parser.Rawsock.Enable
	udpCgroup := spec.Parser.Udp.Cgroup
	// If TCP or UDP then turn on DNS as nobody wants L4 without DNS.
	if tcpEnabled || udpEnabled {
		dnsEnabled = true
		// DNS requires cgroup programs.
		udpCgroup = true
	}
	// If DNS then turn on UDP otherwise DNS doesn't work.
	if dnsEnabled {
		udpEnabled = true
		// DNS requires cgroup programs.
		udpCgroup = true
	}
	// However, disable cgroup and therefore DNS if the kernel is too old
	if !kernels.MinKernelVersion("5.4.0") {
		udpCgroup = false
		dnsEnabled = false
	}
	tcpTimestampEnable := false
	var err error
	if tcpEnabled {
		tcpTimestampEnable, err = tcp.PolicyHandler(spec)
		if err != nil {
			return nil, fmt.Errorf("tcp.PolicyHandler error: %w", err)
		}
	}

	udpTimestampEnable := false
	var udpInterval time.Duration
	if udpEnabled {
		udpTimestampEnable, udpInterval, err = udp.PolicyHandler(spec)
		if err != nil {
			return nil, fmt.Errorf("udp.PolicyHandler error: %w", err)
		}
	}

	if icmpEnabled {
		err = icmp.PolicyHandler(spec)
		if err != nil {
			return nil, fmt.Errorf("icmp.PolicyHandler error: %w", err)
		}
	}

	reportRawClose := false
	if rawEnabled {
		reportRawClose, err = rawsock.PolicyHandler(spec)
		if err != nil {
			return nil, fmt.Errorf("rawsock.PolicyHandler error: %w", err)
		}
	}

	return EnableLayer3(tcpTimestampEnable,
		udpCgroup, udpTimestampEnable, udpInterval, reportRawClose), nil
}

type CgroupProtocolConfigValue struct {
	icmp4Enabled uint32
	icmp6Enabled uint32
}

func (v *CgroupProtocolConfigValue) String() string {
	return fmt.Sprintf("CgroupProtocolConfigValue: "+
		"icmp4Enabled: %d, "+
		"icmp6Enabled: %d",
		v.icmp4Enabled,
		v.icmp6Enabled,
	)
}

type CgroupProtocolConfigKey struct {
	Zero uint32
}

func (k *CgroupProtocolConfigKey) String() string {
	return fmt.Sprintf("Zero: %d", k.Zero)
}

func (l3 *l3Sensor) createCgroupProtocolCfgMap(l3cfg CgroupProtocolConfigValue) error {
	zero := CgroupProtocolConfigKey{
		Zero: 0,
	}
	c := &ebpf.MapSpec{
		Name:       CgroupProtocolConfigMapName,
		Type:       bpf.BPF_MAP_TYPE_ARRAY,
		KeySize:    uint32(unsafe.Sizeof(CgroupProtocolConfigKey{})),
		ValueSize:  uint32(unsafe.Sizeof(CgroupProtocolConfigValue{})),
		MaxEntries: 1,
		Pinning:    ebpf.PinByName,
	}
	opts := ebpf.MapOptions{
		PinPath: bpf.MapPrefixPath(),
	}

	cfgMap, err := ebpf.NewMapWithOptions(c, opts)
	if err != nil {
		return fmt.Errorf("failed `tg_cgroup_protocol_cfg_map` ebpf.NewMapWithOptions: %w", err)
	}
	defer cfgMap.Close()

	if err := cfgMap.Update(zero, l3cfg, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("failed cgroup_protocol_cfg_map Update: %w", err)
	}

	return nil
}

func (l3 *l3Sensor) LoadProbe(args sensors.LoadProbeArgs) error {
	if !configured {
		l3cfg := CgroupProtocolConfigValue{}

		if tcpEnabled {
			tcp.GetRunningSockets(true, true)
		}
		if udpEnabled {
			ip.LoadSockets(udp.FdCallback, unix.IPPROTO_UDP)
		}
		if icmpEnabled {
			ip.LoadSockets(icmp.FdCallback, unix.IPPROTO_ICMP)
			l3cfg.icmp4Enabled = 1
			l3cfg.icmp6Enabled = 1
		}
		if rawEnabled {
			ip.LoadSockets(rawsock.FdCallback, unix.IPPROTO_RAW)
		}

		if icmpEnabled {
			if err := l3.createCgroupProtocolCfgMap(l3cfg); err != nil {
				return err
			}
		}
	}

	switch args.Load.Type {
	case "cgrp_ingress", "cgrp_egress", "cgrp_inet4_bind", "cgrp_inet6_bind":
		err := cgroup.LoadCgroupProgram(args.BPFDir, args.Load, args.Verbose)
		if err != nil {
			logger.GetLogger().WithError(err).Warn("CGRP")
			return err
		}
	case "udp_tc_egress", "tcp_tc_egress":
		err := networklatency.AttachTc(args)
		if err != nil {
			logger.GetLogger().WithError(err).Warn("TC_EGRESS")
			return err
		}
	case "layer3_sensor":
		if tcp.StatsEnabled {
			tcp.ConfigureSockStatSampler(tcp.Interval,
				tcp.WatermarksEnable,
				tcp.WatermarksWindowSize,
				tcp.WatermarksBurstTriggerMult,
				tcp.WatermarksDipTriggerMult,
				tcpconfig.RttHistogramMax,
				tcpconfig.RttHistogramMin)
		}
		tcp.ConfigureTCPDisableEvents(tcp.DisableConnect, tcp.DisableClose, tcp.DisableAccept, tcp.DisableListen)
		err := program.LoadKprobeProgram(args.BPFDir, args.Load, args.Verbose)
		if err != nil {
			logger.GetLogger().WithError(err).Warn("LAYER3_SENSOR")
			return err
		}
	}

	if !configured {
		if tcpEnabled && tcp.TimestampEnabled {
			if err := networklatency.ConfigureLatency(args.BPFDir, unix.IPPROTO_TCP, tcpconfig.LatencyConfig); err != nil {
				logger.GetLogger().WithError(err).Warn("ConfigureLatency TCP")
				return err
			}
			networklatency.Start()
		}
		if udpEnabled {
			if err := udp.ConfigureUdpSensor(args.BPFDir, udp.ConfigMapName, udp.Config); err != nil {
				return err
			}
			logger.GetLogger().WithField("timestampEnabled", udp.TimestampEnabled).Debug("UDP Loader")
			if udp.TimestampEnabled {
				if err := networklatency.ConfigureLatency(args.BPFDir, unix.IPPROTO_UDP, udpconfig.LatencyConfig); err != nil {
					return err
				}
				networklatency.Start()
			}
		}
		if icmpEnabled {
			if err := icmp.ConfigureIcmpSensor(args.BPFDir, icmp.ConfigMapName, icmp.Config); err != nil {
				return err
			}
		}

		configured = true
	}

	return nil
}

func init() {
	AddLayer3()
}

func AddLayer3() {
	err := tcp.Init()
	if err != nil {
		logger.GetLogger().WithError(err).Errorf("TCP init failed. Disabling Layer3")
		return
	}

	err = udp.Init()
	if err != nil {
		logger.GetLogger().WithError(err).Errorf("UDP init failed. Disabling Layer3")
		return
	}

	err = icmp.Init()
	if err != nil {
		logger.GetLogger().WithError(err).Errorf("ICMP init failed. Disabling Layer3")
		return
	}

	err = rawsock.Init()
	if err != nil {
		logger.GetLogger().WithError(err).Errorf("RAW init failed. Disabling Layer3")
		return
	}

	l3 := &l3Sensor{
		name: "Layer3 sensor",
	}

	sensors.RegisterPolicyHandlerAtInit(l3.name, l3)

	sensors.RegisterProbeType("layer3_sensor", l3)
	sensors.RegisterProbeType("cgrp_ingress", l3)
	sensors.RegisterProbeType("cgrp_egress", l3)
	sensors.RegisterProbeType("cgrp_inet4_bind", l3)
	sensors.RegisterProbeType("cgrp_inet6_bind", l3)
	sensors.RegisterProbeType("udp_tc_egress", l3)
	sensors.RegisterProbeType("tcp_tc_egress", l3)
}

func HTTPContext() *program.Map {
	return tcp.HTTPContext
}

func SocketMap() *program.Map {
	return tcp.SocketMap
}

func SocketStats() *program.Map {
	return tcp.SocketStats
}

func TLSContext() *program.Map {
	return tcp.TLSContext
}

func TLSMapStats() *program.Map {
	return tcp.TLSMapStats
}

func TLSBottles() *program.Map {
	return tcp.TLSBottles
}

func TLSBottleStats() *program.Map {
	return tcp.TLSBottleStats
}

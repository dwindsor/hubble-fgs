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
	"time"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
	"github.com/isovalent/hubble-fgs/pkg/sensors/ip"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3/internal/tcp"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3/internal/udp"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3/tcpconfig"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3/udpconfig"
	"github.com/isovalent/hubble-fgs/pkg/sensors/networklatency"
	"github.com/isovalent/hubble-fgs/pkg/sensors/program/cgroup"
	"golang.org/x/sys/unix"
)

var (
	configured = false
	tcpEnabled = false
	udpEnabled = false
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
	return nil
}

func EnableLayer3(tcpTimestampEnable, cgroup, udpTimestampEnable bool, udpInterval time.Duration) *sensors.Sensor {
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

	if !spec.Parser.Tcp.Enable && !spec.Parser.Udp.Enable {
		return nil, nil
	}

	if fid != policyfilter.NoFilterID {
		return nil, fmt.Errorf("layer3 sensor does not implement policy filtering")
	}

	tcpTimestampEnable := false
	var err error
	if spec.Parser.Tcp.Enable {
		tcpTimestampEnable, err = tcp.PolicyHandler(spec)
		if err != nil {
			return nil, fmt.Errorf("tcp.PolicyHandler error: %w", err)
		}
		tcpEnabled = true
	}
	cgroup := false
	udpTimestampEnable := false
	var udpInterval time.Duration
	if spec.Parser.Udp.Enable {
		cgroup, udpTimestampEnable, udpInterval, err = udp.PolicyHandler(spec)
		if err != nil {
			return nil, fmt.Errorf("udp.PolicyHandler error: %w", err)
		}
		udpEnabled = true
	}
	return EnableLayer3(tcpTimestampEnable, cgroup, udpTimestampEnable, udpInterval), nil
}

func (l3 *l3Sensor) LoadProbe(args sensors.LoadProbeArgs) error {
	if !configured {
		if tcpEnabled {
			tcp.GetRunningSockets(true, true)
		}
		if udpEnabled {
			ip.LoadSockets(udp.FdCallback, unix.IPPROTO_UDP)
		}
	}

	switch args.Load.Type {
	case "cgrp_ingress", "cgrp_egress", "cgrp_inet4_bind", "cgrp_inet6_bind":
		err := cgroup.LoadCgroupProgram(args.BPFDir, args.Load, args.Verbose)
		if err != nil {
			return err
		}
	case "kprobe_udp":
		err := program.LoadKprobeProgram(args.BPFDir, args.Load, args.Verbose)
		if err != nil {
			return err
		}
	case "udp_tc_egress", "tcp_tc_egress":
		err := networklatency.AttachTc(args)
		if err != nil {
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
			return err
		}
	}

	if !configured {
		if tcpEnabled && tcp.TimestampEnabled {
			if err := networklatency.ConfigureLatency(args.BPFDir, unix.IPPROTO_TCP, tcpconfig.LatencyConfig); err != nil {
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

	l3 := &l3Sensor{
		name: "Layer3 sensor",
	}

	sensors.RegisterPolicyHandlerAtInit(l3.name, l3)

	sensors.RegisterProbeType("layer3_sensor", l3)
	sensors.RegisterProbeType("cgrp_ingress", l3)
	sensors.RegisterProbeType("cgrp_egress", l3)
	sensors.RegisterProbeType("cgrp_inet4_bind", l3)
	sensors.RegisterProbeType("cgrp_inet6_bind", l3)
	sensors.RegisterProbeType("kprobe_udp", l3)
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

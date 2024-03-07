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

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3/internal/tcp"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3/tcpconfig"
	"github.com/isovalent/hubble-fgs/pkg/sensors/networklatency"
	"github.com/isovalent/hubble-fgs/pkg/sensors/program/cgroup"
	"golang.org/x/sys/unix"
)

var (
	configured = false
)

func unloadLayer3Sensor() error {
	// We want to make sure we stand configuration up when loading/unloading the sensor.
	configured = false
	err := tcp.UnloadSensor()
	return err
}

func EnableLayer3(timestampEnable bool) *sensors.Sensor {
	// We want to make sure we stand configuration up when loading/unloading the sensor.
	configured = false

	tcpProgs, tcpMaps := tcp.EnableTcp(timestampEnable)

	l3Sensor := sensors.SensorBuilder("tcp_sensors", tcpProgs, tcpMaps)
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

	if !spec.Parser.Tcp.Enable {
		return nil, nil
	}

	if fid != policyfilter.NoFilterID {
		return nil, fmt.Errorf("layer3 sensor does not implement policy filtering")
	}

	timestampEnable, err := tcp.PolicyHandler(spec)
	if err != nil {
		return nil, err
	}
	return EnableLayer3(timestampEnable), nil
}

func (l3 *l3Sensor) LoadProbe(args sensors.LoadProbeArgs) error {
	if !configured {
		tcp.GetRunningSockets(true, true)
	}

	if args.Load.Type == "cgrp_tcp_ingress" {
		err := cgroup.LoadCgroupProgram(args.BPFDir, args.Load, args.Verbose)
		if err != nil {
			return err
		}
	} else if args.Load.Type == "tcp_tc_egress" {
		err := networklatency.AttachTc(args)
		if err != nil {
			return err
		}
	} else {
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
		if tcp.TimestampEnabled {
			if err := networklatency.ConfigureLatency(args.BPFDir, unix.IPPROTO_TCP, tcpconfig.LatencyConfig); err != nil {
				return err
			}
			networklatency.Start()
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

	l3 := &l3Sensor{
		name: "Layer3 sensor",
	}

	sensors.RegisterPolicyHandlerAtInit(l3.name, l3)

	sensors.RegisterProbeType("layer3_sensor", l3)
	sensors.RegisterProbeType("cgrp_tcp_ingress", l3)
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

//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package socktrack

import (
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/isovalent/hubble-fgs/pkg/sensors/utils"
)

const (
	SocketMapName          = "tg_socket_map"
	SocketStatsName        = "tg_socket_map_stats"
	SocketTupleMapName     = "tg_socket_tuple_map"
	SocketTupleStatsName   = "tg_socket_tuple_map_stats"
	SocketTupleRevMapName  = "tg_rev_tuple_map"
	SocketTupleHintMapName = "tg_socket_tuple_hint_map"
	SocketVersionMapName   = "tg_ver_map"
	SocketCfgMapName       = "tg_cfg_map"
)

var (
	SkAllocKprobe = program.Builder(
		"bpf_sk_alloc.o",
		"security_sk_alloc",
		"kprobe/security_sk_alloc",
		"tg_security_sk_alloc",
		"kprobe")

	SkFreeKprobe = program.Builder(
		"bpf_sk_alloc.o",
		"security_sk_free",
		"kprobe/security_sk_free",
		"tg_security_sk_free",
		"kprobe")

	SkAllocFentry = program.Builder(
		"bpf_security_sk_alloc.o",
		"security_sk_alloc",
		"fentry/security_sk_alloc",
		"tg_security_sk_alloc",
		"socktrack_fentry")

	SkFreeFentry = program.Builder(
		"bpf_security_sk_alloc.o",
		"security_sk_free",
		"fentry/security_sk_free",
		"tg_security_sk_free",
		"socktrack_fentry")

	SocketMapKprobe           = program.MapBuilder(SocketMapName, SkAllocKprobe)
	SocketMapStatsKprobe      = program.MapBuilder(SocketStatsName, SkAllocKprobe)
	SocketTupleMapKprobe      = program.MapBuilder(SocketTupleMapName, SkFreeKprobe)
	SocketTupleMapStatsKprobe = program.MapBuilder(SocketTupleStatsName, SkFreeKprobe)
	SocketTupleRevMapKprobe   = program.MapBuilder(SocketTupleRevMapName, SkFreeKprobe)
	SocketTupleHintMapKprobe  = program.MapBuilder(SocketTupleHintMapName, SkFreeKprobe)
	VersionMapKprobe          = program.MapBuilder(SocketVersionMapName, SkAllocKprobe)
	ConfigMapKprobe           = program.MapBuilder(SocketCfgMapName, SkFreeKprobe)
	SocketMapFentry           = program.MapBuilder(SocketMapName, SkAllocFentry)
	SocketMapStatsFentry      = program.MapBuilder(SocketStatsName, SkAllocFentry)
	SocketTupleMapFentry      = program.MapBuilder(SocketTupleMapName, SkFreeFentry)
	SocketTupleMapStatsFentry = program.MapBuilder(SocketTupleStatsName, SkFreeFentry)
	SocketTupleRevMapFentry   = program.MapBuilder(SocketTupleRevMapName, SkFreeFentry)
	SocketTupleHintMapFentry  = program.MapBuilder(SocketTupleHintMapName, SkFreeFentry)
	VersionMapFentry          = program.MapBuilder(SocketVersionMapName, SkAllocFentry)
	ConfigMapFentry           = program.MapBuilder(SocketCfgMapName, SkFreeFentry)
)

type socktrackSensor struct {
	name string
}

func (sktr *socktrackSensor) LoadProbe(args sensors.LoadProbeArgs) error {
	switch args.Load.Type {
	case "socktrack_fentry":
		err := program.LoadTracingProgram(args.BPFDir, args.Load, args.Verbose)
		if err != nil {
			logger.GetLogger().WithError(err).Warn("FENTRY")
			return err
		}
	}

	return nil
}

/* Add sensor from CRD */
func EnableSocktrack() ([]*program.Program, []*program.Map) {
	logger.GetLogger().Infof("Enable Socktrack")

	var progs []*program.Program
	var maps []*program.Map

	if utils.SupportFentry() {
		progs = []*program.Program{
			SkAllocFentry,
			SkFreeFentry,
		}
		maps = []*program.Map{
			SocketMapFentry,
			SocketMapStatsFentry,
			SocketTupleMapFentry,
			SocketTupleMapStatsFentry,
			SocketTupleRevMapFentry,
			SocketTupleHintMapFentry,
			VersionMapFentry,
			ConfigMapFentry,
		}
	} else {
		progs = []*program.Program{
			SkAllocKprobe,
			SkFreeKprobe,
		}
		maps = []*program.Map{
			SocketMapKprobe,
			SocketMapStatsKprobe,
			SocketTupleMapKprobe,
			SocketTupleMapStatsKprobe,
			SocketTupleRevMapKprobe,
			SocketTupleHintMapKprobe,
			VersionMapKprobe,
			ConfigMapKprobe,
		}
	}

	return progs, maps
}

func init() {
	AddSocktrack()
}

func AddSocktrack() {
	socktrack := &socktrackSensor{
		name: "Socktrack sensor",
	}

	sensors.RegisterProbeType("socktrack_fentry", socktrack)
}

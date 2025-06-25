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
	"github.com/cilium/tetragon/pkg/sensors/program"
	socktrackmaps "github.com/isovalent/hubble-fgs/pkg/sensors/socktrack/maps"
	"github.com/isovalent/hubble-fgs/pkg/sensors/utils"
)

var (
	SkAllocKprobe = program.Builder(
		"bpf_sk_alloc.o",
		"security_sk_alloc",
		"kprobe/security_sk_alloc",
		"tg_security_sk_alloc",
		"layer3_sensor")

	SkFreeKprobe = program.Builder(
		"bpf_sk_alloc.o",
		"security_sk_free",
		"kprobe/security_sk_free",
		"tg_security_sk_free",
		"layer3_sensor")

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

	SocketMapKprobe           = program.MapBuilder(socktrackmaps.SocketMapName, SkAllocKprobe)
	SocketMapStatsKprobe      = program.MapBuilder(socktrackmaps.SocketStatsName, SkAllocKprobe)
	SocketTupleMapKprobe      = program.MapBuilder(socktrackmaps.SocketTupleMapName, SkFreeKprobe)
	SocketTupleMapStatsKprobe = program.MapBuilder(socktrackmaps.SocketTupleStatsName, SkFreeKprobe)
	SocketTupleRevMapKprobe   = program.MapBuilder(socktrackmaps.SocketTupleRevMapName, SkFreeKprobe)
	SocketTupleHintMapKprobe  = program.MapBuilder(socktrackmaps.SocketTupleHintMapName, SkFreeKprobe)
	VersionMapKprobe          = program.MapBuilder(socktrackmaps.SocketVersionMapName, SkAllocKprobe)
	ConfigMapKprobe           = program.MapBuilder(socktrackmaps.SocketCfgMapName, SkFreeKprobe)
	SocketMapFentry           = program.MapBuilder(socktrackmaps.SocketMapName, SkAllocFentry)
	SocketMapStatsFentry      = program.MapBuilder(socktrackmaps.SocketStatsName, SkAllocFentry)
	SocketTupleMapFentry      = program.MapBuilder(socktrackmaps.SocketTupleMapName, SkFreeFentry)
	SocketTupleMapStatsFentry = program.MapBuilder(socktrackmaps.SocketTupleStatsName, SkFreeFentry)
	SocketTupleRevMapFentry   = program.MapBuilder(socktrackmaps.SocketTupleRevMapName, SkFreeFentry)
	SocketTupleHintMapFentry  = program.MapBuilder(socktrackmaps.SocketTupleHintMapName, SkFreeFentry)
	VersionMapFentry          = program.MapBuilder(socktrackmaps.SocketVersionMapName, SkAllocFentry)
	ConfigMapFentry           = program.MapBuilder(socktrackmaps.SocketCfgMapName, SkFreeFentry)
)

/* Enabled from the layer3 sensor */
func EnableSocktrack() ([]*program.Program, []*program.Map) {
	logger.GetLogger().Info("Enable Socktrack")

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

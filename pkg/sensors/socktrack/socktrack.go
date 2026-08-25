// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package socktrack

import (
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/sensors/program"

	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"
	"github.com/isovalent/hubble-fgs/pkg/sensors/base"
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

	ConfigMap   = program.MapUserFrom(base.CfgMap)
	TCPFinRxMap = program.MapBuilder("tg_l3_tcp_finrx", SkAllocKprobe, SkFreeKprobe, SkAllocFentry, SkFreeFentry)

	// tg_http_map is used by any ebpf program that calls __event_tcp_close()
	// or event_tcp_close_sockops() (e.g. security_sk_free), aside from the
	// HTTP parser itself. As socktrack is always loaded at startup, the
	// map is defined here / owned by socktrack and used downstream
	HTTPContext = program.MapBuilder("tg_http_map", SkAllocKprobe, SkFreeKprobe, SkAllocFentry, SkFreeFentry)

	// same premise as tg_http_map above
	TLSContext = program.MapBuilder("tg_tls_map", SkAllocKprobe, SkFreeKprobe, SkAllocFentry, SkFreeFentry)

	// and again for to_tls_map_stats, tg_bottles and tg_bottle_map_stats
	TLSMapStats    = program.MapBuilder("tg_tls_map_stats", SkAllocKprobe, SkFreeKprobe, SkAllocFentry, SkFreeFentry)
	TLSBottles     = program.MapBuilder("tg_bottles", SkAllocKprobe, SkFreeKprobe, SkAllocFentry, SkFreeFentry)
	TLSBottleStats = program.MapBuilder("tg_bottle_map_stats", SkAllocKprobe, SkFreeKprobe, SkAllocFentry, SkFreeFentry)
)

/* Enabled from the layer3 sensor */
func EnableSocktrack() ([]*program.Program, []*program.Map) {
	logger.GetLogger().Info("Enable Socktrack")

	var progs []*program.Program

	if !enterpriseOption.Config.DisableLayer3 {
		TCPFinRxMap.SetMaxEntries(enterpriseOption.Config.TCPSocketMapSize)
		HTTPContext.SetMaxEntries(enterpriseOption.Config.HTTPContextMapSize)
		TLSContext.SetMaxEntries(enterpriseOption.Config.TLSContextMapSize)
	}

	maps := []*program.Map{
		program.MapUserFrom(base.SocketMap),
		program.MapUserFrom(base.SocketStats),
		program.MapUserFrom(base.SocketVersionMap),
		program.MapUserFrom(base.SocketTupleMap),
		program.MapUserFrom(base.SocketTupleStats),
		program.MapUserFrom(base.SocketTupleRevMap),
		program.MapUserFrom(base.SocketTupleHintMap),
		ConfigMap,
		TCPFinRxMap,
		HTTPContext,
		TLSContext,
		TLSMapStats,
		TLSBottles,
		TLSBottleStats,
	}

	if utils.SupportFentry() {
		progs = []*program.Program{
			SkAllocFentry,
			SkFreeFentry,
		}
	} else {
		progs = []*program.Program{
			SkAllocKprobe,
			SkFreeKprobe,
		}
	}

	return progs, maps
}

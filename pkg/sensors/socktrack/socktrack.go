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

	SocketMap           = program.MapUserFrom(base.SocketMap)
	SocketMapStats      = program.MapUserFrom(base.SocketStats)
	SocketVersionMap    = program.MapUserFrom(base.SocketVersionMap)
	SocketTupleMap      = program.MapUserFrom(base.SocketTupleMap)
	SocketTupleMapStats = program.MapUserFrom(base.SocketTupleStats)
	SocketTupleRevMap   = program.MapUserFrom(base.SocketTupleRevMap)
	SocketTupleHintMap  = program.MapUserFrom(base.SocketTupleHintMap)
	ConfigMap           = program.MapUserFrom(base.CfgMap)
	UDPConfigMap        = program.MapUserFrom(base.UDPCfgMap)
)

/* Enabled from the layer3 sensor */
func EnableSocktrack() ([]*program.Program, []*program.Map) {
	logger.GetLogger().Info("Enable Socktrack")

	var progs []*program.Program

	maps := []*program.Map{
		SocketMap,
		SocketMapStats,
		SocketVersionMap,
		SocketTupleMap,
		SocketTupleMapStats,
		SocketTupleRevMap,
		SocketTupleHintMap,
		ConfigMap,
		UDPConfigMap,
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

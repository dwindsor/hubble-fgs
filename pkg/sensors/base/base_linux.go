// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package base

import (
	"github.com/cilium/tetragon/pkg/config"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/sensors/program"

	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"
	"github.com/isovalent/hubble-fgs/pkg/sensors/utils"
)

func GetDefaultPrograms() []*program.Program {
	progs := []*program.Program{
		ExecveBprmCommit,
		ExecveMapUpdate,
	}
	if EnableV612Progs() {
		progs = append(progs, ExecveV612)
	} else if config.EnableV61Progs() {
		progs = append(progs, ExecveV61)
	} else if utils.EnableV511Progs() {
		progs = append(progs, ExecveV511)
	} else if config.EnableLargeProgs() {
		progs = append(progs, ExecveV53)
	} else {
		progs = append(progs, Execve)
	}
	if config.EnableV511Progs() {
		progs = append(progs, ForkV511, ExitV511)
	} else {
		progs = append(progs, Fork, Exit)
	}
	if enterpriseOption.Config.EnableApplicationModel && enterpriseOption.Config.EnableSyscallTracking {
		logger.GetLogger().Info("Enable syscall tracking")
		progs = append(progs, SysEnterProg)
	}
	return progs
}

func GetDefaultMaps() []*program.Map {
	maps := []*program.Map{
		TCPMonMap,
		ExecveMap,
		ProcessNetworkWatermarksMap,
		SocketMap,
		SocketStats,
		SocketVersionMap,
		SocketTupleMap,
		SocketTupleStats,
		SocketTupleRevMap,
		SocketTupleHintMap,
		CfgMap,
		TcpSocketMap,
		TcpSocketMapStats,
		ExecveMapUpdateData,
		ExecveJoinMap,
		TetragonConfMap,
		ExecveStats,
		PNWatermarksMapStats,
		ExecveJoinMapStats,
		StatsMap,
		PidDataMap,
		ProcessTreeId,
		ProcessTreeMap,
		ProcessTreeBinaryUUIDMap,
		EndpointIdMap,
		Addr6LpmMap,
		Addr4LpmMap,
		DestinationEndpointMap,
		ListenEndpointMap,
		BpfEndpointIdMap,
		ProcessTreeConfigMap,
		MatchBinariesSetMap,
		MatchBinariesGenMap,
		ErrMetricsMap,
	}
	if !config.EnableLargeProgs() {
		maps = append(maps, ExecveTailCallsMap)
	}
	if enterpriseOption.Config.EnableApplicationModel && enterpriseOption.Config.EnableSyscallTracking {
		maps = append(maps, SyscallsMap)
	}

	maps = appendApplicationModelMaps(maps)

	// The BPF ring buffer is available from v5.8, but rather than add another set of
	// kernel-version-specific objects, let's set the gate at v5.11 as we already have
	// objects for that version number. We can revisit this of course.
	if config.EnableV511Progs() && !option.Config.UsePerfRingBuffer {
		maps = append(maps, RingBufEvents)
	}

	if option.Config.ParentsMapEnabled {
		maps = append(maps, ParentBinariesMap)
	}

	ConfigureMapSizes()
	return maps
}

//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package base

import (
	"github.com/cilium/tetragon/pkg/config"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/sensors/program"

	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"
	"github.com/isovalent/hubble-fgs/pkg/sensors/utils"
)

func GetDefaultPrograms() []*program.Program {
	progs := []*program.Program{
		Exit,
		Fork,
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
		ExecveTailCallsMap,
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
		ProcessTreeUUIDBinaryMap,
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
	if enterpriseOption.Config.EnableApplicationModel && enterpriseOption.Config.EnableSyscallTracking {
		maps = append(maps, SyscallsMap)
	}
	if enterpriseOption.Config.EnableApplicationModel {
		maps = append(maps, NsIDMap)
	}

	ConfigureMapSizes()
	return maps
}

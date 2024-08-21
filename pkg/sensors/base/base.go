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
	"fmt"
	"log"
	"sync"

	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/ksyms"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/mbset"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/sensors"
	ossbase "github.com/cilium/tetragon/pkg/sensors/base"
	"github.com/cilium/tetragon/pkg/sensors/program"
	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"
	"github.com/isovalent/hubble-fgs/pkg/sensors/socktrack"
)

var (
	basePolicy = "__base__"

	Execve = program.Builder(
		"bpf_execve_event.o",
		"sched/sched_process_exec",
		"tracepoint/sys_execve",
		"event_execve",
		"execve",
	).SetPolicy(basePolicy)

	ExecveV53 = program.Builder(
		"bpf_execve_event_v53.o",
		"sched/sched_process_exec",
		"tracepoint/sys_execve",
		"event_execve",
		"execve",
	).SetPolicy(basePolicy)

	ExecveV61 = program.Builder(
		"bpf_execve_event_v61.o",
		"sched/sched_process_exec",
		"tracepoint/sys_execve",
		"event_execve",
		"execve",
	).SetPolicy(basePolicy)

	ExecveV611 = program.Builder(
		"bpf_execve_event_v611.o",
		"sched/sched_process_exec",
		"tracepoint/sys_execve",
		"event_execve",
		"execve",
	).SetPolicy(basePolicy)

	ExecveBprmCommit = program.Builder(
		"bpf_execve_bprm_commit_creds.o",
		"security_bprm_committing_creds",
		"kprobe/security_bprm_committing_creds",
		"tg_kp_bprm_committing_creds",
		"kprobe",
	).SetPolicy(basePolicy)

	Exit = program.Builder(
		"bpf_exit.o",
		"acct_process",
		"kprobe/acct_process",
		"event_exit",
		"kprobe",
	).SetPolicy(basePolicy)

	Fork = program.Builder(
		"bpf_fork.o",
		"wake_up_new_task",
		"kprobe/wake_up_new_task",
		"kprobe_pid_clear",
		"kprobe",
	).SetPolicy(basePolicy)

	/* Event Ring map */
	TCPMonMap = program.MapBuilder("tcpmon_map", Execve, ExecveV53, ExecveV61, ExecveV611)

	/* Networking and Process Monitoring maps */
	ExecveMap                   = program.MapBuilder("execve_map", Execve, ExecveV53, ExecveV61, ExecveV611)
	ProcessNetworkWatermarksMap = program.MapBuilder("tg_pn_watermarks_map", Exit)
	SocketMap                   = program.MapBuilder(socktrack.SocketMapName, Exit)
	SocketStats                 = program.MapBuilder(socktrack.SocketStatsName, Exit)
	SocketTupleMap              = program.MapBuilder(socktrack.SocketTupleMapName, Exit)
	SocketTupleStats            = program.MapBuilder(socktrack.SocketTupleStatsName, Exit)
	SocketTupleRevMap           = program.MapBuilder(socktrack.SocketTupleRevMapName, Exit)
	SocketTupleHintMap          = program.MapBuilder(socktrack.SocketTupleHintMapName, Exit)
	CfgMap                      = program.MapBuilder(socktrack.SocketCfgMapName, Exit)

	ExecveTailCallsMap = program.MapBuilderType("execve_calls", program.MapTypeProgram, Execve, ExecveV53, ExecveV61, ExecveV611)

	ExecveJoinMap = program.MapBuilder("tg_execve_joined_info_map", ExecveBprmCommit)

	/* Tetragon runtime configuration */
	TetragonConfMap = program.MapBuilder("tg_conf_map", Execve, ExecveV53, ExecveV61, ExecveV611)

	/* Internal statistics for debugging */
	ExecveStats          = program.MapBuilder("execve_map_stats", Execve, ExecveV53, ExecveV61, ExecveV611)
	PNWatermarksMapStats = program.MapBuilder("tg_pn_watermarks_map_stats", Exit)
	ExecveJoinMapStats   = program.MapBuilder("tg_execve_joined_info_map_stats", ExecveBprmCommit)
	StatsMap             = program.MapBuilder("tg_stats_map", Execve)

	/* In BPF memory aggregated data */
	ProcessTreeMap           = program.MapBuilder("process_tree_map", Execve, ExecveV53, ExecveV61, ExecveV611)
	ProcessTreeBinaryUUIDMap = program.MapBuilder("process_tree_binary_uid_map", Execve, ExecveV53, ExecveV61, ExecveV611)
	ProcessTreeUUIDBinaryMap = program.MapBuilder("process_tree_uid_binary_map", Execve, ExecveV53, ExecveV61, ExecveV611)
	EndpointIdMap            = program.MapBuilder("tg_endpoint_id_map", Execve, ExecveV53, ExecveV61, ExecveV611)
	DestinationEndpointMap   = program.MapBuilder("destination_endpoint_map", Execve, ExecveV53, ExecveV61, ExecveV611)
	BpfEndpointIdMap         = program.MapBuilder("tg_bpf_endpoint_id_map", Execve, ExecveV53, ExecveV61, ExecveV611)
	PorcessTreeConfigMap     = program.MapBuilder("tg_process_tree_config_map", Execve)
	MatchBinariesSetMap      = program.MapBuilder(mbset.MapName, Execve)
)

func setupPrograms() {
	// execve program tail calls details
	Execve.SetTailCall("tracepoint", ExecveTailCallsMap)
	ExecveV53.SetTailCall("tracepoint", ExecveTailCallsMap)
	ExecveV61.SetTailCall("tracepoint", ExecveTailCallsMap)

	ks, err := ksyms.KernelSymbols()
	if err == nil {
		has_acct_process := ks.IsAvailable("acct_process")
		has_disassociate_ctty := ks.IsAvailable("disassociate_ctty")

		/* Preffer acct_process over disassociate_ctty */
		if has_acct_process {
			Exit.Attach = "acct_process"
			Exit.Label = "kprobe/acct_process"
		} else if has_disassociate_ctty {
			Exit.Attach = "disassociate_ctty"
			Exit.Label = "kprobe/disassociate_ctty"
		} else {
			log.Fatal("Failed to detect exit probe symbol.")
		}
	}
	logger.GetLogger().Infof("Exit probe on %s", Exit.Attach)
}

func GetExecveMap() *program.Map {
	return ExecveMap
}

func GetExecveMapStats() *program.Map {
	return ExecveStats
}

func GetTetragonConfMap() *program.Map {
	return TetragonConfMap
}

func GetDefaultPrograms() []*program.Program {
	progs := []*program.Program{
		Exit,
		Fork,
		ExecveBprmCommit,
	}
	if EnableV611Progs() {
		progs = append(progs, ExecveV611)
	} else if kernels.EnableV61Progs() {
		progs = append(progs, ExecveV61)
	} else if kernels.EnableLargeProgs() {
		progs = append(progs, ExecveV53)
	} else {
		progs = append(progs, Execve)
	}
	return progs
}

func GetDefaultMaps() []*program.Map {
	maps := []*program.Map{
		PNWatermarksMapStats,
		ProcessNetworkWatermarksMap,
		SocketMap,
		SocketStats,
		SocketTupleMap,
		SocketTupleStats,
		SocketTupleRevMap,
		SocketTupleHintMap,
		CfgMap,
		ExecveJoinMap,
		ExecveJoinMapStats,
		ExecveMap,
		ExecveStats,
		ExecveTailCallsMap,
		StatsMap,
		PorcessTreeConfigMap,
		MatchBinariesSetMap,
		TetragonConfMap,
		TCPMonMap,
		ProcessTreeMap,
		ProcessTreeBinaryUUIDMap,
		ProcessTreeUUIDBinaryMap,
		EndpointIdMap,
		DestinationEndpointMap,
		BpfEndpointIdMap,
	}

	ConfigureMapSizes()
	return maps
}

func initBaseSensor() *sensors.Sensor {
	sensor := sensors.Sensor{
		Name: basePolicy,
	}
	setupPrograms()
	sensor.Progs = GetDefaultPrograms()
	sensor.Maps = GetDefaultMaps()
	return ossbase.ApplyExtensions(&sensor)
}

var (
	// GetInitialSensor returns the collection of Sensor that is loaded at
	// initialization time.
	GetInitialSensor = sync.OnceValue(initBaseSensor)
)

// LoadDefault loads the default sensor, including any from the configuration
// file.
func LoadDefault(bpfDir string) error {
	// This is technically not a sensor since we are loading this
	// statically when we start, but it allows us to have a single path for
	// loading bpf programs.
	load := GetInitialSensor()
	if err := load.Load(bpfDir); err != nil {
		return fmt.Errorf("hubble-fgs, aborting could not load BPF programs: %w", err)
	}
	return nil
}

func ConfigureMapSizes() {
	// If Process Tree Modeling is enabled also set maps to minimal size
	// to avoid unnecessary memory usage.
	if !enterpriseOption.Config.EnableProcessTree {
		return
	}

	EndpointIdMap.SetMaxEntries(enterpriseOption.Config.EndpointCacheSize)
	BpfEndpointIdMap.SetMaxEntries(enterpriseOption.Config.BpfEndpointCacheSize)
	ProcessTreeBinaryUUIDMap.SetMaxEntries(enterpriseOption.Config.ProcessTreeCacheSize)
	ProcessTreeUUIDBinaryMap.SetMaxEntries(enterpriseOption.Config.ProcessTreeCacheSize)
	ProcessTreeMap.SetMaxEntries(enterpriseOption.Config.ProcessTreeCacheSize)
	DestinationEndpointMap.SetMaxEntries(enterpriseOption.Config.ProcessTreeCacheSize)
}

func EnableV611Progs() bool {
	if option.Config.ForceSmallProgs {
		return false
	}
	kernelVer, _, _ := kernels.GetKernelVersion(option.Config.KernelVersion, option.Config.ProcFS)
	return (int64(kernelVer) >= kernels.KernelStringToNumeric("6.11.0"))
}

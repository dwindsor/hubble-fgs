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
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/program"
	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"
	"github.com/isovalent/hubble-fgs/pkg/sensors/socktrack"
)

var (
	Execve = program.Builder(
		"bpf_execve_event.o",
		"sched/sched_process_exec",
		"tracepoint/sys_execve",
		"event_execve",
		"execve",
	)

	ExecveV53 = program.Builder(
		"bpf_execve_event_v53.o",
		"sched/sched_process_exec",
		"tracepoint/sys_execve",
		"event_execve",
		"execve",
	)

	ExecveV61 = program.Builder(
		"bpf_execve_event_v61.o",
		"sched/sched_process_exec",
		"tracepoint/sys_execve",
		"event_execve",
		"execve",
	)

	ExecveBprmCommit = program.Builder(
		"bpf_execve_bprm_commit_creds.o",
		"security_bprm_committing_creds",
		"kprobe/security_bprm_committing_creds",
		"tg_kp_bprm_committing_creds",
		"kprobe",
	)

	Exit = program.Builder(
		"bpf_exit.o",
		"acct_process",
		"kprobe/acct_process",
		"event_exit",
		"kprobe",
	)

	Fork = program.Builder(
		"bpf_fork.o",
		"wake_up_new_task",
		"kprobe/wake_up_new_task",
		"kprobe_pid_clear",
		"kprobe",
	)

	CgroupRmdir = program.Builder(
		"bpf_cgroup.o",
		"cgroup/cgroup_rmdir",
		"raw_tracepoint/cgroup_rmdir",
		"tg_cgroup_rmdir",
		"raw_tracepoint",
	)

	/* Event Ring map */
	TCPMonMap    = program.MapBuilder("tcpmon_map", Execve)
	TCPMonMapV53 = program.MapBuilder("tcpmon_map", ExecveV53)
	TCPMonMapV61 = program.MapBuilder("tcpmon_map", ExecveV61)

	/* Networking and Process Monitoring maps */
	ExecveMap                   = program.MapBuilder("execve_map", Execve)
	ExecveMapV53                = program.MapBuilder("execve_map", ExecveV53)
	ExecveMapV61                = program.MapBuilder("execve_map", ExecveV61)
	ProcessNetworkWatermarksMap = program.MapBuilder("tg_pn_watermarks_map", Exit)
	SocketMap                   = program.MapBuilder(socktrack.SocketMapName, Exit)
	SocketStats                 = program.MapBuilder(socktrack.SocketStatsName, Exit)
	SocketTupleMap              = program.MapBuilder(socktrack.SocketTupleMapName, Exit)
	SocketTupleStats            = program.MapBuilder(socktrack.SocketTupleStatsName, Exit)
	SocketTupleHintMap          = program.MapBuilder(socktrack.SocketTupleHintMapName, Exit)
	CfgMap                      = program.MapBuilder(socktrack.SocketCfgMapName, Exit)

	ExecveTailCallsMap    = program.MapBuilderPin("execve_calls", "execve_calls", Execve)
	ExecveTailCallsMapV53 = program.MapBuilderPin("execve_calls", "execve_calls", ExecveV53)
	ExecveTailCallsMapV61 = program.MapBuilderPin("execve_calls", "execve_calls", ExecveV61)

	ExecveJoinMap = program.MapBuilder("tg_execve_joined_info_map", ExecveBprmCommit)

	/* Tetragon runtime configuration */
	TetragonConfMap    = program.MapBuilder("tg_conf_map", Execve)
	TetragonConfMapV53 = program.MapBuilder("tg_conf_map", ExecveV53)
	TetragonConfMapV61 = program.MapBuilder("tg_conf_map", ExecveV61)

	/* Internal statistics for debugging */
	ExecveStats          = program.MapBuilder("execve_map_stats", Execve)
	ExecveStatsV53       = program.MapBuilder("execve_map_stats", ExecveV53)
	ExecveStatsV61       = program.MapBuilder("execve_map_stats", ExecveV61)
	PNWatermarksMapStats = program.MapBuilder("tg_pn_watermarks_map_stats", Exit)
	ExecveJoinMapStats   = program.MapBuilder("tg_execve_joined_info_map_stats", ExecveBprmCommit)
	StatsMap             = program.MapBuilder("tg_stats_map", Execve)

	/* Cgroup rate data, attached to execve sensor */
	CgroupRateMap        = program.MapBuilder("cgroup_rate_map", Execve)
	CgroupRateOptionsMap = program.MapBuilder("cgroup_rate_options_map", Execve)

	/* In BPF memory aggregated data */
	ProcessTreeMap           = program.MapBuilder("process_tree_map", Execve)
	ProcessTreeBinaryUUIDMap = program.MapBuilder("process_tree_binary_uid_map", Execve)
	ProcessTreeUUIDBinaryMap = program.MapBuilder("process_tree_uid_binary_map", Execve)

	EndpointIdMap    = program.MapBuilder("tg_endpoint_id_map", Execve)
	EndpointIdMapV53 = program.MapBuilder("tg_endpoint_id_map", ExecveV53)
	EndpointIdMapV61 = program.MapBuilder("tg_endpoint_id_map", ExecveV61)

	DestinationEndpointMap = program.MapBuilder("destination_endpoint_map", Execve)

	sensor = sensors.Sensor{
		Name: "__main__",
	}
	sensorInit sync.Once
)

func setupExitProgram() {
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
	if kernels.EnableV61Progs() {
		return ExecveMapV61
	}
	if kernels.EnableLargeProgs() {
		return ExecveMapV53
	}
	return ExecveMap
}

func GetExecveMapStats() *program.Map {
	if kernels.EnableLargeProgs() {
		return ExecveStatsV53
	}
	return ExecveStats
}

func GetTetragonConfMap() *program.Map {
	if kernels.EnableV61Progs() {
		return TetragonConfMapV61
	}
	if kernels.EnableLargeProgs() {
		return TetragonConfMapV53
	}
	return TetragonConfMap
}

func GetDefaultPrograms() []*program.Program {
	progs := []*program.Program{
		Exit,
		Fork,
		ExecveBprmCommit,
	}
	if kernels.EnableV61Progs() {
		progs = append(progs, ExecveV61)
	} else if kernels.EnableLargeProgs() {
		progs = append(progs, ExecveV53)
	} else {
		progs = append(progs, Execve)
	}
	if option.CgroupRateEnabled() {
		progs = append(progs, CgroupRmdir)
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
		SocketTupleHintMap,
		CfgMap,
		ExecveJoinMap,
		ExecveJoinMapStats,
		StatsMap,
		ProcessTreeMap,
		ProcessTreeBinaryUUIDMap,
		ProcessTreeUUIDBinaryMap,
		DestinationEndpointMap,
	}

	if kernels.EnableV61Progs() {
		maps = append(maps,
			ExecveMapV61,
			ExecveStatsV61,
			ExecveTailCallsMapV61,
			TCPMonMapV61,
			TetragonConfMapV61,
			EndpointIdMapV61,
		)
	} else if kernels.EnableLargeProgs() {
		maps = append(maps,
			ExecveMapV53,
			ExecveStatsV53,
			ExecveTailCallsMapV53,
			TCPMonMapV53,
			TetragonConfMapV53,
			EndpointIdMapV53,
		)
	} else {
		maps = append(maps,
			ExecveMap,
			ExecveStats,
			ExecveTailCallsMap,
			TCPMonMap,
			TetragonConfMap,
			EndpointIdMap,
		)
	}
	if option.CgroupRateEnabled() {
		maps = append(maps, CgroupRateMap, CgroupRateOptionsMap)
	}

	ConfigureMapSizes()
	return maps
}

// GetInitialSensor returns the collection of Sensor that is loaded at
// initialization time.
func GetInitialSensor() *sensors.Sensor {
	sensorInit.Do(func() {
		setupExitProgram()
		sensor.Progs = GetDefaultPrograms()
		sensor.Maps = GetDefaultMaps()
	})
	return &sensor
}

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
	EndpointIdMap.SetMaxEntries(enterpriseOption.Config.EndpointCacheSize)
	EndpointIdMapV53.SetMaxEntries(enterpriseOption.Config.EndpointCacheSize)
	EndpointIdMapV61.SetMaxEntries(enterpriseOption.Config.EndpointCacheSize)
}

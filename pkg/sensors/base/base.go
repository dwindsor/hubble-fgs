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

	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/program"
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

	/* Event Ring map */
	TCPMonMap    = program.MapBuilder("tcpmon_map", Execve)
	TCPMonMapV53 = program.MapBuilder("tcpmon_map", ExecveV53)
	TCPMonMapV61 = program.MapBuilder("tcpmon_map", ExecveV61)

	/* Networking and Process Monitoring maps */
	ExecveMap                   = program.MapBuilder("execve_map", Execve)
	ExecveMapV53                = program.MapBuilder("execve_map", ExecveV53)
	ExecveMapV61                = program.MapBuilder("execve_map", ExecveV61)
	ProcessNetworkWatermarksMap = program.MapBuilder("tg_pn_watermarks_map", Exit)

	ExecveTailCallsMap    = program.MapBuilderPin("execve_calls", "execve_calls", Execve)
	ExecveTailCallsMapV53 = program.MapBuilderPin("execve_calls", "execve_calls", ExecveV53)
	ExecveTailCallsMapV61 = program.MapBuilderPin("execve_calls", "execve_calls", ExecveV61)

	/* Policy maps populated from base programs */
	NamesMap    = program.MapBuilder("names_map", Execve)
	NamesMapV53 = program.MapBuilder("names_map", ExecveV53)
	NamesMapV61 = program.MapBuilder("names_map", ExecveV61)

	/* Tetragon runtime configuration */
	TetragonConfMap    = program.MapBuilder("tg_conf_map", Execve)
	TetragonConfMapV53 = program.MapBuilder("tg_conf_map", ExecveV53)
	TetragonConfMapV61 = program.MapBuilder("tg_conf_map", ExecveV61)

	/* Internal statistics for debugging */
	ExecveStats          = program.MapBuilder("execve_map_stats", Execve)
	ExecveStatsV53       = program.MapBuilder("execve_map_stats", ExecveV53)
	ExecveStatsV61       = program.MapBuilder("execve_map_stats", ExecveV61)
	PNWatermarksMapStats = program.MapBuilder("tg_pn_watermarks_map_stats", Exit)

	sensor = sensors.Sensor{
		Name:  "__main__",
		Progs: GetDefaultPrograms(),
		Maps:  GetDefaultMaps(),
	}
)

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
	}
	if kernels.EnableV61Progs() {
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
	}

	if kernels.EnableV61Progs() {
		maps = append(maps,
			ExecveMapV61,
			ExecveStatsV61,
			ExecveTailCallsMapV61,
			NamesMapV61,
			TCPMonMapV61,
			TetragonConfMapV61,
		)
	} else if kernels.EnableLargeProgs() {
		maps = append(maps,
			ExecveMapV53,
			ExecveStatsV53,
			ExecveTailCallsMapV53,
			NamesMapV53,
			TCPMonMapV53,
			TetragonConfMapV53,
		)
	} else {
		maps = append(maps,
			ExecveMap,
			ExecveStats,
			ExecveTailCallsMap,
			NamesMap,
			TCPMonMap,
			TetragonConfMap,
		)
	}
	return maps

}

// GetInitialSensor returns the collection of Sensor that is loaded at
// initialization time.
func GetInitialSensor() *sensors.Sensor {
	return &sensor
}

// LoadDefault loads the default sensor, including any from the configuration
// file.
func LoadDefault(bpfDir, mapDir string) error {
	// This is technically not a sensor since we are loading this
	// statically when we start, but it allows us to have a single path for
	// loading bpf programs.
	load := GetInitialSensor()
	if err := load.Load(bpfDir, mapDir); err != nil {
		return fmt.Errorf("hubble-fgs, aborting could not load BPF programs: %w", err)
	}
	return nil
}

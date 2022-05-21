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
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/isovalent/hubble-fgs/pkg/sensors/program"
)

var (
	Execve = program.ProgramBuilder(
		"bpf_execve_event.o",
		"sched/sched_process_exec",
		"tracepoint/sys_execve",
		"event_execve",
		"execve",
	)

	ExecveV53 = program.ProgramBuilder(
		"bpf_execve_event_v53.o",
		"sched/sched_process_exec",
		"tracepoint/sys_execve",
		"event_execve",
		"execve",
	)

	Exit = program.ProgramBuilder(
		"bpf_exit.o",
		"sched/sched_process_exit",
		"tracepoint/sys_exit",
		"event_exit",
		"tracepoint",
	)

	Fork = program.ProgramBuilder(
		"bpf_fork.o",
		"wake_up_new_task",
		"kprobe/wake_up_new_task",
		"kprobe_pid_clear",
		"kprobe",
	)

	/* Event Ring map */
	TCPMonMap    = program.MapBuilder("tcpmon_map", Execve)
	TCPMonMapV53 = program.MapBuilder("tcpmon_map", ExecveV53)

	/* Networking and Process Monitoring maps */
	ExecveMap              = program.MapBuilder("execve_map", Execve)
	ExecveMapV53           = program.MapBuilder("execve_map", ExecveV53)
	ProcessNetworkBurstMap = program.MapBuilder("pn_burst_map", Exit)

	/* Policy maps populated from base programs */
	NamesMap    = program.MapBuilder("names_map", Execve)
	NamesMapV53 = program.MapBuilder("names_map", ExecveV53)

	/* Internal statistics for debugging */
	ExecveStats     = program.MapBuilder("execve_map_stats", Execve)
	ExecveStatsV53  = program.MapBuilder("execve_map_stats", ExecveV53)
	PNBurstMapStats = program.MapBuilder("pn_burst_map_stats", Exit)
)

func GetExecveMap() *program.Map {
	if kernels.EnableLargeProgs() {
		return ExecveMapV53
	}
	return ExecveMap
}

func GetDefaultPrograms() []*program.Program {
	progs := []*program.Program{
		Exit,
		Fork,
	}
	if kernels.EnableLargeProgs() {
		progs = append(progs, ExecveV53)
	} else {
		progs = append(progs, Execve)
	}
	return progs
}

func GetDefaultMaps() []*program.Map {
	maps := []*program.Map{
		PNBurstMapStats,
		ProcessNetworkBurstMap,
	}

	if kernels.EnableLargeProgs() {
		maps = append(maps,
			ExecveMapV53,
			ExecveStatsV53,
			NamesMapV53,
			TCPMonMapV53,
		)
	} else {
		maps = append(maps,
			ExecveMap,
			ExecveStats,
			NamesMap,
			TCPMonMap,
		)
	}
	return maps

}

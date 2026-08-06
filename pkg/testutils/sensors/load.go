// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package sensors

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/config"
	"github.com/cilium/tetragon/pkg/option"
	sensorsoss "github.com/cilium/tetragon/pkg/sensors"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"

	"github.com/isovalent/hubble-fgs/pkg/sensors/utils"
)

func CheckSensorLoad(sensors []*sensorsoss.Sensor, sensorMaps []tus.SensorMap, sensorProgs []tus.SensorProg, t *testing.T) {
	var baseProgs []tus.SensorProg
	var baseMaps []tus.SensorMap

	if config.EnableLargeProgs() {
		baseProgs = []tus.SensorProg{
			0: {Name: "event_execve", Type: ebpf.RawTracepoint},
			1: {Name: "event_exit", Type: ebpf.Kprobe, Match: tus.ProgMatchPartial},
			2: {Name: "event_wake_up_new_task", Type: ebpf.Kprobe},
			3: {Name: "tg_kp_bprm_committing_creds", Type: ebpf.Kprobe},
			4: {Name: "execve_map_update", Type: ebpf.SocketFilter},
			5: {Name: "event_exit_acct_process", Type: ebpf.Kprobe},
		}
		baseMaps = []tus.SensorMap{
			// all process event programs
			{Name: "tcpmon_map", Progs: []uint{0, 1, 2}},

			// exit and fork
			{Name: "execve_map_stats", Progs: []uint{1, 2}},

			// event_wake_up_new_task
			{Name: "execve_val", Progs: []uint{2}},

			// event_execve and tg_kp_bprm_committing_creds
			{Name: "tg_execve_joined_info_map", Progs: []uint{0, 3}},
			{Name: "tg_execve_joined_info_map_stats", Progs: []uint{0, 3}},
		}
	} else {
		baseProgs = []tus.SensorProg{
			0: {Name: "event_execve", Type: ebpf.RawTracepoint},
			1: {Name: "event_exit", Type: ebpf.Kprobe, Match: tus.ProgMatchPartial},
			2: {Name: "event_wake_up_new_task", Type: ebpf.Kprobe},
			3: {Name: "execve_send", Type: ebpf.RawTracepoint},
			4: {Name: "tg_kp_bprm_committing_creds", Type: ebpf.Kprobe},
			5: {Name: "execve_rate", Type: ebpf.RawTracepoint},
			6: {Name: "execve_map_update", Type: ebpf.SocketFilter},
			7: {Name: "event_exit_acct_process", Type: ebpf.Kprobe},
		}
		baseMaps = []tus.SensorMap{
			// all process event programs
			{Name: "tcpmon_map", Progs: []uint{0, 1, 2, 3, 5}},

			// exit and fork
			{Name: "execve_map_stats", Progs: []uint{1, 2}},

			// event_wake_up_new_task
			{Name: "execve_val", Progs: []uint{2}},

			// event_execve and tg_kp_bprm_committing_creds
			{Name: "tg_execve_joined_info_map", Progs: []uint{0, 4}},
			{Name: "tg_execve_joined_info_map_stats", Progs: []uint{0, 4}},
		}
	}

	if utils.SupportProcessTree() {
		progs := []uint{0, 2, 3, 5, 7}
		if config.EnableLargeProgs() {
			progs = []uint{0, 2, 5}
		}
		pstreeMaps := []tus.SensorMap{
			{Name: "tg_conf_map", Progs: progs},
		}
		baseMaps = append(baseMaps, pstreeMaps...)
	}

	if option.CgroupRateEnabled() {
		sensorProgs = append(sensorProgs, tus.SensorProg{Name: "tg_cgroup_rmdir", Type: ebpf.RawTracepoint})

		progs := []uint{1, 2, 5, 6}
		if config.EnableLargeProgs() {
			progs = []uint{0, 1, 2, 4}
		}
		baseMaps = append(baseMaps, tus.SensorMap{Name: "cgroup_rate_map", Progs: progs})
	}

	if config.EnableLargeProgs() {
		// all programs
		baseMaps = append(baseMaps, tus.SensorMap{Name: "execve_map", Progs: []uint{0, 1, 2, 3, 4}})

		// execve_map_update
		baseMaps = append(baseMaps, tus.SensorMap{Name: "execve_map_update_data", Progs: []uint{4}})
	} else {
		// all programs except for execve_map_update, execve_rate
		baseMaps = append(baseMaps, tus.SensorMap{Name: "execve_map", Progs: []uint{0, 1, 2, 3, 4}})
	}

	tus.CheckSensorLoadBase(t, sensors, sensorMaps, sensorProgs, baseMaps, baseProgs)
}

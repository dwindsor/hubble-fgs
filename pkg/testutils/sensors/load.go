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

	"github.com/isovalent/hubble-fgs/pkg/sensors/base"
	"github.com/isovalent/hubble-fgs/pkg/sensors/utils"
)

func CheckSensorLoad(sensors []*sensorsoss.Sensor, sensorMaps []tus.SensorMap, sensorProgs []tus.SensorProg, t *testing.T) {
	send := "execve_send"
	if base.EnableV612Progs() {
		send = "ee_execve_send"
	}

	var baseProgs = []tus.SensorProg{
		0: tus.SensorProg{Name: "event_execve", Type: ebpf.RawTracepoint},
		1: tus.SensorProg{Name: "event_exit", Type: ebpf.Kprobe, Match: tus.ProgMatchPartial},
		2: tus.SensorProg{Name: "event_wake_up_new_task", Type: ebpf.Kprobe},
		3: tus.SensorProg{Name: send, Type: ebpf.RawTracepoint},
		4: tus.SensorProg{Name: "tg_kp_bprm_committing_creds", Type: ebpf.Kprobe},
		5: tus.SensorProg{Name: "execve_rate", Type: ebpf.RawTracepoint},
		6: tus.SensorProg{Name: "execve_map_update", Type: ebpf.SocketFilter},
		7: tus.SensorProg{Name: "event_exit_acct_process", Type: ebpf.Kprobe},
	}

	var baseMaps = []tus.SensorMap{
		// all programs
		tus.SensorMap{Name: "tcpmon_map", Progs: []uint{0, 1, 2, 3, 5}},

		// all but event_execve
		tus.SensorMap{Name: "execve_map_stats", Progs: []uint{1, 2}},

		// event_wake_up_new_task
		tus.SensorMap{Name: "execve_val", Progs: []uint{2}},

		// event_execve and tg_kp_bprm_committing_creds
		tus.SensorMap{Name: "tg_execve_joined_info_map", Progs: []uint{0, 4}},
		tus.SensorMap{Name: "tg_execve_joined_info_map_stats", Progs: []uint{0, 4}},
	}

	if utils.SupportProcessTree() {
		pstreeMaps := []tus.SensorMap{
			{Name: "tg_conf_map", Progs: []uint{0, 2, 3, 5, 7}},
		}
		baseMaps = append(baseMaps, pstreeMaps...)
	}

	if option.CgroupRateEnabled() {
		/* 6: tg_cgroup_rmdir */
		sensorProgs = append(sensorProgs, tus.SensorProg{Name: "tg_cgroup_rmdir", Type: ebpf.RawTracepoint})

		/* cgroup_rate_map */
		baseMaps = append(baseMaps, tus.SensorMap{Name: "cgroup_rate_map", Progs: []uint{1, 2, 5, 6}})
	}

	if config.EnableLargeProgs() {
		// all programs
		baseMaps = append(baseMaps, tus.SensorMap{Name: "execve_map", Progs: []uint{0, 1, 2, 3, 4, 6}})

		// execve_map_update
		baseMaps = append(baseMaps, tus.SensorMap{Name: "execve_map_update_data", Progs: []uint{6}})
	} else {
		// all programs except for execve_map_update, execve_rate
		baseMaps = append(baseMaps, tus.SensorMap{Name: "execve_map", Progs: []uint{0, 1, 2, 3, 4}})
	}

	tus.CheckSensorLoadBase(t, sensors, sensorMaps, sensorProgs, baseMaps, baseProgs)
}

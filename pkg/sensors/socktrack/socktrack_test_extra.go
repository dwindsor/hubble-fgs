//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.
//

package socktrack

import (
	"github.com/cilium/ebpf"
	"github.com/isovalent/hubble-fgs/pkg/sensors/utils"

	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
)

func ProgsAndMaps() ([]tus.SensorProg, []tus.SensorMap) {
	var sensorProgs []tus.SensorProg

	if utils.SupportFentry() {
		sensorProgs = []tus.SensorProg{
			0: tus.SensorProg{Name: "tg_security_sk_alloc", Type: ebpf.Tracing},
			1: tus.SensorProg{Name: "tg_security_sk_free", Type: ebpf.Tracing},
		}
	} else {
		sensorProgs = []tus.SensorProg{
			0: tus.SensorProg{Name: "tg_security_sk_alloc", Type: ebpf.Kprobe},
			1: tus.SensorProg{Name: "tg_security_sk_free", Type: ebpf.Kprobe},
		}
	}

	sensorMaps := []tus.SensorMap{
		tus.SensorMap{Name: "tg_l3_sk", Progs: []uint{0, 1}},
		tus.SensorMap{Name: "tg_l3_sk_stats", Progs: []uint{0, 1}},
		tus.SensorMap{Name: "tg_socket_tuple_map", Progs: []uint{1}},
		tus.SensorMap{Name: "tg_socket_tuple_map_stats", Progs: []uint{1}},
		tus.SensorMap{Name: "tg_rev_tuple_map", Progs: []uint{1}},
		tus.SensorMap{Name: "tg_socket_tuple_hint_map", Progs: []uint{1}},
		tus.SensorMap{Name: "tg_ver_map", Progs: []uint{0}},
		tus.SensorMap{Name: "tg_l3_cfg", Progs: []uint{0, 1}},
		tus.SensorMap{Name: "execve_map", Progs: []uint{0}},
		tus.SensorMap{Name: "tcpmon_map", Progs: []uint{0, 1}},
	}

	if utils.SupportProcessTree() {
		pstreeMaps := []tus.SensorMap{
			{Name: "tg_conf_map", Progs: []uint{0, 1}},
		}
		sensorMaps = append(sensorMaps, pstreeMaps...)
	}

	return sensorProgs, sensorMaps
}

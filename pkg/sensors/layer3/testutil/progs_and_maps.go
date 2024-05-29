//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package testutil

import (
	"github.com/cilium/ebpf"
	ossBTF "github.com/cilium/tetragon/pkg/btf"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/logger"

	fgsBTF "github.com/isovalent/hubble-fgs/pkg/btf"

	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3/internal/udp"
	"github.com/isovalent/hubble-fgs/pkg/sensors/socktrack"

	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
)

func AddToMap(maps []tus.SensorMap, name string, progs []uint) {
	for i, m := range maps {
		if m.Name == name {
			maps[i].Progs = append(maps[i].Progs, progs...)
			return
		}
	}
}

func MergeIntoMap(existing []uint, addon []uint, start uint) []uint {
	out := make([]uint, len(existing))
	copy(out, existing)
	for _, a := range addon {
		out = append(out, start+a)
	}
	return out
}

func GetMapProgs(maps []tus.SensorMap, name string) []uint {
	for _, m := range maps {
		if m.Name == name {
			return m.Progs
		}
	}
	return nil
}

func ProgsAndMaps(withUdpLatency bool, withIcmp bool, withRaw bool) ([]tus.SensorProg, []tus.SensorMap) {
	sensorProgs := []tus.SensorProg{
		0: tus.SensorProg{Name: "tg_event_tcp_connect", Type: ebpf.Kprobe},
		1: tus.SensorProg{Name: "tg_event_tcp_close_and_accept", Type: ebpf.Kprobe},
		2: tus.SensorProg{Name: "tg_event_sys_listen", Type: ebpf.Kprobe},

		// new accept sensor
		3: tus.SensorProg{Name: "tg_event_tcp_accept", Type: ebpf.Kprobe},
		4: tus.SensorProg{Name: "tg_event_tcp_accept_ret", Type: ebpf.Kprobe},
	}

	// all but close and accept
	socketMap := tus.SensorMap{Name: "tg_socket_map", Progs: []uint{0, 2, 4}}

	// just accept_ret
	socketMapStats := tus.SensorMap{Name: "tg_socket_map_stats", Progs: []uint{4}}

	// all but accept
	tcpSocketMap := tus.SensorMap{Name: "tg_tcpsocket_map", Progs: []uint{0, 1, 2, 4}}

	// all but accept
	tcpSocketMapStats := tus.SensorMap{Name: "tg_tcpsocket_map_stats", Progs: []uint{0, 1, 2, 4}}

	// all but accept
	socketTupleMap := tus.SensorMap{Name: "tg_socket_tuple_map", Progs: []uint{0, 1, 2, 4}}

	// all but accept
	socketTupleMapStats := tus.SensorMap{Name: "tg_socket_tuple_map_stats", Progs: []uint{0, 1, 2, 4}}

	// all but accept
	socketTupleHintMap := tus.SensorMap{Name: "tg_socket_tuple_hint_map", Progs: []uint{0, 1, 2, 4}}

	// all but accept and accept_ret
	tcpMonMap := tus.SensorMap{Name: "tcpmon_map", Progs: []uint{0, 1, 2}}

	// all but accept, accept_ret and event_tcp4_close
	execveMap := tus.SensorMap{Name: "execve_map", Progs: []uint{0, 2}}

	// all but accept
	cfgMap := tus.SensorMap{Name: "tg_cfg_map", Progs: []uint{0, 1, 2, 4}}

	verMap := tus.SensorMap{Name: "tg_ver_map", Progs: []uint{0, 2, 4}}

	latencyConfigMap := tus.SensorMap{Name: "tg_latency_config_map", Progs: []uint{}}

	sensorMaps := []tus.SensorMap{
		// accept and accept_ret
		tus.SensorMap{Name: "tg_tcp_accept_sock_map", Progs: []uint{3, 4}},
		tcpSocketMapStats,
	}

	spec, err := ossBTF.NewBTF()
	useIPv6InitHook := false
	if err != nil {
		logger.GetLogger().WithError(err).Warn("GetCachedBTF failed")
	} else {
		if spec == nil {
			logger.GetLogger().Warn("GetCachedBTF returned nil")
		} else {
			_, err := fgsBTF.GetFuncProto(spec, udp.SkUdpAlloc6.Attach, false)
			if err == nil {
				useIPv6InitHook = true
			}
		}
	}

	var ni uint // next index

	if !kernels.MinKernelVersion("5.4.0") { // 4.19 - <5.4
		sensorProgs = append(sensorProgs, []tus.SensorProg{
			tus.SensorProg{Name: "tg_udp_init_sock", Type: ebpf.Kprobe}, // Index 5
			tus.SensorProg{Name: "tg_udp_destroy_sock", Type: ebpf.Kprobe},
			tus.SensorProg{Name: "tg_inet_lazy_send_kp", Type: ebpf.Kprobe},
			tus.SensorProg{Name: "tg_udp4_send_kprobe", Type: ebpf.Kprobe},
			tus.SensorProg{Name: "tg_udp4_sendret_kprobe", Type: ebpf.Kprobe},
			tus.SensorProg{Name: "tg_udp6_send_kprobe", Type: ebpf.Kprobe},
			tus.SensorProg{Name: "tg_udp6_sendret_kprobe", Type: ebpf.Kprobe},
			tus.SensorProg{Name: "tg_udp_recv_kprobe", Type: ebpf.Kprobe},
			tus.SensorProg{Name: "tg_udp_bind_sock", Type: ebpf.Kprobe},
			tus.SensorProg{Name: "tg_event_tcp_v6_send_check", Type: ebpf.Kprobe},
			tus.SensorProg{Name: "tg_event_tcp_v4_send_check", Type: ebpf.Kprobe}, // Index 15
		}...)
		ni = 16

		sensorMaps = append(sensorMaps, []tus.SensorMap{
			// udp4_send_lazy_kprobe, udp4_sendret_lazy_kprobe, udp6_send_lazy_kprobe,
			// udp6_sendret_lazy_kprobe, udp_recv_lazy_kprobe
			tus.SensorMap{Name: "tg_udp_retprobe_map", Progs: []uint{8, 9, 10, 11}},

			// udp4_send_lazy_kprobe, udp4_sendret_lazy_kprobe, udp6_send_lazy_kprobe,
			// udp6_sendret_lazy_kprobe, udp_recv_lazy_kprobe
			tus.SensorMap{Name: "tg_udp_retprobe_map_stats", Progs: []uint{8, 9, 10, 11}},

			// inet_lazy_send_kp, udp4_sendret_lazy_kprobe, udp6_sendret_lazy_kprobe,
			// udp_recv_lazy_kprobe
			tus.SensorMap{Name: "tg_udp_map", Progs: []uint{7, 9, 11, 12}},
			tus.SensorMap{Name: "tg_udp_config_map", Progs: []uint{7}},
		}...)

		// udp_destroy_sock
		socketTupleMap.Progs = append(socketTupleMap.Progs, []uint{6, 9, 11, 12}...)
		socketTupleMapStats.Progs = append(socketTupleMapStats.Progs, []uint{6, 9, 11, 12}...)
		socketTupleHintMap.Progs = append(socketTupleHintMap.Progs, []uint{6, 9, 11, 12}...)
		// udp_init_sock, udp4_sendret_lazy_kprobe, udp6_sendret_lazy_kprobe, udp_recv_lazy_kprobe
		execveMap.Progs = append(execveMap.Progs, []uint{5, 7, 9, 11, 12, 14, 15}...)

		// udp_init_sock, udp_destroy_sock, inet_lazy_send_kp (not stats), udp4_sendret_lazy_kprobe,
		// udp6_sendret_lazy_kprobe, udp_recv_lazy_kprobe
		socketMap.Progs = append(socketMap.Progs, []uint{5, 6, 7, 9, 11, 12, 13}...)
		socketMapStats.Progs = append(socketMapStats.Progs, []uint{5, 6, 9, 11, 12}...)

		// tg_event_tcp_v4_send_check, tg_event_tcp_v6_send_check
		tcpSocketMap.Progs = append(tcpSocketMap.Progs, []uint{14, 15}...)

		// udp_init_sock, udp_destroy_sock, inet_lazy_send_kp, udp4_sendret_lazy_kprobe,
		// udp6_sendret_lazy_kprobe, udp_recv_lazy_kprobe
		tcpMonMap.Progs = append(tcpMonMap.Progs, []uint{5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}...)

		latencyConfigMap.Progs = append(latencyConfigMap.Progs, 7)

		cfgMap.Progs = append(cfgMap.Progs, []uint{6, 9, 11, 12}...)

		// udp_init_sock, udp4_sendret_kprobe, udp6_sendret_kprobe, udp_recv_kprobe
		verMap.Progs = append(verMap.Progs, []uint{5, 9, 11, 12}...)

		if useIPv6InitHook {
			sensorProgs = append(sensorProgs, tus.SensorProg{Name: "tg_udpv6_init_sock", Type: ebpf.Kprobe}) // Index 16
			execveMap.Progs = append(execveMap.Progs, 16)
			socketMap.Progs = append(socketMap.Progs, 16)
			socketMapStats.Progs = append(socketMapStats.Progs, 16)
			tcpMonMap.Progs = append(tcpMonMap.Progs, 16)
			verMap.Progs = append(verMap.Progs, 16)
			ni++
		}
	} else if !kernels.MinKernelVersion("5.15.0") { // 5.4 - <5.15
		sensorProgs = append(sensorProgs, []tus.SensorProg{
			tus.SensorProg{Name: "tg_udp_init_sock", Type: ebpf.Kprobe}, // Index 5
			tus.SensorProg{Name: "tg_udp_destroy_sock", Type: ebpf.Kprobe},
			tus.SensorProg{Name: "tg_cgroup_egress", Type: ebpf.CGroupSKB},
			tus.SensorProg{Name: "tg_cgroup_ingress", Type: ebpf.CGroupSKB},
			tus.SensorProg{Name: "tg_udp4_send_kprobe", Type: ebpf.Kprobe},
			tus.SensorProg{Name: "tg_udp4_sendret_kprobe", Type: ebpf.Kprobe},
			tus.SensorProg{Name: "tg_udp6_send_kprobe", Type: ebpf.Kprobe},
			tus.SensorProg{Name: "tg_udp6_sendret_kprobe", Type: ebpf.Kprobe},
			tus.SensorProg{Name: "tg_udp_recv_kprobe", Type: ebpf.Kprobe},
			tus.SensorProg{Name: "tg_udp_bind_sock", Type: ebpf.Kprobe}, // Index 14
		}...)
		ni = 15

		sensorMaps = append(sensorMaps, []tus.SensorMap{
			// udp4_send_lazy_kprobe, udp4_sendret_lazy_kprobe, udp6_send_lazy_kprobe,
			// udp6_sendret_lazy_kprobe, udp_recv_lazy_kprobe
			tus.SensorMap{Name: "tg_udp_retprobe_map", Progs: []uint{9, 10, 11, 12}},

			// udp4_send_lazy_kprobe, udp4_sendret_lazy_kprobe, udp6_send_lazy_kprobe,
			// udp6_sendret_lazy_kprobe, udp_recv_lazy_kprobe
			tus.SensorMap{Name: "tg_udp_retprobe_map_stats", Progs: []uint{9, 10, 11, 12}},

			// inet_lazy_send, inet_lazy_recv, udp4_sendret_lazy_kprobe, udp6_sendret_lazy_kprobe,
			// udp_recv_lazy_kprobe
			tus.SensorMap{Name: "tg_udp_map", Progs: []uint{7, 8, 10, 12, 13}},
			tus.SensorMap{Name: "tg_udp_config_map", Progs: []uint{7, 8}},
		}...)

		// udp_destroy_sock, inet_lazy_send, inet_lazy_recv
		socketTupleMap.Progs = append(socketTupleMap.Progs, []uint{6, 7, 8, 10, 12, 13}...)
		socketTupleMapStats.Progs = append(socketTupleMapStats.Progs, []uint{6, 7, 8, 10, 12, 13}...)
		socketTupleHintMap.Progs = append(socketTupleHintMap.Progs, []uint{6, 7, 8, 10, 12, 13}...)

		// udp_init_sock, udp4_sendret_lazy_kprobe, udp6_sendret_lazy_kprobe, udp_recv_lazy_kprobe
		execveMap.Progs = append(execveMap.Progs, []uint{5, 7, 8, 10, 12, 13}...)

		// udp_init_sock, udp_destroy_sock, inet_lazy_send (not stats), inet_lazy_recv (not stats),
		// udp4_sendret_lazy_kprobe, udp6_sendret_lazy_kprobe, udp_recv_lazy_kprobe
		socketMap.Progs = append(socketMap.Progs, []uint{5, 6, 7, 8, 10, 12, 13, 14}...)
		socketMapStats.Progs = append(socketMapStats.Progs, []uint{5, 6, 10, 12, 13}...)

		// cgroup_egress, cgroup_ingress
		tcpSocketMap.Progs = append(tcpSocketMap.Progs, []uint{7, 8}...)

		// udp_init_sock, udp_destroy_sock, inet_lazy_send, inet_lazy_recv, udp4_sendret_lazy_kprobe,
		// udp6_sendret_lazy_kprobe, udp_recv_lazy_kprobe
		tcpMonMap.Progs = append(tcpMonMap.Progs, []uint{5, 6, 7, 8, 9, 10, 11, 12, 13, 14}...)

		latencyConfigMap.Progs = append(latencyConfigMap.Progs, []uint{7, 8}...)

		cfgMap.Progs = append(cfgMap.Progs, []uint{6, 7, 8, 10, 12, 13}...)

		if !kernels.MinKernelVersion("5.5.0") { // 5.4 special snowflake
			sensorProgs = append(sensorProgs,
				tus.SensorProg{Name: "tg_event_tcp_v6_send_check", Type: ebpf.Kprobe}) // Index 15
			sensorProgs = append(sensorProgs,
				tus.SensorProg{Name: "tg_event_tcp_v4_send_check", Type: ebpf.Kprobe}) // Index 16

			execveMap.Progs = append(execveMap.Progs, []uint{15, 16}...)
			tcpSocketMap.Progs = append(tcpSocketMap.Progs, []uint{15, 16}...)
			tcpMonMap.Progs = append(tcpMonMap.Progs, []uint{15, 16}...)
			ni = 17
		}

		// udp_init_sock, udp4_sendret_kprobe, udp6_sendret_kprobe, udp_recv_kprobe
		verMap.Progs = append(verMap.Progs, []uint{5, 10, 12, 13}...)

		if useIPv6InitHook {
			sensorProgs = append(sensorProgs, tus.SensorProg{Name: "tg_udpv6_init_sock", Type: ebpf.Kprobe}) // Index ni
			execveMap.Progs = append(execveMap.Progs, ni)
			socketMap.Progs = append(socketMap.Progs, ni)
			socketMapStats.Progs = append(socketMapStats.Progs, ni)
			tcpMonMap.Progs = append(tcpMonMap.Progs, ni)
			verMap.Progs = append(verMap.Progs, ni)
			ni++
		}
	} else { // 5.15+
		sensorProgs = append(sensorProgs, []tus.SensorProg{
			tus.SensorProg{Name: "tg_udp_init_sock", Type: ebpf.Kprobe}, // Index 5
			tus.SensorProg{Name: "tg_udp_destroy_sock", Type: ebpf.Kprobe},
			tus.SensorProg{Name: "tg_cgroup_egress", Type: ebpf.CGroupSKB},
			tus.SensorProg{Name: "tg_cgroup_ingress", Type: ebpf.CGroupSKB},
			tus.SensorProg{Name: "tg_udp4_send_kprobe", Type: ebpf.Kprobe},
			tus.SensorProg{Name: "tg_udp4_sendret_kprobe", Type: ebpf.Kprobe},
			tus.SensorProg{Name: "tg_udp6_send_kprobe", Type: ebpf.Kprobe},
			tus.SensorProg{Name: "tg_udp6_sendret_kprobe", Type: ebpf.Kprobe},
			tus.SensorProg{Name: "tg_udp_recv_kprobe", Type: ebpf.Kprobe},
			tus.SensorProg{Name: "tg_udp_bind_sock", Type: ebpf.Kprobe},
			tus.SensorProg{Name: "tg_udp_bind_dummy4", Type: ebpf.CGroupSock},
			tus.SensorProg{Name: "tg_udp_bind_dummy6", Type: ebpf.CGroupSock}, // Index 16
		}...)
		ni = 17

		sensorMaps = append(sensorMaps, []tus.SensorMap{
			// udp4_send_lazy_kprobe, udp4_sendret_lazy_kprobe, udp6_send_lazy_kprobe,
			// udp6_sendret_lazy_kprobe, udp_recv_lazy_kprobe
			tus.SensorMap{Name: "tg_udp_retprobe_map", Progs: []uint{9, 10, 11, 12}},

			// udp4_send_lazy_kprobe, udp4_sendret_lazy_kprobe, udp6_send_lazy_kprobe,
			// udp6_sendret_lazy_kprobe, udp_recv_lazy_kprobe
			tus.SensorMap{Name: "tg_udp_retprobe_map_stats", Progs: []uint{9, 10, 11, 12}},

			// inet_lazy_send, inet_lazy_recv, udp4_sendret_lazy_kprobe, udp6_sendret_lazy_kprobe,
			// udp_recv_lazy_kprobe
			tus.SensorMap{Name: "tg_udp_map", Progs: []uint{7, 8, 10, 12, 13}},
			tus.SensorMap{Name: "tg_udp_config_map", Progs: []uint{7, 8}},
		}...)

		// udp_destroy_sock, inet_send, inet_recv
		socketTupleMap.Progs = append(socketTupleMap.Progs, []uint{6, 7, 8, 10, 12, 13}...)
		socketTupleMapStats.Progs = append(socketTupleMapStats.Progs, []uint{6, 7, 8, 10, 12, 13}...)
		socketTupleHintMap.Progs = append(socketTupleHintMap.Progs, []uint{6, 7, 8, 10, 12, 13}...)

		// udp_init_sock, udp4_sendret_lazy_kprobe, udp6_sendret_lazy_kprobe, udp_recv_lazy_kprobe
		execveMap.Progs = append(execveMap.Progs, []uint{5, 7, 8, 10, 12, 13}...)

		// udp_init_sock, udp_destroy_sock, inet_lazy_send (not stats), inet_lazy_recv (not stats),
		// udp4_sendret_lazy_kprobe, udp6_sendret_lazy_kprobe, udp_recv_lazy_kprobe
		socketMap.Progs = append(socketMap.Progs, []uint{5, 6, 7, 8, 10, 12, 13, 14}...)
		socketMapStats.Progs = append(socketMapStats.Progs, []uint{5, 6, 10, 12, 13}...)

		// cgroup_egress, cgroup_ingress
		tcpSocketMap.Progs = append(tcpSocketMap.Progs, []uint{7, 8}...)

		// udp_init_sock, udp_destroy_sock, inet_lazy_send, inet_lazy_recv, udp4_sendret_lazy_kprobe,
		// udp6_sendret_lazy_kprobe, udp_recv_lazy_kprobe
		tcpMonMap.Progs = append(tcpMonMap.Progs, []uint{5, 6, 7, 8, 9, 10, 11, 12, 13, 14}...)

		latencyConfigMap.Progs = append(latencyConfigMap.Progs, []uint{7, 8}...)

		cfgMap.Progs = append(cfgMap.Progs, []uint{6, 7, 8, 10, 12, 13}...)

		// udp_init_sock, udp4_sendret_kprobe, udp6_sendret_kprobe, udp_recv_kprobe
		verMap.Progs = append(verMap.Progs, []uint{5, 10, 12, 13}...)

		if useIPv6InitHook {
			sensorProgs = append(sensorProgs, tus.SensorProg{Name: "tg_udpv6_init_sock", Type: ebpf.Kprobe}) // Index ni
			execveMap.Progs = append(execveMap.Progs, ni)
			socketMap.Progs = append(socketMap.Progs, ni)
			socketMapStats.Progs = append(socketMapStats.Progs, ni)
			tcpMonMap.Progs = append(tcpMonMap.Progs, ni)
			verMap.Progs = append(verMap.Progs, ni)
			ni++
		}
	}

	if withUdpLatency {
		sensorProgs = append(sensorProgs, tus.SensorProg{Name: "tg_egress_timestamp", Type: ebpf.SchedCLS}) // index ni
		latencyConfigMap.Progs = append(latencyConfigMap.Progs, ni)
		tcpMonMap.Progs = append(tcpMonMap.Progs, ni)
		ni++
	}

	if withIcmp && kernels.MinKernelVersion("5.4.0") {
		sensorProgs = append(sensorProgs, []tus.SensorProg{
			tus.SensorProg{Name: "tg_ping_init_sock", Type: ebpf.Kprobe}, // index ni
			tus.SensorProg{Name: "tg_icmp_rcv", Type: ebpf.Kprobe},
			tus.SensorProg{Name: "tg_icmpv6_rcv", Type: ebpf.Kprobe}, // index ni + 2
		}...)
		socketMap.Progs = append(socketMap.Progs, []uint{ni, ni + 1, ni + 2}...)
		socketMapStats.Progs = append(socketMapStats.Progs, []uint{ni}...)
		socketTupleMap.Progs = append(socketTupleMap.Progs, []uint{ni + 1, ni + 2}...)
		socketTupleHintMap.Progs = append(socketTupleHintMap.Progs, []uint{ni + 1, ni + 2}...)
		tcpMonMap.Progs = append(tcpMonMap.Progs, []uint{ni, ni + 1, ni + 2}...)
		execveMap.Progs = append(execveMap.Progs, []uint{ni}...)
		cfgMap.Progs = append(cfgMap.Progs, []uint{ni, ni + 1, ni + 2}...)
		verMap.Progs = append(verMap.Progs, []uint{ni}...)
		ni += 3
	}

	if withRaw && kernels.MinKernelVersion("5.4.0") {
		sensorProgs = append(sensorProgs, []tus.SensorProg{
			tus.SensorProg{Name: "tg_rawsock_sk_init", Type: ebpf.Kprobe},   // index ni
			tus.SensorProg{Name: "tg_rawsockv6_init_sk", Type: ebpf.Kprobe}, // ni + 1
		}...)
		socketMap.Progs = append(socketMap.Progs, []uint{ni, ni + 1}...)
		socketMapStats.Progs = append(socketMapStats.Progs, []uint{ni, ni + 1}...)
		tcpMonMap.Progs = append(tcpMonMap.Progs, []uint{ni, ni + 1}...)
		execveMap.Progs = append(execveMap.Progs, []uint{ni, ni + 1}...)
		cfgMap.Progs = append(cfgMap.Progs, []uint{ni, ni + 1}...)
		verMap.Progs = append(verMap.Progs, []uint{ni, ni + 1}...)
		ni += 2
	}

	sockProgs, sockMaps := socktrack.ProgsAndMaps()
	sensorProgs = append(sensorProgs, sockProgs...) // starts at index ni

	socketMap.Progs = MergeIntoMap(socketMap.Progs, GetMapProgs(sockMaps, socketMap.Name), ni)
	socketMapStats.Progs = MergeIntoMap(socketMapStats.Progs, GetMapProgs(sockMaps, socketMapStats.Name), ni)
	socketTupleMap.Progs = MergeIntoMap(socketTupleMap.Progs, GetMapProgs(sockMaps, socketTupleMap.Name), ni)
	socketTupleMapStats.Progs = MergeIntoMap(socketTupleMapStats.Progs, GetMapProgs(sockMaps, socketTupleMapStats.Name), ni)
	socketTupleHintMap.Progs = MergeIntoMap(socketTupleHintMap.Progs, GetMapProgs(sockMaps, socketTupleHintMap.Name), ni)
	execveMap.Progs = MergeIntoMap(execveMap.Progs, GetMapProgs(sockMaps, execveMap.Name), ni)
	tcpMonMap.Progs = MergeIntoMap(tcpMonMap.Progs, GetMapProgs(sockMaps, tcpMonMap.Name), ni)
	cfgMap.Progs = MergeIntoMap(cfgMap.Progs, GetMapProgs(sockMaps, cfgMap.Name), ni)
	verMap.Progs = MergeIntoMap(verMap.Progs, GetMapProgs(sockMaps, verMap.Name), ni)

	sensorMaps = append(sensorMaps, []tus.SensorMap{
		socketMap,
		socketMapStats,
		socketTupleMap,
		socketTupleMapStats,
		socketTupleHintMap,
		tcpSocketMap,
		execveMap,
		tcpMonMap,
		latencyConfigMap,
		cfgMap,
		verMap,
	}...)

	return sensorProgs, sensorMaps
}

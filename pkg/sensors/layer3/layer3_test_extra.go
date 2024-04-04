//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package layer3

import (
	"github.com/cilium/ebpf"
	ossBTF "github.com/cilium/tetragon/pkg/btf"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/logger"

	fgsBTF "github.com/isovalent/hubble-fgs/pkg/btf"

	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3/internal/udp"

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

func ProgsAndMaps(withUdpLatency bool, withIcmp bool, withRaw bool) ([]tus.SensorProg, []tus.SensorMap) {
	sensorProgs := []tus.SensorProg{
		0: tus.SensorProg{Name: "tg_event_tcp_connect", Type: ebpf.Kprobe},
		1: tus.SensorProg{Name: "tg_event_tcp_close_and_accept", Type: ebpf.Kprobe},
		2: tus.SensorProg{Name: "tg_event_sys_listen", Type: ebpf.Kprobe},
		3: tus.SensorProg{Name: "tg_event_tcp_v4_send_check", Type: ebpf.Kprobe},

		// new accept sensor
		4: tus.SensorProg{Name: "tg_event_tcp_accept", Type: ebpf.Kprobe},
		5: tus.SensorProg{Name: "tg_event_tcp_accept_ret", Type: ebpf.Kprobe},

		// IPv6 sensor
		6: tus.SensorProg{Name: "tg_event_tcp_v6_send_check", Type: ebpf.Kprobe},
	}

	// all but accept
	socketMap := tus.SensorMap{Name: "tg_socket_map", Progs: []uint{0, 1, 2, 3, 5, 6}}

	// all but base, accept, event_tcp_v4_send_check and event_tcp_v6_send_check
	socketMapStats := tus.SensorMap{Name: "tg_socket_map_stats", Progs: []uint{0, 1, 2, 5}}

	// all but base, event_tcp_v4_send_check and event_tcp_v6_send_check
	socketTupleMap := tus.SensorMap{Name: "tg_socket_tuple_map", Progs: []uint{0, 1, 2, 5}}

	// all but base, event_tcp_v4_send_check and event_tcp_v6_send_check
	socketTupleMapStats := tus.SensorMap{Name: "tg_socket_tuple_map_stats", Progs: []uint{0, 1, 2, 5}}

	// all but base, event_tcp_v4_send_check and event_tcp_v6_send_check
	socketTupleHintMap := tus.SensorMap{Name: "tg_socket_tuple_hint_map", Progs: []uint{0, 1, 2, 5}}

	// all but accept and accept_ret
	tcpMonMap := tus.SensorMap{Name: "tcpmon_map", Progs: []uint{0, 1, 2, 3, 6}}

	// all but accept, accept_ret and event_tcp4_close
	execveMap := tus.SensorMap{Name: "execve_map", Progs: []uint{0, 2, 3, 6}}

	// all but accept, accept_ret and event_tcp4_close
	cfgMap := tus.SensorMap{Name: "tg_cfg_map", Progs: []uint{0, 1, 2, 5}}

	latencyConfigMap := tus.SensorMap{Name: "tg_latency_config_map", Progs: []uint{}}

	sensorMaps := []tus.SensorMap{
		// accept and accept_ret
		tus.SensorMap{Name: "tg_tcp_accept_sock_map", Progs: []uint{4, 5}},
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
			tus.SensorProg{Name: "tg_udp_init_sock", Type: ebpf.Kprobe}, // Index 7
			tus.SensorProg{Name: "tg_udp_destroy_sock", Type: ebpf.Kprobe},
			tus.SensorProg{Name: "tg_inet_lazy_send_kp", Type: ebpf.Kprobe},
			tus.SensorProg{Name: "tg_udp4_send_kprobe", Type: ebpf.Kprobe},
			tus.SensorProg{Name: "tg_udp4_sendret_kprobe", Type: ebpf.Kprobe},
			tus.SensorProg{Name: "tg_udp6_send_kprobe", Type: ebpf.Kprobe},
			tus.SensorProg{Name: "tg_udp6_sendret_kprobe", Type: ebpf.Kprobe},
			tus.SensorProg{Name: "tg_udp_recv_kprobe", Type: ebpf.Kprobe},
			tus.SensorProg{Name: "tg_udp_bind_sock", Type: ebpf.Kprobe}, // Index 15
		}...)
		ni = 16

		sensorMaps = append(sensorMaps, []tus.SensorMap{
			// udp4_send_lazy_kprobe, udp4_sendret_lazy_kprobe, udp6_send_lazy_kprobe,
			// udp6_sendret_lazy_kprobe, udp_recv_lazy_kprobe
			tus.SensorMap{Name: "tg_udp_retprobe_map", Progs: []uint{10, 11, 12, 13}},

			// udp4_send_lazy_kprobe, udp4_sendret_lazy_kprobe, udp6_send_lazy_kprobe,
			// udp6_sendret_lazy_kprobe, udp_recv_lazy_kprobe
			tus.SensorMap{Name: "tg_udp_retprobe_map_stats", Progs: []uint{10, 11, 12, 13}},

			// inet_lazy_send_kp, udp4_sendret_lazy_kprobe, udp6_sendret_lazy_kprobe,
			// udp_recv_lazy_kprobe
			tus.SensorMap{Name: "tg_udp_map", Progs: []uint{9, 11, 13, 14}},
			tus.SensorMap{Name: "tg_udp_config_map", Progs: []uint{9}},
		}...)

		// udp_destroy_sock
		socketTupleMap.Progs = append(socketTupleMap.Progs, []uint{8, 11, 13, 14}...)
		socketTupleMapStats.Progs = append(socketTupleMapStats.Progs, []uint{8, 11, 13, 14}...)
		socketTupleHintMap.Progs = append(socketTupleHintMap.Progs, []uint{8, 11, 13, 14}...)
		// udp_init_sock, udp4_sendret_lazy_kprobe, udp6_sendret_lazy_kprobe, udp_recv_lazy_kprobe
		execveMap.Progs = append(execveMap.Progs, []uint{7, 9, 11, 13, 14}...)

		// udp_init_sock, udp_destroy_sock, inet_lazy_send_kp (not stats), udp4_sendret_lazy_kprobe,
		// udp6_sendret_lazy_kprobe, udp_recv_lazy_kprobe
		socketMap.Progs = append(socketMap.Progs, []uint{7, 8, 9, 11, 13, 14, 15, 16}...)
		socketMapStats.Progs = append(socketMapStats.Progs, []uint{7, 8, 11, 13, 14}...)

		// udp_init_sock, udp_destroy_sock, inet_lazy_send_kp, udp4_sendret_lazy_kprobe,
		// udp6_sendret_lazy_kprobe, udp_recv_lazy_kprobe
		tcpMonMap.Progs = append(tcpMonMap.Progs, []uint{7, 8, 9, 10, 11, 12, 13, 14, 15}...)

		latencyConfigMap.Progs = append(latencyConfigMap.Progs, 9)

		cfgMap.Progs = append(cfgMap.Progs, []uint{8, 11, 13, 14}...)

		if useIPv6InitHook {
			sensorProgs = append(sensorProgs, tus.SensorProg{Name: "tg_udpv6_init_sock", Type: ebpf.Kprobe}) // Index 16
			execveMap.Progs = append(execveMap.Progs, 16)
			socketMap.Progs = append(socketMap.Progs, 16)
			socketMapStats.Progs = append(socketMapStats.Progs, 16)
			tcpMonMap.Progs = append(tcpMonMap.Progs, 16)
			ni++
		}
	} else if !kernels.MinKernelVersion("5.10.0") { // 5.4 - <5.10
		sensorProgs = append(sensorProgs, []tus.SensorProg{
			tus.SensorProg{Name: "tg_udp_init_sock", Type: ebpf.Kprobe}, // Index 7
			tus.SensorProg{Name: "tg_udp_destroy_sock", Type: ebpf.Kprobe},
			tus.SensorProg{Name: "tg_inet_lazy_send", Type: ebpf.CGroupSKB},
			tus.SensorProg{Name: "tg_inet_lazy_recv", Type: ebpf.CGroupSKB},
			tus.SensorProg{Name: "tg_udp4_send_kprobe", Type: ebpf.Kprobe},
			tus.SensorProg{Name: "tg_udp4_sendret_kprobe", Type: ebpf.Kprobe},
			tus.SensorProg{Name: "tg_udp6_send_kprobe", Type: ebpf.Kprobe},
			tus.SensorProg{Name: "tg_udp6_sendret_kprobe", Type: ebpf.Kprobe},
			tus.SensorProg{Name: "tg_udp_recv_kprobe", Type: ebpf.Kprobe},
			tus.SensorProg{Name: "tg_udp_bind_sock", Type: ebpf.Kprobe}, // Index 16
		}...)
		ni = 17

		sensorMaps = append(sensorMaps, []tus.SensorMap{
			// udp4_send_lazy_kprobe, udp4_sendret_lazy_kprobe, udp6_send_lazy_kprobe,
			// udp6_sendret_lazy_kprobe, udp_recv_lazy_kprobe
			tus.SensorMap{Name: "tg_udp_retprobe_map", Progs: []uint{11, 12, 13, 14}},

			// udp4_send_lazy_kprobe, udp4_sendret_lazy_kprobe, udp6_send_lazy_kprobe,
			// udp6_sendret_lazy_kprobe, udp_recv_lazy_kprobe
			tus.SensorMap{Name: "tg_udp_retprobe_map_stats", Progs: []uint{11, 12, 13, 14}},

			// inet_lazy_send, inet_lazy_recv, udp4_sendret_lazy_kprobe, udp6_sendret_lazy_kprobe,
			// udp_recv_lazy_kprobe
			tus.SensorMap{Name: "tg_udp_map", Progs: []uint{9, 10, 12, 14, 15}},
			tus.SensorMap{Name: "tg_udp_config_map", Progs: []uint{9, 10}},
		}...)

		// udp_destroy_sock, inet_lazy_send, inet_lazy_recv
		socketTupleMap.Progs = append(socketTupleMap.Progs, []uint{8, 9, 10, 12, 14, 15}...)
		socketTupleMapStats.Progs = append(socketTupleMapStats.Progs, []uint{8, 9, 10, 12, 14, 15}...)
		socketTupleHintMap.Progs = append(socketTupleHintMap.Progs, []uint{8, 9, 10, 12, 14, 15}...)

		// udp_init_sock, udp4_sendret_lazy_kprobe, udp6_sendret_lazy_kprobe, udp_recv_lazy_kprobe
		execveMap.Progs = append(execveMap.Progs, []uint{7, 9, 10, 12, 14, 15}...)

		// udp_init_sock, udp_destroy_sock, inet_lazy_send (not stats), inet_lazy_recv (not stats),
		// udp4_sendret_lazy_kprobe, udp6_sendret_lazy_kprobe, udp_recv_lazy_kprobe
		socketMap.Progs = append(socketMap.Progs, []uint{7, 8, 9, 10, 12, 14, 15, 16}...)
		socketMapStats.Progs = append(socketMapStats.Progs, []uint{7, 8, 12, 14, 15}...)

		// udp_init_sock, udp_destroy_sock, inet_lazy_send, inet_lazy_recv, udp4_sendret_lazy_kprobe,
		// udp6_sendret_lazy_kprobe, udp_recv_lazy_kprobe
		tcpMonMap.Progs = append(tcpMonMap.Progs, []uint{7, 8, 9, 10, 11, 12, 13, 14, 15, 16}...)

		latencyConfigMap.Progs = append(latencyConfigMap.Progs, 10)

		cfgMap.Progs = append(cfgMap.Progs, []uint{8, 9, 10, 12, 14, 15}...)

		if useIPv6InitHook {
			sensorProgs = append(sensorProgs, tus.SensorProg{Name: "tg_udpv6_init_sock", Type: ebpf.Kprobe}) // Index 17
			execveMap.Progs = append(execveMap.Progs, 17)
			socketMap.Progs = append(socketMap.Progs, 17)
			socketMapStats.Progs = append(socketMapStats.Progs, 17)
			tcpMonMap.Progs = append(tcpMonMap.Progs, 17)
			ni++
		}
	} else { // 5.10+
		sensorProgs = append(sensorProgs, []tus.SensorProg{
			tus.SensorProg{Name: "tg_udp_init_sock", Type: ebpf.Kprobe}, // Index 7
			tus.SensorProg{Name: "tg_udp_destroy_sock", Type: ebpf.Kprobe},
			tus.SensorProg{Name: "tg_inet_send", Type: ebpf.CGroupSKB},
			tus.SensorProg{Name: "tg_inet_recv", Type: ebpf.CGroupSKB},
			tus.SensorProg{Name: "tg_udp4_send_kprobe", Type: ebpf.Kprobe},
			tus.SensorProg{Name: "tg_udp4_sendret_kprobe", Type: ebpf.Kprobe},
			tus.SensorProg{Name: "tg_udp6_send_kprobe", Type: ebpf.Kprobe},
			tus.SensorProg{Name: "tg_udp6_sendret_kprobe", Type: ebpf.Kprobe},
			tus.SensorProg{Name: "tg_udp_recv_kprobe", Type: ebpf.Kprobe},
			tus.SensorProg{Name: "tg_udp_bind_sock", Type: ebpf.Kprobe},
			tus.SensorProg{Name: "tg_udp_bind_dummy4", Type: ebpf.CGroupSock},
			tus.SensorProg{Name: "tg_udp_bind_dummy6", Type: ebpf.CGroupSock}, // Index 18
		}...)
		ni = 19

		sensorMaps = append(sensorMaps, []tus.SensorMap{
			// udp4_send_lazy_kprobe, udp4_sendret_lazy_kprobe, udp6_send_lazy_kprobe,
			// udp6_sendret_lazy_kprobe, udp_recv_lazy_kprobe
			tus.SensorMap{Name: "tg_udp_retprobe_map", Progs: []uint{11, 12, 13, 14}},

			// udp4_send_lazy_kprobe, udp4_sendret_lazy_kprobe, udp6_send_lazy_kprobe,
			// udp6_sendret_lazy_kprobe, udp_recv_lazy_kprobe
			tus.SensorMap{Name: "tg_udp_retprobe_map_stats", Progs: []uint{11, 12, 13, 14}},

			// inet_lazy_send, inet_lazy_recv, udp4_sendret_lazy_kprobe, udp6_sendret_lazy_kprobe,
			// udp_recv_lazy_kprobe
			tus.SensorMap{Name: "tg_udp_map", Progs: []uint{9, 10, 12, 14, 15}},
			tus.SensorMap{Name: "tg_udp_config_map", Progs: []uint{9, 10}},
		}...)

		// udp_destroy_sock, inet_send, inet_recv
		socketTupleMap.Progs = append(socketTupleMap.Progs, []uint{8, 9, 10, 12, 14, 15}...)
		socketTupleMapStats.Progs = append(socketTupleMapStats.Progs, []uint{8, 9, 10, 12, 14, 15}...)
		socketTupleHintMap.Progs = append(socketTupleHintMap.Progs, []uint{8, 9, 10, 12, 14, 15}...)

		// udp_init_sock, udp4_sendret_lazy_kprobe, udp6_sendret_lazy_kprobe, udp_recv_lazy_kprobe
		execveMap.Progs = append(execveMap.Progs, []uint{7, 9, 10, 12, 14, 15}...)

		// udp_init_sock, udp_destroy_sock, inet_lazy_send (not stats), inet_lazy_recv (not stats),
		// udp4_sendret_lazy_kprobe, udp6_sendret_lazy_kprobe, udp_recv_lazy_kprobe
		socketMap.Progs = append(socketMap.Progs, []uint{7, 8, 9, 10, 12, 14, 15, 16}...)
		socketMapStats.Progs = append(socketMapStats.Progs, []uint{7, 8, 12, 14, 15}...)

		// udp_init_sock, udp_destroy_sock, inet_lazy_send, inet_lazy_recv, udp4_sendret_lazy_kprobe,
		// udp6_sendret_lazy_kprobe, udp_recv_lazy_kprobe
		tcpMonMap.Progs = append(tcpMonMap.Progs, []uint{7, 8, 9, 10, 11, 12, 13, 14, 15, 16}...)

		latencyConfigMap.Progs = append(latencyConfigMap.Progs, 10)

		cfgMap.Progs = append(cfgMap.Progs, []uint{8, 9, 10, 12, 14, 15}...)

		if useIPv6InitHook {
			sensorProgs = append(sensorProgs, tus.SensorProg{Name: "tg_udpv6_init_sock", Type: ebpf.Kprobe}) // Index 19
			execveMap.Progs = append(execveMap.Progs, 19)
			socketMap.Progs = append(socketMap.Progs, 19)
			socketMapStats.Progs = append(socketMapStats.Progs, 19)
			tcpMonMap.Progs = append(tcpMonMap.Progs, 19)
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
		if !kernels.MinKernelVersion("5.10.0") { // 5.4 - 5.9
			sensorProgs = append(sensorProgs, []tus.SensorProg{
				tus.SensorProg{Name: "tg_icmp_raw_sk_init", Type: ebpf.Kprobe}, // index ni
				tus.SensorProg{Name: "tg_ping_init_sock", Type: ebpf.Kprobe},
				tus.SensorProg{Name: "tg_icmp_sk_free", Type: ebpf.Kprobe},
				tus.SensorProg{Name: "tg_icmp_send_lazy", Type: ebpf.CGroupSKB},
				tus.SensorProg{Name: "tg_icmp_recv_lazy", Type: ebpf.CGroupSKB},
				tus.SensorProg{Name: "tg_icmp_rcv", Type: ebpf.Kprobe},
				tus.SensorProg{Name: "tg_icmp_rawv6_init_sk", Type: ebpf.Kprobe},
				tus.SensorProg{Name: "tg_icmpv6_rcv", Type: ebpf.Kprobe}, // index ni + 7
			}...)
		} else { // 5.10 -
			sensorProgs = append(sensorProgs, []tus.SensorProg{
				tus.SensorProg{Name: "tg_icmp_raw_sk_init", Type: ebpf.Kprobe}, // index ni
				tus.SensorProg{Name: "tg_ping_init_sock", Type: ebpf.Kprobe},
				tus.SensorProg{Name: "tg_icmp_sk_free", Type: ebpf.Kprobe},
				tus.SensorProg{Name: "tg_icmp_send", Type: ebpf.CGroupSKB},
				tus.SensorProg{Name: "tg_icmp_recv", Type: ebpf.CGroupSKB},
				tus.SensorProg{Name: "tg_icmp_rcv", Type: ebpf.Kprobe},
				tus.SensorProg{Name: "tg_icmp_rawv6_init_sk", Type: ebpf.Kprobe},
				tus.SensorProg{Name: "tg_icmpv6_rcv", Type: ebpf.Kprobe}, // index ni + 7
			}...)
		}
		socketMap.Progs = append(socketMap.Progs, []uint{ni, ni + 1, ni + 2, ni + 3, ni + 4, ni + 5, ni + 6, ni + 7}...)
		socketMapStats.Progs = append(socketMapStats.Progs, []uint{ni, ni + 1, ni + 2, ni + 6}...)
		socketTupleMap.Progs = append(socketTupleMap.Progs, []uint{ni + 2, ni + 5, ni + 7}...)
		socketTupleMapStats.Progs = append(socketTupleMapStats.Progs, []uint{ni + 2}...)
		socketTupleHintMap.Progs = append(socketTupleHintMap.Progs, []uint{ni + 2, ni + 5, ni + 7}...)
		tcpMonMap.Progs = append(tcpMonMap.Progs, []uint{ni, ni + 1, ni + 3, ni + 4, ni + 5, ni + 6, ni + 7}...)
		execveMap.Progs = append(execveMap.Progs, []uint{ni, ni + 1, ni + 6}...)
		cfgMap.Progs = append(cfgMap.Progs, []uint{ni + 2, ni + 3, ni + 4, ni + 5, ni + 7}...)
		ni += 8
	}

	if withRaw && kernels.MinKernelVersion("5.4.0") {
		sensorProgs = append(sensorProgs, []tus.SensorProg{
			tus.SensorProg{Name: "tg_rawsock_sk_init", Type: ebpf.Kprobe}, // index ni
			tus.SensorProg{Name: "tg_rawsockv6_init_sk", Type: ebpf.Kprobe},
			tus.SensorProg{Name: "tg_raw_packet_reg_prot_hook", Type: ebpf.Kprobe},
			tus.SensorProg{Name: "tg_rawsock_sk_free", Type: ebpf.Kprobe}, // index ni + 3
		}...)
		socketMap.Progs = append(socketMap.Progs, []uint{ni, ni + 1, ni + 2, ni + 3}...)
		socketMapStats.Progs = append(socketMapStats.Progs, []uint{ni, ni + 1, ni + 2, ni + 3}...)
		tcpMonMap.Progs = append(tcpMonMap.Progs, []uint{ni, ni + 1, ni + 2, ni + 3}...)
		execveMap.Progs = append(execveMap.Progs, []uint{ni, ni + 1, ni + 2}...)
		socketTupleMap.Progs = append(socketTupleMap.Progs, []uint{ni + 3}...)
		socketTupleMapStats.Progs = append(socketTupleMapStats.Progs, []uint{ni + 3}...)
		socketTupleHintMap.Progs = append(socketTupleHintMap.Progs, []uint{ni + 3}...)
		cfgMap.Progs = append(cfgMap.Progs, []uint{ni + 3}...)
	}

	sensorMaps = append(sensorMaps, []tus.SensorMap{
		socketMap,
		socketMapStats,
		socketTupleMap,
		socketTupleMapStats,
		socketTupleHintMap,
		execveMap,
		tcpMonMap,
		latencyConfigMap,
		cfgMap,
	}...)

	return sensorProgs, sensorMaps
}

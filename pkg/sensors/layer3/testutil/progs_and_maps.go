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
	"runtime"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/kernels"

	"github.com/isovalent/hubble-fgs/pkg/sensors/socktrack"
	"github.com/isovalent/hubble-fgs/pkg/sensors/utils"

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

func progInList(name string, progNames []string) bool {
	for _, p := range progNames {
		if name == p {
			return true
		}
	}
	return false
}

func getMapIndicesByName(progs []tus.SensorProg, progNames []string) []uint {
	maps := make([]uint, 0)
	for i, p := range progs {
		if progInList(p.Name, progNames) {
			maps = append(maps, uint(i))
		}
	}
	return maps
}

func SensorMapByProgName(progs []tus.SensorProg, mapName string, progNames []string) tus.SensorMap {
	return tus.SensorMap{Name: mapName, Progs: getMapIndicesByName(progs, progNames)}
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

	if utils.SupportFentry() {
		sensorProgs = append(sensorProgs, []tus.SensorProg{
			tus.SensorProg{Name: "security_sk_alloc",
				Type: ebpf.Tracing,
			},
		}...)
	}

	socketMap := SensorMapByProgName(sensorProgs, "tg_socket_map", []string{
		"tg_event_tcp_connect", "tg_event_sys_listen", "tg_event_tcp_accept_ret",
	})

	socketMapStats := SensorMapByProgName(sensorProgs, "tg_socket_map_stats", []string{
		"tg_event_tcp_accept_ret",
	})

	tcpSocketMap := SensorMapByProgName(sensorProgs, "tg_tcpsocket_map", []string{
		"tg_event_tcp_connect", "tg_event_tcp_close_and_accept", "tg_event_sys_listen",
		"tg_event_tcp_accept_ret",
	})

	tcpSocketMapStats := SensorMapByProgName(sensorProgs, "tg_tcpsocket_map_stats", []string{
		"tg_event_tcp_connect", "tg_event_tcp_close_and_accept", "tg_event_sys_listen",
		"tg_event_tcp_accept_ret",
	})

	socketTupleMap := SensorMapByProgName(sensorProgs, "tg_socket_tuple_map", []string{
		"tg_event_tcp_connect", "tg_event_tcp_close_and_accept", "tg_event_sys_listen",
		"tg_event_tcp_accept_ret",
	})

	socketTupleMapStats := SensorMapByProgName(sensorProgs, "tg_socket_tuple_map_stats", []string{
		"tg_event_tcp_connect", "tg_event_tcp_close_and_accept", "tg_event_sys_listen",
		"tg_event_tcp_accept_ret",
	})

	socketTupleHintMap := SensorMapByProgName(sensorProgs, "tg_socket_tuple_hint_map", []string{
		"tg_event_tcp_connect", "tg_event_tcp_close_and_accept", "tg_event_sys_listen",
		"tg_event_tcp_accept_ret",
	})

	tcpMonMap := SensorMapByProgName(sensorProgs, "tcpmon_map", []string{
		"tg_event_tcp_connect", "tg_event_tcp_close_and_accept", "tg_event_sys_listen",
	})

	execveMap := SensorMapByProgName(sensorProgs, "execve_map", []string{
		"tg_event_tcp_connect", "tg_event_sys_listen",
	})

	cfgMap := SensorMapByProgName(sensorProgs, "tg_cfg_map", []string{
		"tg_event_tcp_connect", "tg_event_tcp_close_and_accept", "tg_event_sys_listen",
		"tg_event_tcp_accept_ret",
	})

	verMap := SensorMapByProgName(sensorProgs, "tg_ver_map", []string{
		"tg_event_tcp_accept_ret",
	})

	latencyConfigMap := tus.SensorMap{Name: "tg_latency_config_map", Progs: []uint{}}

	sensorMaps := []tus.SensorMap{
		SensorMapByProgName(sensorProgs, "tg_tcp_accept_sock_map", []string{
			"tg_event_tcp_accept", "tg_event_tcp_accept_ret",
		}),
		tcpSocketMapStats,
	}

	if !kernels.MinKernelVersion("5.5.0") { // <=5.4 special snowflake
		sensorProgs = append(sensorProgs, []tus.SensorProg{
			tus.SensorProg{Name: "tg_event_tcp_v4_send_check", Type: ebpf.Kprobe},
			tus.SensorProg{Name: "tg_event_tcp_v6_send_check", Type: ebpf.Kprobe},
		}...)

		execveMap.Progs = append(execveMap.Progs, getMapIndicesByName(sensorProgs, []string{
			"tg_event_tcp_v4_send_check", "tg_event_tcp_v6_send_check",
		})...)
		tcpMonMap.Progs = append(tcpMonMap.Progs, getMapIndicesByName(sensorProgs, []string{
			"tg_event_tcp_v4_send_check", "tg_event_tcp_v6_send_check",
		})...)
		tcpSocketMap.Progs = append(tcpSocketMap.Progs, getMapIndicesByName(sensorProgs, []string{
			"tg_event_tcp_v4_send_check", "tg_event_tcp_v6_send_check",
		})...)
	}

	if !kernels.MinKernelVersion("5.4.0") { // 4.19 - <5.4
		sensorProgs = append(sensorProgs, []tus.SensorProg{
			tus.SensorProg{Name: "tg_inet_lazy_send_kp", Type: ebpf.Kprobe},
			tus.SensorProg{Name: "tg_udp4_send_kprobe", Type: ebpf.Kprobe},
			tus.SensorProg{Name: "tg_udp4_sendret_kprobe", Type: ebpf.Kprobe},
			tus.SensorProg{Name: "tg_udp6_send_kprobe", Type: ebpf.Kprobe},
			tus.SensorProg{Name: "tg_udp6_sendret_kprobe", Type: ebpf.Kprobe},
			tus.SensorProg{Name: "tg_udp_recv_kprobe", Type: ebpf.Kprobe},
			tus.SensorProg{Name: "tg_udp_bind_sock", Type: ebpf.Kprobe},
		}...)

		sensorMaps = append(sensorMaps, []tus.SensorMap{
			SensorMapByProgName(sensorProgs, "tg_udp_retprobe_map", []string{
				"tg_udp4_send_kprobe", "tg_udp4_sendret_kprobe", "tg_udp6_send_kprobe",
				"tg_udp6_sendret_kprobe",
			}),
			SensorMapByProgName(sensorProgs, "tg_udp_retprobe_map_stats", []string{
				"tg_udp4_send_kprobe", "tg_udp4_sendret_kprobe", "tg_udp6_send_kprobe",
				"tg_udp6_sendret_kprobe",
			}),
			SensorMapByProgName(sensorProgs, "tg_udp_map", []string{
				"tg_inet_lazy_send_kp", "tg_udp4_sendret_kprobe", "tg_udp6_sendret_kprobe",
				"tg_udp_recv_kprobe",
			}),
			SensorMapByProgName(sensorProgs, "tg_udp_config_map", []string{
				"tg_inet_lazy_send_kp",
			}),
		}...)

		socketTupleMap.Progs = append(socketTupleMap.Progs, getMapIndicesByName(sensorProgs, []string{
			"tg_udp4_sendret_kprobe", "tg_udp6_sendret_kprobe", "tg_udp_recv_kprobe",
		})...)
		socketTupleMapStats.Progs = append(socketTupleMapStats.Progs, getMapIndicesByName(sensorProgs, []string{
			"tg_udp4_sendret_kprobe", "tg_udp6_sendret_kprobe", "tg_udp_recv_kprobe",
		})...)
		socketTupleHintMap.Progs = append(socketTupleHintMap.Progs, getMapIndicesByName(sensorProgs, []string{
			"tg_udp4_sendret_kprobe", "tg_udp6_sendret_kprobe", "tg_udp_recv_kprobe",
		})...)
		execveMap.Progs = append(execveMap.Progs, getMapIndicesByName(sensorProgs, []string{
			"tg_inet_lazy_send_kp", "tg_udp4_sendret_kprobe", "tg_udp6_sendret_kprobe", "tg_udp_recv_kprobe",
		})...)
		socketMap.Progs = append(socketMap.Progs, getMapIndicesByName(sensorProgs, []string{
			"tg_inet_lazy_send_kp", "tg_udp4_sendret_kprobe", "tg_udp6_sendret_kprobe", "tg_udp_recv_kprobe",
			"tg_udp_bind_sock",
		})...)
		socketMapStats.Progs = append(socketMapStats.Progs, getMapIndicesByName(sensorProgs, []string{
			"tg_udp4_sendret_kprobe", "tg_udp6_sendret_kprobe", "tg_udp_recv_kprobe",
		})...)
		tcpMonMap.Progs = append(tcpMonMap.Progs, getMapIndicesByName(sensorProgs, []string{
			"tg_inet_lazy_send_kp", "tg_udp4_send_kprobe", "tg_udp4_sendret_kprobe", "tg_udp6_send_kprobe",
			"tg_udp6_sendret_kprobe", "tg_udp_recv_kprobe", "tg_udp_bind_sock",
		})...)
		latencyConfigMap.Progs = append(latencyConfigMap.Progs, getMapIndicesByName(sensorProgs, []string{
			"tg_inet_lazy_send_kp",
		})...)
		cfgMap.Progs = append(cfgMap.Progs, getMapIndicesByName(sensorProgs, []string{
			"tg_udp4_sendret_kprobe", "tg_udp6_sendret_kprobe", "tg_udp_recv_kprobe",
		})...)
		verMap.Progs = append(verMap.Progs, getMapIndicesByName(sensorProgs, []string{
			"tg_udp4_sendret_kprobe", "tg_udp6_sendret_kprobe", "tg_udp_recv_kprobe",
		})...)
	} else { // 5.4+
		sensorProgs = append(sensorProgs, []tus.SensorProg{
			tus.SensorProg{Name: "tg_cgroup_egress", Type: ebpf.CGroupSKB},
			tus.SensorProg{Name: "tg_cgroup_ingress", Type: ebpf.CGroupSKB},
			tus.SensorProg{Name: "tg_udp4_send_kprobe", Type: ebpf.Kprobe},
			tus.SensorProg{Name: "tg_udp4_sendret_kprobe", Type: ebpf.Kprobe},
			tus.SensorProg{Name: "tg_udp6_send_kprobe", Type: ebpf.Kprobe},
			tus.SensorProg{Name: "tg_udp6_sendret_kprobe", Type: ebpf.Kprobe},
			tus.SensorProg{Name: "tg_udp_recv_kprobe", Type: ebpf.Kprobe},
			tus.SensorProg{Name: "tg_udp_bind_sock", Type: ebpf.Kprobe},
		}...)

		sensorMaps = append(sensorMaps, []tus.SensorMap{
			SensorMapByProgName(sensorProgs, "tg_udp_retprobe_map", []string{
				"tg_udp4_send_kprobe", "tg_udp4_sendret_kprobe", "tg_udp6_send_kprobe",
				"tg_udp6_sendret_kprobe",
			}),
			SensorMapByProgName(sensorProgs, "tg_udp_retprobe_map_stats", []string{
				"tg_udp4_send_kprobe", "tg_udp4_sendret_kprobe", "tg_udp6_send_kprobe",
				"tg_udp6_sendret_kprobe",
			}),
			SensorMapByProgName(sensorProgs, "tg_udp_map", []string{
				"tg_cgroup_egress", "tg_cgroup_ingress", "tg_udp4_sendret_kprobe", "tg_udp6_sendret_kprobe",
				"tg_udp_recv_kprobe",
			}),
			SensorMapByProgName(sensorProgs, "tg_udp_config_map", []string{
				"tg_cgroup_egress", "tg_cgroup_ingress",
			}),
		}...)

		socketTupleMap.Progs = append(socketTupleMap.Progs, getMapIndicesByName(sensorProgs, []string{
			"tg_cgroup_egress", "tg_cgroup_ingress", "tg_udp4_sendret_kprobe", "tg_udp6_sendret_kprobe",
			"tg_udp_recv_kprobe",
		})...)
		socketTupleMapStats.Progs = append(socketTupleMapStats.Progs, getMapIndicesByName(sensorProgs, []string{
			"tg_cgroup_egress", "tg_cgroup_ingress", "tg_udp4_sendret_kprobe", "tg_udp6_sendret_kprobe",
			"tg_udp_recv_kprobe",
		})...)
		socketTupleHintMap.Progs = append(socketTupleHintMap.Progs, getMapIndicesByName(sensorProgs, []string{
			"tg_cgroup_egress", "tg_cgroup_ingress", "tg_udp4_sendret_kprobe", "tg_udp6_sendret_kprobe",
			"tg_udp_recv_kprobe",
		})...)
		execveMap.Progs = append(execveMap.Progs, getMapIndicesByName(sensorProgs, []string{
			"tg_cgroup_egress", "tg_cgroup_ingress", "tg_udp4_sendret_kprobe", "tg_udp6_sendret_kprobe",
			"tg_udp_recv_kprobe",
		})...)
		socketMap.Progs = append(socketMap.Progs, getMapIndicesByName(sensorProgs, []string{
			"tg_cgroup_egress", "tg_cgroup_ingress", "tg_udp4_sendret_kprobe", "tg_udp6_sendret_kprobe",
			"tg_udp_recv_kprobe", "tg_udp_bind_sock",
		})...)
		socketMapStats.Progs = append(socketMapStats.Progs, getMapIndicesByName(sensorProgs, []string{
			"tg_udp4_sendret_kprobe", "tg_udp6_sendret_kprobe", "tg_udp_recv_kprobe",
		})...)
		tcpSocketMap.Progs = append(tcpSocketMap.Progs, getMapIndicesByName(sensorProgs, []string{
			"tg_cgroup_egress", "tg_cgroup_ingress",
		})...)
		tcpMonMap.Progs = append(tcpMonMap.Progs, getMapIndicesByName(sensorProgs, []string{
			"tg_cgroup_egress", "tg_cgroup_ingress", "tg_udp4_send_kprobe", "tg_udp4_sendret_kprobe",
			"tg_udp6_send_kprobe", "tg_udp6_sendret_kprobe", "tg_udp_recv_kprobe", "tg_udp_bind_sock",
		})...)
		latencyConfigMap.Progs = append(latencyConfigMap.Progs, getMapIndicesByName(sensorProgs, []string{
			"tg_cgroup_egress", "tg_cgroup_ingress",
		})...)
		cfgMap.Progs = append(cfgMap.Progs, getMapIndicesByName(sensorProgs, []string{
			"tg_cgroup_egress", "tg_cgroup_ingress", "tg_udp4_sendret_kprobe", "tg_udp6_sendret_kprobe",
			"tg_udp_recv_kprobe",
		})...)
		verMap.Progs = append(verMap.Progs, getMapIndicesByName(sensorProgs, []string{
			"tg_udp4_sendret_kprobe", "tg_udp6_sendret_kprobe", "tg_udp_recv_kprobe",
		})...)
	}

	if kernels.MinKernelVersion("5.14.0") { // 5.14+
		sensorProgs = append(sensorProgs, []tus.SensorProg{
			tus.SensorProg{Name: "tg_udp_bind_dummy4", Type: ebpf.CGroupSock},
			tus.SensorProg{Name: "tg_udp_bind_dummy6", Type: ebpf.CGroupSock},
		}...)
	}

	if withUdpLatency {
		sensorProgs = append(sensorProgs, tus.SensorProg{Name: "tg_egress_timestamp", Type: ebpf.SchedCLS})
		latencyConfigMap.Progs = append(latencyConfigMap.Progs, getMapIndicesByName(sensorProgs, []string{
			"tg_egress_timestamp",
		})...)
		tcpMonMap.Progs = append(tcpMonMap.Progs, getMapIndicesByName(sensorProgs, []string{
			"tg_egress_timestamp",
		})...)
	}

	if withIcmp && kernels.MinKernelVersion("5.4.0") {
		sensorProgs = append(sensorProgs, []tus.SensorProg{
			tus.SensorProg{Name: "tg_ping_init_sock", Type: ebpf.Kprobe},
			tus.SensorProg{Name: "tg_icmp_rcv", Type: ebpf.Kprobe},
			tus.SensorProg{Name: "tg_icmpv6_rcv", Type: ebpf.Kprobe},
		}...)
		socketMap.Progs = append(socketMap.Progs, getMapIndicesByName(sensorProgs, []string{
			"tg_ping_init_sock", "tg_icmp_rcv", "tg_icmpv6_rcv",
		})...)
		tcpMonMap.Progs = append(tcpMonMap.Progs, getMapIndicesByName(sensorProgs, []string{
			"tg_ping_init_sock", "tg_icmp_rcv", "tg_icmpv6_rcv",
		})...)
		cfgMap.Progs = append(cfgMap.Progs, getMapIndicesByName(sensorProgs, []string{
			"tg_ping_init_sock", "tg_icmp_rcv", "tg_icmpv6_rcv",
		})...)
		socketMapStats.Progs = append(socketMapStats.Progs, getMapIndicesByName(sensorProgs, []string{
			"tg_ping_init_sock",
		})...)
		socketTupleMap.Progs = append(socketTupleMap.Progs, getMapIndicesByName(sensorProgs, []string{
			"tg_icmp_rcv", "tg_icmpv6_rcv",
		})...)
		socketTupleHintMap.Progs = append(socketTupleHintMap.Progs, getMapIndicesByName(sensorProgs, []string{
			"tg_icmp_rcv", "tg_icmpv6_rcv",
		})...)
		execveMap.Progs = append(execveMap.Progs, getMapIndicesByName(sensorProgs, []string{
			"tg_ping_init_sock",
		})...)
		verMap.Progs = append(verMap.Progs, getMapIndicesByName(sensorProgs, []string{
			"tg_ping_init_sock",
		})...)
	}

	if withRaw && kernels.MinKernelVersion("5.4.0") {
		sensorProgs = append(sensorProgs, []tus.SensorProg{
			tus.SensorProg{Name: "tg_rawsock_sk_init", Type: ebpf.Kprobe},
			tus.SensorProg{Name: "tg_rawsockv6_init_sk", Type: ebpf.Kprobe},
		}...)
		socketMap.Progs = append(socketMap.Progs, getMapIndicesByName(sensorProgs, []string{
			"tg_rawsock_sk_init", "tg_rawsockv6_init_sk",
		})...)
		socketMapStats.Progs = append(socketMapStats.Progs, getMapIndicesByName(sensorProgs, []string{
			"tg_rawsock_sk_init", "tg_rawsockv6_init_sk",
		})...)
		tcpMonMap.Progs = append(tcpMonMap.Progs, getMapIndicesByName(sensorProgs, []string{
			"tg_rawsock_sk_init", "tg_rawsockv6_init_sk",
		})...)
		execveMap.Progs = append(execveMap.Progs, getMapIndicesByName(sensorProgs, []string{
			"tg_rawsock_sk_init", "tg_rawsockv6_init_sk",
		})...)
		cfgMap.Progs = append(cfgMap.Progs, getMapIndicesByName(sensorProgs, []string{
			"tg_rawsock_sk_init", "tg_rawsockv6_init_sk",
		})...)
		verMap.Progs = append(verMap.Progs, getMapIndicesByName(sensorProgs, []string{
			"tg_rawsock_sk_init", "tg_rawsockv6_init_sk",
		})...)
	}

	ni := uint(len(sensorProgs))

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

	// merge base sensor extensions specific for EE
	sensorProgs = append(sensorProgs, []tus.SensorProg{
		tus.SensorProg{Name: "execve_send", Type: ebpf.TracePoint},
	}...)

	var confMap tus.SensorMap
	if kernels.MinKernelVersion("5.14.0") {
		if runtime.GOARCH != "amd64" {
			confMap = SensorMapByProgName(sensorProgs, "tg_conf_map", []string{
				"execve_send",
			})
		} else {
			confMap = SensorMapByProgName(sensorProgs, "tg_conf_map", []string{
				"tg_event_tcp_connect", "execve_send",
			})
		}
	} else {
		confMap = SensorMapByProgName(sensorProgs, "tg_conf_map", []string{
			"execve_send",
		})
	}

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
		confMap,
	}...)

	return sensorProgs, sensorMaps
}

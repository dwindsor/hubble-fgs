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

// Define names of programs to provide some consistency checking.
const (
	fentrySkAlloc = "security_sk_alloc"

	cgroupEgressProg  = "tg_cgroup_egress"
	cgroupIngressProg = "tg_cgroup_ingress"

	tcpConnectProg        = "tg_event_tcp_connect"
	tcpCloseAndAcceptProg = "tg_event_tcp_close_and_accept"
	tcpListenProg         = "tg_event_sys_listen"
	tcpAcceptProg         = "tg_event_tcp_accept"
	tcpAcceptRetProg      = "tg_event_tcp_accept_ret"
	tcpSendCheck4Prog     = "tg_event_tcp_v4_send_check"
	tcpSendCheck6Prog     = "tg_event_tcp_v6_send_check"

	udpInetLazySendProg    = "tg_inet_lazy_send_kp"
	udpBindProg            = "tg_udp_bind_sock"
	udpBindDummy4Prog      = "tg_udp_bind_dummy4"
	udpBindDummy6Prog      = "tg_udp_bind_dummy6"
	udpEgressTimestampProg = "tg_egress_timestamp"

	pingInitSockProg = "tg_ping_init_sock"
	icmp4RcvProg     = "tg_icmp_rcv"
	icmp6RcvProg     = "tg_icmpv6_rcv"

	rawsock4SkInitProg = "tg_rawsock_sk_init"
	rawsock6SkInitProg = "tg_rawsockv6_init_sk"

	execveSendProg = "execve_send"
)

func ProgsAndMaps(withUdpLatency bool, withIcmp bool, withRaw bool) ([]tus.SensorProg, []tus.SensorMap) {
	sensorProgs := []tus.SensorProg{
		0: {Name: tcpConnectProg, Type: ebpf.Kprobe},
		1: {Name: tcpCloseAndAcceptProg, Type: ebpf.Kprobe},
		2: {Name: tcpListenProg, Type: ebpf.Kprobe},

		// new accept sensor
		3: {Name: tcpAcceptProg, Type: ebpf.Kprobe},
		4: {Name: tcpAcceptRetProg, Type: ebpf.Kprobe},
	}

	if utils.SupportFentry() {
		sensorProgs = append(sensorProgs, []tus.SensorProg{
			{Name: fentrySkAlloc,
				Type: ebpf.Tracing,
			},
		}...)
	}

	socketMap := SensorMapByProgName(sensorProgs, "tg_socket_map", []string{
		tcpConnectProg, tcpCloseAndAcceptProg, tcpListenProg, tcpAcceptRetProg,
	})

	socketMapStats := SensorMapByProgName(sensorProgs, "tg_socket_map_stats", []string{
		tcpAcceptRetProg,
	})

	tcpSocketMap := SensorMapByProgName(sensorProgs, "tg_tcpsocket_map", []string{
		tcpConnectProg, tcpCloseAndAcceptProg, tcpListenProg,
		tcpAcceptRetProg,
	})

	tcpSocketMapStats := SensorMapByProgName(sensorProgs, "tg_tcpsocket_map_stats", []string{
		tcpConnectProg, tcpCloseAndAcceptProg, tcpListenProg,
		tcpAcceptRetProg,
	})

	socketTupleMap := SensorMapByProgName(sensorProgs, "tg_socket_tuple_map", []string{
		tcpConnectProg, tcpCloseAndAcceptProg, tcpListenProg,
		tcpAcceptRetProg,
	})

	socketTupleMapStats := SensorMapByProgName(sensorProgs, "tg_socket_tuple_map_stats", []string{
		tcpConnectProg, tcpCloseAndAcceptProg, tcpListenProg,
		tcpAcceptRetProg,
	})

	socketTupleHintMap := SensorMapByProgName(sensorProgs, "tg_socket_tuple_hint_map", []string{
		tcpConnectProg, tcpCloseAndAcceptProg, tcpListenProg,
		tcpAcceptRetProg,
	})

	tcpMonMap := SensorMapByProgName(sensorProgs, "tcpmon_map", []string{
		tcpConnectProg, tcpCloseAndAcceptProg, tcpListenProg, tcpAcceptRetProg,
	})

	execveMap := SensorMapByProgName(sensorProgs, "execve_map", []string{
		tcpConnectProg, tcpListenProg,
	})

	cfgMap := SensorMapByProgName(sensorProgs, "tg_cfg_map", []string{
		tcpConnectProg, tcpCloseAndAcceptProg, tcpListenProg,
		tcpAcceptRetProg,
	})

	verMap := SensorMapByProgName(sensorProgs, "tg_ver_map", []string{
		tcpAcceptRetProg,
	})

	latencyConfigMap := tus.SensorMap{Name: "tg_latency_config_map", Progs: []uint{}}

	sensorMaps := []tus.SensorMap{
		SensorMapByProgName(sensorProgs, "tg_tcp_accept_sock_map", []string{
			tcpAcceptProg, tcpAcceptRetProg,
		}),
		tcpSocketMapStats,
	}

	if !kernels.MinKernelVersion("5.5.0") { // <=5.4 special snowflake
		sensorProgs = append(sensorProgs, []tus.SensorProg{
			{Name: tcpSendCheck4Prog, Type: ebpf.Kprobe},
			{Name: tcpSendCheck6Prog, Type: ebpf.Kprobe},
		}...)

		socketMap.Progs = append(socketMap.Progs, getMapIndicesByName(sensorProgs, []string{
			"tg_event_tcp_v4_send_check", "tg_event_tcp_v6_send_check",
		})...)
		execveMap.Progs = append(execveMap.Progs, getMapIndicesByName(sensorProgs, []string{
			tcpSendCheck4Prog, tcpSendCheck6Prog,
		})...)
		tcpMonMap.Progs = append(tcpMonMap.Progs, getMapIndicesByName(sensorProgs, []string{
			tcpSendCheck4Prog, tcpSendCheck6Prog,
		})...)
		tcpSocketMap.Progs = append(tcpSocketMap.Progs, getMapIndicesByName(sensorProgs, []string{
			tcpSendCheck4Prog, tcpSendCheck6Prog,
		})...)
	}

	if !kernels.MinKernelVersion("5.4.0") { // 4.19 - <5.4
		sensorProgs = append(sensorProgs, []tus.SensorProg{
			{Name: udpInetLazySendProg, Type: ebpf.Kprobe},
			{Name: udpBindProg, Type: ebpf.Kprobe},
		}...)

		sensorMaps = append(sensorMaps, []tus.SensorMap{
			SensorMapByProgName(sensorProgs, "tg_udp_map", []string{
				udpInetLazySendProg,
			}),
			SensorMapByProgName(sensorProgs, "tg_udp_config_map", []string{
				udpInetLazySendProg,
			}),
		}...)

		execveMap.Progs = append(execveMap.Progs, getMapIndicesByName(sensorProgs, []string{
			udpInetLazySendProg,
		})...)
		socketMap.Progs = append(socketMap.Progs, getMapIndicesByName(sensorProgs, []string{
			udpInetLazySendProg, udpBindProg,
		})...)
		tcpMonMap.Progs = append(tcpMonMap.Progs, getMapIndicesByName(sensorProgs, []string{
			udpInetLazySendProg, udpBindProg,
		})...)
		latencyConfigMap.Progs = append(latencyConfigMap.Progs, getMapIndicesByName(sensorProgs, []string{
			udpInetLazySendProg,
		})...)
	} else { // 5.4+
		sensorProgs = append(sensorProgs, []tus.SensorProg{
			{Name: cgroupEgressProg, Type: ebpf.CGroupSKB},
			{Name: cgroupIngressProg, Type: ebpf.CGroupSKB},
			{Name: udpBindProg, Type: ebpf.Kprobe},
		}...)

		sensorMaps = append(sensorMaps, []tus.SensorMap{
			SensorMapByProgName(sensorProgs, "tg_udp_map", []string{
				cgroupEgressProg, cgroupIngressProg,
			}),
			SensorMapByProgName(sensorProgs, "tg_udp_config_map", []string{
				cgroupEgressProg, cgroupIngressProg,
			}),
		}...)

		socketTupleMap.Progs = append(socketTupleMap.Progs, getMapIndicesByName(sensorProgs, []string{
			cgroupEgressProg, cgroupIngressProg,
		})...)
		socketTupleMapStats.Progs = append(socketTupleMapStats.Progs, getMapIndicesByName(sensorProgs, []string{
			cgroupEgressProg, cgroupIngressProg,
		})...)
		socketTupleHintMap.Progs = append(socketTupleHintMap.Progs, getMapIndicesByName(sensorProgs, []string{
			cgroupEgressProg, cgroupIngressProg,
		})...)
		execveMap.Progs = append(execveMap.Progs, getMapIndicesByName(sensorProgs, []string{
			cgroupEgressProg, cgroupIngressProg,
		})...)
		socketMap.Progs = append(socketMap.Progs, getMapIndicesByName(sensorProgs, []string{
			cgroupEgressProg, cgroupIngressProg, udpBindProg,
		})...)
		tcpSocketMap.Progs = append(tcpSocketMap.Progs, getMapIndicesByName(sensorProgs, []string{
			cgroupEgressProg, cgroupIngressProg,
		})...)
		tcpMonMap.Progs = append(tcpMonMap.Progs, getMapIndicesByName(sensorProgs, []string{
			cgroupEgressProg, cgroupIngressProg, udpBindProg,
		})...)
		latencyConfigMap.Progs = append(latencyConfigMap.Progs, getMapIndicesByName(sensorProgs, []string{
			cgroupEgressProg, cgroupIngressProg,
		})...)
		cfgMap.Progs = append(cfgMap.Progs, getMapIndicesByName(sensorProgs, []string{
			cgroupEgressProg, cgroupIngressProg,
		})...)
	}

	if kernels.MinKernelVersion("5.14.0") { // 5.14+
		sensorProgs = append(sensorProgs, []tus.SensorProg{
			{Name: udpBindDummy4Prog, Type: ebpf.CGroupSock},
			{Name: udpBindDummy6Prog, Type: ebpf.CGroupSock},
		}...)
	}

	if withUdpLatency {
		sensorProgs = append(sensorProgs, tus.SensorProg{Name: udpEgressTimestampProg, Type: ebpf.SchedCLS})
		latencyConfigMap.Progs = append(latencyConfigMap.Progs, getMapIndicesByName(sensorProgs, []string{
			udpEgressTimestampProg,
		})...)
		tcpMonMap.Progs = append(tcpMonMap.Progs, getMapIndicesByName(sensorProgs, []string{
			udpEgressTimestampProg,
		})...)
	}

	if withIcmp && kernels.MinKernelVersion("5.4.0") {
		sensorProgs = append(sensorProgs, []tus.SensorProg{
			{Name: pingInitSockProg, Type: ebpf.Kprobe},
			{Name: icmp4RcvProg, Type: ebpf.Kprobe},
			{Name: icmp6RcvProg, Type: ebpf.Kprobe},
		}...)
		socketMap.Progs = append(socketMap.Progs, getMapIndicesByName(sensorProgs, []string{
			pingInitSockProg, icmp4RcvProg, icmp6RcvProg,
		})...)
		tcpMonMap.Progs = append(tcpMonMap.Progs, getMapIndicesByName(sensorProgs, []string{
			pingInitSockProg, icmp4RcvProg, icmp6RcvProg,
		})...)
		cfgMap.Progs = append(cfgMap.Progs, getMapIndicesByName(sensorProgs, []string{
			pingInitSockProg, icmp4RcvProg, icmp6RcvProg,
		})...)
		socketMapStats.Progs = append(socketMapStats.Progs, getMapIndicesByName(sensorProgs, []string{
			pingInitSockProg,
		})...)
		socketTupleMap.Progs = append(socketTupleMap.Progs, getMapIndicesByName(sensorProgs, []string{
			icmp4RcvProg, icmp6RcvProg,
		})...)
		socketTupleHintMap.Progs = append(socketTupleHintMap.Progs, getMapIndicesByName(sensorProgs, []string{
			icmp4RcvProg, icmp6RcvProg,
		})...)
		execveMap.Progs = append(execveMap.Progs, getMapIndicesByName(sensorProgs, []string{
			pingInitSockProg,
		})...)
		verMap.Progs = append(verMap.Progs, getMapIndicesByName(sensorProgs, []string{
			pingInitSockProg,
		})...)
	}

	if withRaw && kernels.MinKernelVersion("5.4.0") {
		sensorProgs = append(sensorProgs, []tus.SensorProg{
			{Name: rawsock4SkInitProg, Type: ebpf.Kprobe},
			{Name: rawsock6SkInitProg, Type: ebpf.Kprobe},
		}...)
		socketMap.Progs = append(socketMap.Progs, getMapIndicesByName(sensorProgs, []string{
			rawsock4SkInitProg, rawsock6SkInitProg,
		})...)
		socketMapStats.Progs = append(socketMapStats.Progs, getMapIndicesByName(sensorProgs, []string{
			rawsock4SkInitProg, rawsock6SkInitProg,
		})...)
		tcpMonMap.Progs = append(tcpMonMap.Progs, getMapIndicesByName(sensorProgs, []string{
			rawsock4SkInitProg, rawsock6SkInitProg,
		})...)
		execveMap.Progs = append(execveMap.Progs, getMapIndicesByName(sensorProgs, []string{
			rawsock4SkInitProg, rawsock6SkInitProg,
		})...)
		cfgMap.Progs = append(cfgMap.Progs, getMapIndicesByName(sensorProgs, []string{
			rawsock4SkInitProg, rawsock6SkInitProg,
		})...)
		verMap.Progs = append(verMap.Progs, getMapIndicesByName(sensorProgs, []string{
			rawsock4SkInitProg, rawsock6SkInitProg,
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
		{Name: execveSendProg, Type: ebpf.TracePoint},
	}...)

	confMap := SensorMapByProgName(sensorProgs, "tg_conf_map", []string{})
	if kernels.MinKernelVersion("5.14.0") {
		if runtime.GOARCH != "amd64" {
			confMap.Progs = append(confMap.Progs, getMapIndicesByName(sensorProgs, []string{
				execveSendProg,
			})...)
		} else {
			confMap.Progs = append(confMap.Progs, getMapIndicesByName(sensorProgs, []string{
				tcpConnectProg, execveSendProg,
			})...)
		}
	} else {
		confMap.Progs = append(confMap.Progs, getMapIndicesByName(sensorProgs, []string{
			execveSendProg,
		})...)
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

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
	fentrySkAlloc    = "security_sk_alloc"
	fentrySkFreeProg = "security_sk_free"

	securitySkAllocProg = "tg_security_sk_alloc"
	securitySkFreeProg  = "tg_security_sk_free"

	cgroupEgressProg  = "tg_cgroup_egress"
	cgroupIngressProg = "tg_cgroup_ingress"

	tcpConnectProg    = "tg_event_tcp_connect"
	tcpSockopsProg    = "tg_event_tcp_sockops"
	tcpSecurityAccept = "tg_security_socket_accept"
	tcpSecurityGraft  = "tg_security_sock_graft"
	tcpCloseProg      = "tg_event_tcp_close"
	tcpListenProg     = "tg_event_sys_listen"
	tcpSendCheck4Prog = "tg_event_tcp_v4_send_check"
	tcpSendCheck6Prog = "tg_event_tcp_v6_send_check"

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
)

func sockopsSensorMaps(withUdpLatency bool, withIcmp bool, withRaw bool, sensorProgs []tus.SensorProg, ni uint) []tus.SensorMap {
	var sensorMaps []tus.SensorMap

	socketMap := SensorMapByProgName(sensorProgs, "tg_socket_map", []string{tcpSockopsProg, tcpSecurityGraft})
	socketMapStats := SensorMapByProgName(sensorProgs, "tg_socket_map_stats", []string{tcpSecurityGraft})
	tcpSocketMap := SensorMapByProgName(sensorProgs, "tg_tcpsocket_map", []string{tcpSockopsProg, fentrySkFreeProg, tcpSecurityGraft})
	socketTupleMap := SensorMapByProgName(sensorProgs, "tg_socket_tuple_map", []string{tcpSockopsProg, tcpSecurityGraft})
	socketTupleMapStats := SensorMapByProgName(sensorProgs, "tg_socket_tuple_map_stats", []string{tcpSockopsProg, tcpSecurityGraft})
	socketTupleRevMap := SensorMapByProgName(sensorProgs, "tg_rev_tuple_map", []string{tcpSockopsProg, tcpSecurityGraft})
	socketTupleHintMap := SensorMapByProgName(sensorProgs, "tg_socket_tuple_hint_map", []string{tcpSockopsProg, tcpSecurityGraft})
	tcpMonMap := SensorMapByProgName(sensorProgs, "tcpmon_map", []string{tcpSockopsProg, tcpSecurityGraft})
	execveMap := SensorMapByProgName(sensorProgs, "execve_map", []string{tcpSockopsProg, tcpSecurityGraft})
	cfgMap := SensorMapByProgName(sensorProgs, "tg_cfg_map", []string{tcpSockopsProg, tcpSecurityGraft})
	verMap := SensorMapByProgName(sensorProgs, "tg_ver_map", []string{tcpSecurityGraft})
	acceptMap := SensorMapByProgName(sensorProgs, "tg_tcp_accept_socket_to_sk_map", []string{tcpSecurityAccept, tcpSecurityGraft})

	latencyConfigMap := tus.SensorMap{Name: "tg_latency_config_map", Progs: []uint{}}
	if withUdpLatency {
		latencyConfigMap.Progs = append(latencyConfigMap.Progs, getMapIndicesByName(sensorProgs, []string{
			udpEgressTimestampProg,
		})...)
		tcpMonMap.Progs = append(tcpMonMap.Progs, getMapIndicesByName(sensorProgs, []string{
			udpEgressTimestampProg,
		})...)
	}

	sensorMaps = append(sensorMaps, []tus.SensorMap{
		SensorMapByProgName(sensorProgs, "tg_udp_map", []string{
			cgroupEgressProg, cgroupIngressProg,
		}),
		SensorMapByProgName(sensorProgs, "tg_udp_map_count", []string{
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
	socketTupleRevMap.Progs = append(socketTupleRevMap.Progs, getMapIndicesByName(sensorProgs, []string{
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

	if withIcmp {
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

	if withRaw {
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

	_, sockMaps := socktrack.ProgsAndMaps()

	socketMap.Progs = MergeIntoMap(socketMap.Progs, GetMapProgs(sockMaps, socketMap.Name), ni)
	socketMapStats.Progs = MergeIntoMap(socketMapStats.Progs, GetMapProgs(sockMaps, socketMapStats.Name), ni)
	socketTupleMap.Progs = MergeIntoMap(socketTupleMap.Progs, GetMapProgs(sockMaps, socketTupleMap.Name), ni)
	socketTupleMapStats.Progs = MergeIntoMap(socketTupleMapStats.Progs, GetMapProgs(sockMaps, socketTupleMapStats.Name), ni)
	socketTupleRevMap.Progs = MergeIntoMap(socketTupleRevMap.Progs, GetMapProgs(sockMaps, socketTupleRevMap.Name), ni)
	socketTupleHintMap.Progs = MergeIntoMap(socketTupleHintMap.Progs, GetMapProgs(sockMaps, socketTupleHintMap.Name), ni)
	execveMap.Progs = MergeIntoMap(execveMap.Progs, GetMapProgs(sockMaps, execveMap.Name), ni)
	tcpMonMap.Progs = MergeIntoMap(tcpMonMap.Progs, GetMapProgs(sockMaps, tcpMonMap.Name), ni)
	cfgMap.Progs = MergeIntoMap(cfgMap.Progs, GetMapProgs(sockMaps, cfgMap.Name), ni)
	verMap.Progs = MergeIntoMap(verMap.Progs, GetMapProgs(sockMaps, verMap.Name), ni)

	confMap := SensorMapByProgName(sensorProgs, "tg_conf_map", []string{})
	confMap.Progs = append(confMap.Progs, getMapIndicesByName(sensorProgs, []string{
		tcpSockopsProg,
	})...)

	sensorMaps = append(sensorMaps, []tus.SensorMap{
		socketMap,
		socketMapStats,
		socketTupleMap,
		socketTupleMapStats,
		socketTupleRevMap,
		socketTupleHintMap,
		tcpSocketMap,
		execveMap,
		tcpMonMap,
		latencyConfigMap,
		cfgMap,
		verMap,
		confMap,
		acceptMap,
	}...)

	return sensorMaps
}

func kprobeOrFentrySensorMaps(withUdpLatency bool, withIcmp bool, withRaw bool, sensorProgs []tus.SensorProg, ni uint) []tus.SensorMap {
	var sensorMaps []tus.SensorMap
	var skFreeProg string

	if utils.SupportFentry() {
		skFreeProg = fentrySkFreeProg
	} else {
		skFreeProg = securitySkFreeProg
	}

	socketMap := SensorMapByProgName(sensorProgs, "tg_socket_map", []string{
		tcpConnectProg, tcpCloseProg, tcpListenProg, tcpSecurityGraft,
	})

	socketMapStats := SensorMapByProgName(sensorProgs, "tg_socket_map_stats", []string{
		tcpSecurityGraft,
	})

	tcpSocketMap := SensorMapByProgName(sensorProgs, "tg_tcpsocket_map", []string{
		tcpConnectProg, tcpCloseProg, tcpListenProg, tcpSecurityGraft,
		skFreeProg,
	})

	tcpSocketMapStats := SensorMapByProgName(sensorProgs, "tg_tcpsocket_map_stats", []string{
		tcpConnectProg, tcpListenProg, tcpSecurityGraft,
		skFreeProg,
	})

	socketTupleMap := SensorMapByProgName(sensorProgs, "tg_socket_tuple_map", []string{
		tcpConnectProg, tcpListenProg, tcpSecurityGraft,
	})

	socketTupleMapStats := SensorMapByProgName(sensorProgs, "tg_socket_tuple_map_stats", []string{
		tcpConnectProg, tcpListenProg, tcpSecurityGraft,
	})

	socketTupleRevMap := SensorMapByProgName(sensorProgs, "tg_rev_tuple_map", []string{
		tcpConnectProg, tcpListenProg, tcpSecurityGraft,
	})

	socketTupleHintMap := SensorMapByProgName(sensorProgs, "tg_socket_tuple_hint_map", []string{
		tcpConnectProg, tcpListenProg, tcpSecurityGraft,
	})

	tcpMonMap := SensorMapByProgName(sensorProgs, "tcpmon_map", []string{
		tcpConnectProg, tcpCloseProg, tcpListenProg, tcpSecurityGraft,
	})

	execveMap := SensorMapByProgName(sensorProgs, "execve_map", []string{
		tcpConnectProg, tcpListenProg, tcpSecurityGraft,
	})

	cfgMap := SensorMapByProgName(sensorProgs, "tg_cfg_map", []string{
		tcpConnectProg, tcpListenProg, tcpSecurityGraft,
	})

	verMap := SensorMapByProgName(sensorProgs, "tg_ver_map", []string{
		tcpSecurityGraft,
	})

	acceptMap := SensorMapByProgName(sensorProgs, "tg_tcp_accept_socket_to_sk_map", []string{
		tcpSecurityAccept, tcpSecurityGraft,
	})

	if !kernels.MinKernelVersion("5.5.0") { // <=5.4 special snowflake
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

	latencyConfigMap := tus.SensorMap{Name: "tg_latency_config_map", Progs: []uint{}}
	if withUdpLatency {
		latencyConfigMap.Progs = append(latencyConfigMap.Progs, getMapIndicesByName(sensorProgs, []string{
			udpEgressTimestampProg,
		})...)
		tcpMonMap.Progs = append(tcpMonMap.Progs, getMapIndicesByName(sensorProgs, []string{
			udpEgressTimestampProg,
		})...)
	}

	if !kernels.MinKernelVersion("5.4.0") { // 4.19 - <5.4
		sensorMaps = append(sensorMaps, []tus.SensorMap{
			SensorMapByProgName(sensorProgs, "tg_udp_map", []string{
				udpInetLazySendProg,
			}),
			SensorMapByProgName(sensorProgs, "tg_udp_map_count", []string{
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
		sensorMaps = append(sensorMaps, []tus.SensorMap{
			SensorMapByProgName(sensorProgs, "tg_udp_map", []string{
				cgroupEgressProg, cgroupIngressProg,
			}),
			SensorMapByProgName(sensorProgs, "tg_udp_map_count", []string{
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
		socketTupleRevMap.Progs = append(socketTupleRevMap.Progs, getMapIndicesByName(sensorProgs, []string{
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

	if withIcmp && kernels.MinKernelVersion("5.4.0") {
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

	_, sockMaps := socktrack.ProgsAndMaps()

	socketMap.Progs = MergeIntoMap(socketMap.Progs, GetMapProgs(sockMaps, socketMap.Name), ni)
	socketMapStats.Progs = MergeIntoMap(socketMapStats.Progs, GetMapProgs(sockMaps, socketMapStats.Name), ni)
	socketTupleMap.Progs = MergeIntoMap(socketTupleMap.Progs, GetMapProgs(sockMaps, socketTupleMap.Name), ni)
	socketTupleMapStats.Progs = MergeIntoMap(socketTupleMapStats.Progs, GetMapProgs(sockMaps, socketTupleMapStats.Name), ni)
	socketTupleRevMap.Progs = MergeIntoMap(socketTupleRevMap.Progs, GetMapProgs(sockMaps, socketTupleRevMap.Name), ni)
	socketTupleHintMap.Progs = MergeIntoMap(socketTupleHintMap.Progs, GetMapProgs(sockMaps, socketTupleHintMap.Name), ni)
	execveMap.Progs = MergeIntoMap(execveMap.Progs, GetMapProgs(sockMaps, execveMap.Name), ni)
	tcpMonMap.Progs = MergeIntoMap(tcpMonMap.Progs, GetMapProgs(sockMaps, tcpMonMap.Name), ni)
	cfgMap.Progs = MergeIntoMap(cfgMap.Progs, GetMapProgs(sockMaps, cfgMap.Name), ni)
	verMap.Progs = MergeIntoMap(verMap.Progs, GetMapProgs(sockMaps, verMap.Name), ni)

	confMap := SensorMapByProgName(sensorProgs, "tg_conf_map", []string{})
	if kernels.MinKernelVersion("5.14.0") {
		if runtime.GOARCH == "amd64" {
			confMap.Progs = append(confMap.Progs, getMapIndicesByName(sensorProgs, []string{
				tcpSockopsProg, tcpSecurityAccept, tcpSecurityGraft,
			})...)
		}
	}

	sensorMaps = append(sensorMaps, []tus.SensorMap{
		socketMap,
		socketMapStats,
		socketTupleMap,
		socketTupleMapStats,
		socketTupleRevMap,
		socketTupleHintMap,
		acceptMap,
		tcpSocketMap,
		tcpSocketMapStats,
		execveMap,
		tcpMonMap,
		latencyConfigMap,
		cfgMap,
		verMap,
		confMap,
	}...)

	return sensorMaps
}

func sockopsSensorProgs(withUdpLatency bool, withIcmp bool, withRaw bool) ([]tus.SensorProg, uint) {
	sensorProgs := []tus.SensorProg{
		{Name: tcpSockopsProg, Type: ebpf.SockOps},
		{Name: tcpSecurityAccept, Type: ebpf.Tracing},
		{Name: tcpSecurityGraft, Type: ebpf.Tracing},
		{Name: cgroupEgressProg, Type: ebpf.CGroupSKB},
		{Name: cgroupIngressProg, Type: ebpf.CGroupSKB},
		{Name: udpBindDummy4Prog, Type: ebpf.CGroupSock},
		{Name: udpBindDummy6Prog, Type: ebpf.CGroupSock},
		{Name: fentrySkAlloc, Type: ebpf.Tracing},
		{Name: fentrySkFreeProg, Type: ebpf.Tracing},
	}

	if utils.SupportFentry() {
		sensorProgs = append(sensorProgs, tus.SensorProg{Name: udpBindProg, Type: ebpf.Tracing})
	} else {
		sensorProgs = append(sensorProgs, tus.SensorProg{Name: udpBindProg, Type: ebpf.Kprobe})
	}

	if withUdpLatency {
		sensorProgs = append(sensorProgs, tus.SensorProg{Name: udpEgressTimestampProg, Type: ebpf.SchedCLS})
	}

	if withIcmp {
		sensorProgs = append(sensorProgs, []tus.SensorProg{
			{Name: pingInitSockProg, Type: ebpf.Kprobe},
			{Name: icmp4RcvProg, Type: ebpf.Kprobe},
			{Name: icmp6RcvProg, Type: ebpf.Kprobe},
		}...)
	}

	if withRaw {
		sensorProgs = append(sensorProgs, []tus.SensorProg{
			{Name: rawsock4SkInitProg, Type: ebpf.Kprobe},
			{Name: rawsock6SkInitProg, Type: ebpf.Kprobe},
		}...)
	}

	sockProgs, _ := socktrack.ProgsAndMaps()
	sockProgsOffset := uint(len(sensorProgs))
	sensorProgs = append(sensorProgs, sockProgs...)
	return sensorProgs, sockProgsOffset
}

func kprobeOrFentrySensorProgs(withUdpLatency bool, withIcmp bool, withRaw bool) ([]tus.SensorProg, uint) {
	var sensorProgs []tus.SensorProg

	if utils.SupportFentry() {
		sensorProgs = append(sensorProgs,
			tus.SensorProg{Name: tcpConnectProg, Type: ebpf.Tracing},
			tus.SensorProg{Name: tcpCloseProg, Type: ebpf.Tracing},
			tus.SensorProg{Name: tcpListenProg, Type: ebpf.Tracing},
			tus.SensorProg{Name: tcpSecurityAccept, Type: ebpf.Tracing},
			tus.SensorProg{Name: tcpSecurityGraft, Type: ebpf.Tracing},
		)
	} else {
		sensorProgs = append(sensorProgs,
			tus.SensorProg{Name: tcpConnectProg, Type: ebpf.Kprobe},
			tus.SensorProg{Name: tcpCloseProg, Type: ebpf.Kprobe},
			tus.SensorProg{Name: tcpListenProg, Type: ebpf.Kprobe},
			tus.SensorProg{Name: tcpSecurityAccept, Type: ebpf.Kprobe},
			tus.SensorProg{Name: tcpSecurityGraft, Type: ebpf.Kprobe},
		)
	}

	if !kernels.MinKernelVersion("5.5.0") { // <=5.4 special snowflake
		sensorProgs = append(sensorProgs, []tus.SensorProg{
			{Name: tcpSendCheck4Prog, Type: ebpf.Kprobe},
			{Name: tcpSendCheck6Prog, Type: ebpf.Kprobe},
		}...)
	}

	if !kernels.MinKernelVersion("5.4.0") { // 4.19 - <5.4
		sensorProgs = append(sensorProgs, []tus.SensorProg{
			{Name: udpInetLazySendProg, Type: ebpf.Kprobe},
			{Name: udpBindProg, Type: ebpf.Kprobe},
		}...)
	} else { // 5.4+
		sensorProgs = append(sensorProgs, []tus.SensorProg{
			{Name: cgroupEgressProg, Type: ebpf.CGroupSKB},
			{Name: cgroupIngressProg, Type: ebpf.CGroupSKB},
		}...)
		if utils.SupportFentry() {
			sensorProgs = append(sensorProgs, tus.SensorProg{Name: udpBindProg, Type: ebpf.Tracing})
		} else {
			sensorProgs = append(sensorProgs, tus.SensorProg{Name: udpBindProg, Type: ebpf.Kprobe})
		}
	}

	if kernels.MinKernelVersion("5.14.0") { // 5.14+
		sensorProgs = append(sensorProgs, []tus.SensorProg{
			{Name: udpBindDummy4Prog, Type: ebpf.CGroupSock},
			{Name: udpBindDummy6Prog, Type: ebpf.CGroupSock},
		}...)
	}

	if withUdpLatency {
		sensorProgs = append(sensorProgs, tus.SensorProg{Name: udpEgressTimestampProg, Type: ebpf.SchedCLS})
	}

	if withIcmp && kernels.MinKernelVersion("5.4.0") {
		sensorProgs = append(sensorProgs, []tus.SensorProg{
			{Name: pingInitSockProg, Type: ebpf.Kprobe},
			{Name: icmp4RcvProg, Type: ebpf.Kprobe},
			{Name: icmp6RcvProg, Type: ebpf.Kprobe},
		}...)
	}

	if withRaw && kernels.MinKernelVersion("5.4.0") {
		sensorProgs = append(sensorProgs, []tus.SensorProg{
			{Name: rawsock4SkInitProg, Type: ebpf.Kprobe},
			{Name: rawsock6SkInitProg, Type: ebpf.Kprobe},
		}...)
	}

	if utils.SupportFentry() {
		sensorProgs = append(sensorProgs, []tus.SensorProg{
			{Name: fentrySkAlloc,
				Type: ebpf.Tracing,
			},
			{Name: fentrySkFreeProg,
				Type: ebpf.Tracing,
			},
		}...)
	} else {
		sensorProgs = append(sensorProgs, []tus.SensorProg{
			{Name: securitySkAllocProg,
				Type: ebpf.Kprobe,
			},
			{Name: securitySkFreeProg,
				Type: ebpf.Kprobe,
			},
		}...)
	}
	sockProgs, _ := socktrack.ProgsAndMaps()
	sockProgsOffset := uint(len(sensorProgs))
	sensorProgs = append(sensorProgs, sockProgs...)
	return sensorProgs, sockProgsOffset
}

func ProgsAndMaps(withUdpLatency bool, withIcmp bool, withRaw bool) ([]tus.SensorProg, []tus.SensorMap) {
	var sensorProgs []tus.SensorProg
	var sensorMaps []tus.SensorMap
	var ni uint

	if kernels.MinKernelVersion("5.14.0") {
		if runtime.GOARCH != "amd64" {
			sensorProgs, ni = kprobeOrFentrySensorProgs(withUdpLatency, withIcmp, withRaw)
			sensorMaps = kprobeOrFentrySensorMaps(withUdpLatency, withIcmp, withRaw, sensorProgs, ni)
		} else {
			sensorProgs, ni = sockopsSensorProgs(withUdpLatency, withIcmp, withRaw)
			sensorMaps = sockopsSensorMaps(withUdpLatency, withIcmp, withRaw, sensorProgs, ni)
		}
	} else {
		sensorProgs, ni = kprobeOrFentrySensorProgs(withUdpLatency, withIcmp, withRaw)
		sensorMaps = kprobeOrFentrySensorMaps(withUdpLatency, withIcmp, withRaw, sensorProgs, ni)
	}

	return sensorProgs, sensorMaps
}

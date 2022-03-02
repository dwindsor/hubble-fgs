//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package sensors

var (
	Execve = Program{
		"bpf_execve_event.o",
		"sched/sched_process_exec",
		"sched/sched_process_exec",
		"tracepoint/sys_execve",
		"event_execve",

		false,
		true,
		"tracepoint",
		Idle(),

		-1,

		struct{}{},
	}

	ExecveV53 = Program{
		"bpf_execve_event_v53.o",
		"sched/sched_process_exec",
		"sched/sched_process_exec",
		"tracepoint/sys_execve",
		"event_execve",

		false,
		true,
		"tracepoint",
		Idle(),

		-1,

		struct{}{},
	}

	Exit = Program{
		"bpf_exit.o",
		"sched/sched_process_exit",
		"sched/sched_process_exit",
		"tracepoint/sys_exit",
		"event_exit",

		false,
		true,
		"tracepoint",
		Idle(),

		-1,

		struct{}{},
	}

	Fork = Program{
		"bpf_fork.o",
		"wake_up_new_task",
		"wake_up_new_task",
		"kprobe/wake_up_new_task",
		"kprobe_pid_clear",

		false,
		true,
		"kprobe",
		Idle(),

		-1,

		struct{}{},
	}

	Cred = Program{
		"bpf_cred.o",
		"commit_creds",
		"commit_creds",
		"kprobe/commit_creds",
		"kprobe_commit_creds",

		false,
		true,
		"kprobe",
		Idle(),

		-1,

		struct{}{},
	}

	TCPConnect = Program{
		"bpf_tcpmon.o",
		"tcp_connect",
		"tcp_connect",
		"kprobe/tcp_connect",
		"kprobe_tcp_connect",

		false,
		true,
		"kprobe",
		Idle(),

		-1,

		struct{}{},
	}

	TCPConnectRet = Program{
		"bpf_tcpmonret.o",
		"__x64_sys_connect",
		"sys_connect",
		"kretprobe/sys_connect",
		"kretprobe_sys_connect",

		true,
		true,
		"kprobe",
		Idle(),

		-1,

		struct{}{},
	}

	TCPClose = Program{
		"bpf_tcpclose.o",
		"tcp_set_state",
		"tcp_set_state",
		"kprobe/tcp_set_state",
		"kprobe_tcp_set_state",

		false,
		true,
		"kprobe",
		Idle(),

		-1,

		struct{}{},
	}

	Listen = Program{
		"bpf_listen.o",
		"__inet_hash",
		"__inet_hash",
		"kprobe/inet_hash",
		"kprobe_inet_hash",

		false,
		true,
		"kprobe",
		Idle(),

		-1,

		struct{}{},
	}

	/* Event Ring map */
	TCPMonMap    = MapBuilder("tcpmon_map", "", &Execve)
	TCPMonMapV53 = MapBuilder("tcpmon_map", "", &ExecveV53)

	/* Networking and Process Monitoring maps */
	ExecveMap              = MapBuilder("execve_map", "", &Execve)
	ExecveMapV53           = MapBuilder("execve_map", "", &ExecveV53)
	SocketMap              = MapBuilder("socket_map", "", &TCPConnect)
	ProcessNetworkBurstMap = MapBuilder("pn_burst_map", "", &Exit)

	/* Policy maps populated from base programs */
	NamesMap    = MapBuilder("names_map", "", &Execve)
	NamesMapV53 = MapBuilder("names_map", "", &ExecveV53)

	/* Internal statistics for debugging */
	ExecveStats     = MapBuilder("execve_map_stats", "", &Execve)
	ExecveStatsV53  = MapBuilder("execve_map_stats", "", &ExecveV53)
	SocketStats     = MapBuilder("socket_map_stats", "", &TCPConnect)
	TLSMapStats     = MapBuilder("tls_map_stats", "", &TCPConnect)
	PNBurstMapStats = MapBuilder("pn_burst_map_stats", "", &Exit)

	/* Cilium maps */
	CiliumSNAT = MapBuilder("cilium_snat_v4_external", "", &TCPConnect)

	/* Parser maps */
	HTTPContext = MapBuilder("http_map", "", &TCPClose)
)

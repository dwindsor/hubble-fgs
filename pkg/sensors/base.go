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

	TCPSendCheck = Program{
		"bpf_tcp_send_check.o",
		"tcp_v4_send_check",
		"tcp_v4_send_check",
		"kprobe/tcp_v4_send_check",
		"kprobe_tcp_v4_send_check",

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
	TCPMonMap = Map{"tcpmon_map", "", &Execve, Idle(), -1}

	/* Networking and Process Monitoring maps */
	ExecveMap           = Map{"execve_map", "", &Execve, Idle(), -1}
	SocketMap           = Map{"socket_map", "", &TCPConnect, Idle(), -1}
	TCPSendCheckSampler = Map{"tcp_send_check_sampler", "", &TCPSendCheck, Idle(), -1}

	/* Policy maps populated from base programs */
	NamesMap = Map{"names_map", "", &Execve, Idle(), -1}

	/* Internal statistics for debugging */
	ExecveStats = Map{"execve_map_stats", "", &Execve, Idle(), -1}
	SocketStats = Map{"socket_map_stats", "", &TCPConnect, Idle(), -1}
	TLSMapStats = Map{"tls_map_stats", "", &TCPConnect, Idle(), -1}

	/* Cilium maps */
	CiliumSNAT = Map{"cilium_snat_v4_external", "", &TCPConnect, Idle(), -1}
)

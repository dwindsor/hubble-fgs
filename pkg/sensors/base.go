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

import "github.com/isovalent/hubble-fgs/pkg/sensors/bpf"

var (
	Execve = bpf.Program{
		"bpf_execve_event.o",
		"sched/sched_process_exec",
		"sched/sched_process_exec",
		"tracepoint/sys_execve",
		"event_execve",

		false,
		true,
		"tracepoint",
		bpf.Idle(),

		-1,

		struct{}{},
	}

	Exit = bpf.Program{
		"bpf_exit.o",
		"sched/sched_process_exit",
		"sched/sched_process_exit",
		"tracepoint/sys_exit",
		"event_exit",

		false,
		true,
		"tracepoint",
		bpf.Idle(),

		-1,

		struct{}{},
	}

	Fork = bpf.Program{
		"bpf_fork.o",
		"wake_up_new_task",
		"wake_up_new_task",
		"kprobe/wake_up_new_task",
		"kprobe_pid_clear",

		false,
		true,
		"kprobe",
		bpf.Idle(),

		-1,

		struct{}{},
	}

	Cred = bpf.Program{
		"bpf_cred.o",
		"commit_creds",
		"commit_creds",
		"kprobe/commit_creds",
		"kprobe_commit_creds",

		false,
		true,
		"kprobe",
		bpf.Idle(),

		-1,

		struct{}{},
	}

	TCPConnect = bpf.Program{
		"bpf_tcpmon.o",
		"tcp_connect",
		"tcp_connect",
		"kprobe/tcp_connect",
		"kprobe_tcp_connect",

		false,
		true,
		"kprobe",
		bpf.Idle(),

		-1,

		struct{}{},
	}

	TCPConnectRet = bpf.Program{
		"bpf_tcpmonret.o",
		"__x64_sys_connect",
		"sys_connect",
		"kretprobe/sys_connect",
		"kretprobe_sys_connect",

		true,
		true,
		"kprobe",
		bpf.Idle(),

		-1,

		struct{}{},
	}

	TCPClose = bpf.Program{
		"bpf_tcpclose.o",
		"tcp_set_state",
		"tcp_set_state",
		"kprobe/tcp_set_state",
		"kprobe_tcp_set_state",

		false,
		true,
		"kprobe",
		bpf.Idle(),

		-1,

		struct{}{},
	}

	TCPSendCheck = bpf.Program{
		"bpf_tcp_send_check.o",
		"tcp_v4_send_check",
		"tcp_v4_send_check",
		"kprobe/tcp_v4_send_check",
		"kprobe_tcp_v4_send_check",

		false,
		true,
		"kprobe",
		bpf.Idle(),

		-1,

		struct{}{},
	}

	Listen = bpf.Program{
		"bpf_listen.o",
		"__inet_hash",
		"__inet_hash",
		"kprobe/inet_hash",
		"kprobe_inet_hash",

		false,
		true,
		"kprobe",
		bpf.Idle(),

		-1,

		struct{}{},
	}

	/* Event Ring map */
	TCPMonMap = bpf.Map{"tcpmon_map", "", &Execve, bpf.Idle(), -1}
	/* Networking and Process Monitoring maps */
	ExecveMap           = bpf.Map{"execve_map", "", &Execve, bpf.Idle(), -1}
	SocketMap           = bpf.Map{"socket_map", "", &TCPConnect, bpf.Idle(), -1}
	TCPMap              = bpf.Map{"ipv4_tcp_map", "", &TCPConnect, bpf.Idle(), -1} // NB: This seems to be unused?
	TCPSendCheckSampler = bpf.Map{"tcp_send_check_sampler", "", &TCPSendCheck, bpf.Idle(), -1}
	/* Internal statistics for debugging */
	ExecveStats = bpf.Map{"execve_map_stats", "", &Execve, bpf.Idle(), -1}
	SocketStats = bpf.Map{"socket_map_stats", "", &Execve, bpf.Idle(), -1}
	TLSStats    = bpf.Map{"tls_map_stats", "", &Execve, bpf.Idle(), -1}
	/* Cilium maps */
	CiliumSNAT = bpf.Map{"cilium_snat_v4_external", "", &TCPConnect, bpf.Idle(), -1}
)

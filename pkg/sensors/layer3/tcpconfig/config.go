// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package tcpconfig

import (
	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/cilium/tetragon/pkg/sensors/program"

	"github.com/isovalent/hubble-fgs/pkg/sensors/base"
)

var (
	// Ensure every program has a type defined by the layer3 sensor to force loading
	// through our own LoadProbe function. This is essential for socket discovery.
	//
	// Kprobes are for systems without fentry support (<v5.5).
	// Fentry are preferred from v5.5.
	// SockOps are more efficient and available from v5.14.
	// SockOps needs the SecurityAccept and SecurityGraft.
	ConnectKprobe = program.Builder(
		"bpf_tcp_connect.o",
		"tcp_connect",
		"kprobe/tcp_connect",
		"tg_tcp_connect_kprobe",
		"layer3_sensor",
	)

	ConnectFentry = program.Builder(
		"bpf_tcp_connect_fentry.o",
		"fentry",
		"fentry/tcp_connect",
		"tg_tcp_connect_fentry",
		"tcp_fentry",
	)

	CloseKprobe = program.Builder(
		"bpf_tcp_close.o",
		"tcp_set_state",
		"kprobe/tcp_set_state",
		"tg_tcp_set_state",
		"layer3_sensor",
	)

	CloseFentry = program.Builder(
		"bpf_tcp_close_fentry.o",
		"fentry",
		"fentry/tcp_set_state",
		"tg_tcp_set_state",
		"tcp_fentry",
	)

	ListenKprobe = program.Builder(
		"bpf_tcp_listen.o",
		"__inet_hash",
		"kprobe/__inet_hash",
		"tg___inet_hash",
		"layer3_sensor",
	)

	ListenFentry = program.Builder(
		"bpf_tcp_listen_fentry.o",
		"fentry",
		"fentry/__inet_hash",
		"tg___inet_hash",
		"tcp_fentry",
	)

	SecurityAcceptKprobe = program.Builder(
		"bpf_tcp_security_accept_kprobe.o",
		"security_socket_accept",
		"kprobe/security_socket_accept",
		"tg_tcp_security_accept",
		"layer3_sensor",
	)

	SecurityAccept = program.Builder(
		"bpf_tcp_security_accept.o",
		"security_socket_accept",
		"fentry/security_socket_accept",
		"tg_tcp_security_accept",
		"tcp_fentry",
	)

	SecurityGraftKprobe = program.Builder(
		"bpf_tcp_security_accept_kprobe.o",
		"security_sock_graft",
		"kprobe/security_sock_graft",
		"tg_tcp_security_graft",
		"layer3_sensor",
	)

	SecurityGraft = program.Builder(
		"bpf_tcp_security_accept.o",
		"security_sock_graft",
		"fentry/security_sock_graft",
		"tg_tcp_security_graft",
		"tcp_fentry",
	)

	SendCheck4 = program.Builder(
		"bpf_tcp_send_check.o",
		"tcp_v4_send_check",
		"kprobe/tcp_v4_send_check",
		"tg_tcp_v4_send_check",
		"layer3_sensor",
	)

	SendCheck6 = program.Builder(
		"bpf_tcp_send_check.o",
		"inet6_csk_xmit",
		"kprobe/inet6_csk_xmit",
		"tg_inet6_csk_xmit",
		"layer3_sensor",
	)

	TcpSockops = program.Builder(
		"bpf_tcp_sockops.o",
		"sockops",
		"sockops/tcp_sockops",
		"tg_tcp_sockops",
		"layer3_sensor",
	)

	TCPResetKprobe = program.Builder(
		"bpf_tcp_rst.o",
		"tcp_reset",
		"kprobe/tcp_reset",
		"tg_event_tcp_reset",
		"layer3_sensor",
	)

	TCPResetFentry = program.Builder(
		"bpf_tcp_rst_fentry.o",
		"tcp_reset",
		"fentry/tcp_reset",
		"tg_event_tcp_reset",
		"tcp_fentry",
	)

	// RTT Tracer uses kprobe or Fentry on the TCP ACK Update RTT to get the rtt_us value
	// as that is easily obtained. This is probably as good as we can easily get,
	// although open to improvements and discussion.
	RttTracerKprobe = program.Builder(
		"bpf_tcp_rtt.o",
		"tcp_ack_update_rtt",
		"kprobe/tcp_ack_update_rtt",
		"tg_tcp_ack_update_rtt",
		"layer3_sensor",
	)

	RttTracerFentry = program.Builder(
		"bpf_tcp_rtt_fentry.o",
		"fentry",
		"fentry/tcp_ack_update_rtt",
		"tg_tcp_ack_update_rtt",
		"tcp_fentry",
	)

	// Maps for TCP Sockets
	SocketMap           = program.MapUserFrom(base.SocketMap)
	SocketMapStats      = program.MapUserFrom(base.SocketStats)
	SocketVersionMap    = program.MapUserFrom(base.SocketVersionMap)
	SocketTupleMap      = program.MapUserFrom(base.SocketTupleMap)
	SocketTupleMapStats = program.MapUserFrom(base.SocketTupleStats)
	SocketTupleRevMap   = program.MapUserFrom(base.SocketTupleRevMap)
	SocketTupleHintMap  = program.MapUserFrom(base.SocketTupleHintMap)
	ConfigMap           = program.MapUserFrom(base.CfgMap)

	FinRxMap = program.MapBuilder("tg_l3_tcp_finrx", CloseKprobe, CloseFentry, TcpSockops)

	SecurityAcceptMap = program.MapBuilder("tg_l3_tcp_accsk", SecurityAccept)

	// TCP Runtime maps, created in internal/ip
	TcpSocketMap   = program.MapUserFrom(base.TcpSocketMap)
	TcpSocketStats = program.MapUserFrom(base.TcpSocketMapStats)

	// Parser maps
	HTTPContext    = program.MapBuilder("tg_http_map", TcpSockops)
	TLSContext     = program.MapBuilder("tg_tls_map", TcpSockops)
	TLSMapStats    = program.MapBuilder("tg_tls_map_stats", ConnectKprobe, ConnectFentry, TcpSockops)
	TLSBottles     = program.MapBuilder("tg_bottles", TcpSockops)
	TLSBottleStats = program.MapBuilder("tg_bottle_map_stats", TcpSockops)

	// Maps for watermarks detection
	ProcessNetworkWatermarksMap = program.MapBuilder("tg_l3_wtmk", SendCheck4)

	// LPM maps, created in internal/ip
	Addr6LpmMap = program.MapUserFrom(base.Addr6LpmMap)
	Addr4LpmMap = program.MapUserFrom(base.Addr4LpmMap)
)

var (
	MetricsEnabled  = false
	RttHistogramMax uint32
	RttHistogramMin uint32
	CurrentLabels   = DefaultLabelFilter()
)

// The returned label filter should be kept in sync with:
// SocketLabels.Keys in pkg/metrics/socketmetrics
// createSocketLabels in pkg/metrics/eventmetrics
// TcpPolicySpec.Metrics docs in pkg/k8s (CRD)
func DefaultLabelFilter() metrics.LabelFilter {
	return metrics.LabelFilter{
		"namespace":    true,
		"workload":     true,
		"pod":          false,
		"binary":       true,
		"dstnamespace": true,
		"dstworkload":  true,
		"dstpod":       false,
		"dstdns":       true,
		"dstip":        false,
	}
}

func ClearConfig() {
	MetricsEnabled = false
	RttHistogramMax = 0
	RttHistogramMin = 0
	CurrentLabels = DefaultLabelFilter()
}

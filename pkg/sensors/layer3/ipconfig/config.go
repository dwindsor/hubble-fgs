//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package ipconfig

import (
	"github.com/cilium/tetragon/pkg/sensors/program"

	"github.com/isovalent/hubble-fgs/pkg/sensors/base"
)

const (
	FdLookupConfigMapName = "tg_l3_sk_lookup"
)

var (
	// Socket lookup program
	// Ensure every program has a type defined by the layer3 sensor to force loading
	// through our own LoadProbe function. This is essential for socket discovery.
	FdLookupKprobe = program.Builder(
		"bpf_fd_lookup.o",
		"proc_task_name",
		"kprobe/proc_task_name",
		"kprobe_proc_task_name",
		"layer3_sensor",
	)

	FdLookupFentry = program.Builder(
		"bpf_fd_lookup_fentry.o",
		"fentry",
		"fentry/proc_task_name",
		"fentry_proc_task_name",
		"layer3_sensor",
	)

	FdLookupKprobeProcessTree = program.Builder(
		"bpf_fd_lookup_pstree.o",
		"proc_task_name",
		"kprobe/proc_task_name",
		"kprobe_proc_task_name",
		"layer3_sensor",
	)

	FdLookupFentryProcessTree = program.Builder(
		"bpf_fd_lookup_fentry_pstree.o",
		"fentry",
		"fentry/proc_task_name",
		"fentry_proc_task_name",
		"layer3_sensor",
	)

	// All the FdLookup sensor maps below are accessed from other sensors,
	// so they need to stay global as is expected by its users.

	// Socket lookup config map
	FdLookupConfigMap = program.MapBuilder(FdLookupConfigMapName, FdLookupKprobe, FdLookupFentry, FdLookupKprobeProcessTree, FdLookupFentryProcessTree)

	// Endpoint Models
	ProcessTreeIdMap = program.MapUserFrom(base.ProcessTreeId)

	// Shared socket cookie infrastructure
	SocketMap           = program.MapUserFrom(base.SocketMap)
	SocketMapStats      = program.MapUserFrom(base.SocketStats)
	SocketVersionMap    = program.MapUserFrom(base.SocketVersionMap)
	SocketTupleMap      = program.MapUserFrom(base.SocketTupleMap)
	SocketTupleMapStats = program.MapUserFrom(base.SocketTupleStats)
	SocketTupleRevMap   = program.MapUserFrom(base.SocketTupleRevMap)
	SocketTupleHintMap  = program.MapUserFrom(base.SocketTupleHintMap)
	ConfigMap           = program.MapUserFrom(base.CfgMap)

	// Shared base maps
	ExecveMap = program.MapUserFrom(base.ExecveMap)

	// LPM maps
	Addr6LpmMap = program.MapUserFrom(base.Addr6LpmMap)
	Addr4LpmMap = program.MapUserFrom(base.Addr4LpmMap)

	// TCP maps
	TcpSocketMap      = program.MapUserFrom(base.TcpSocketMap)
	TcpSocketMapStats = program.MapUserFrom(base.TcpSocketMapStats)
)

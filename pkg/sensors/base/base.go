//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package base

import (
	"fmt"
	"log"
	"sync"
	"testing"
	"unsafe"

	"github.com/cilium/tetragon/pkg/errmetrics"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/ksyms"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/mbset"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/sensors"
	ossbase "github.com/cilium/tetragon/pkg/sensors/base"
	"github.com/cilium/tetragon/pkg/sensors/exec/execvemap"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/cilium/tetragon/pkg/strutils"
	"github.com/isovalent/hubble-fgs/pkg/dnsparser"
	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"
	"github.com/isovalent/hubble-fgs/pkg/sensors/base/procfs"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3/lpm"
	socktrackmaps "github.com/isovalent/hubble-fgs/pkg/sensors/socktrack/maps"
)

var (
	basePolicy = "__base__"

	Execve = program.Builder(
		"bpf_execve_event.o",
		"sched/sched_process_exec",
		"tracepoint/sys_execve",
		"event_execve",
		"execve",
	).SetPolicy(basePolicy)

	ExecveV53 = program.Builder(
		"bpf_execve_event_v53.o",
		"sched/sched_process_exec",
		"tracepoint/sys_execve",
		"event_execve",
		"execve",
	).SetPolicy(basePolicy)

	ExecveV511 = program.Builder(
		"bpf_execve_event_v511.o",
		"sched/sched_process_exec",
		"tracepoint/sys_execve",
		"event_execve",
		"execve",
	).SetPolicy(basePolicy)

	ExecveV61 = program.Builder(
		"bpf_execve_event_v61.o",
		"sched/sched_process_exec",
		"tracepoint/sys_execve",
		"event_execve",
		"execve",
	).SetPolicy(basePolicy)

	ExecveV611 = program.Builder(
		"bpf_execve_event_v611.o",
		"sched/sched_process_exec",
		"tracepoint/sys_execve",
		"event_execve",
		"execve",
	).SetPolicy(basePolicy)

	ExecveBprmCommit = program.Builder(
		"bpf_execve_bprm_commit_creds.o",
		"security_bprm_committing_creds",
		"kprobe/security_bprm_committing_creds",
		"tg_kp_bprm_committing_creds",
		"kprobe",
	).SetPolicy(basePolicy)

	Exit = program.Builder(
		"bpf_exit.o",
		"acct_process",
		"kprobe/acct_process",
		"event_exit",
		"kprobe",
	).SetPolicy(basePolicy)

	Fork = program.Builder(
		"bpf_fork.o",
		"wake_up_new_task",
		"kprobe/wake_up_new_task",
		"kprobe_pid_clear",
		"kprobe",
	).SetPolicy(basePolicy)

	SysEnterProg = program.Builder(
		"bpf_syscall.o",
		"raw_syscalls/sys_enter",
		"tracepoint/sys_enter",
		"sys_enter",
		"tracepoint",
	).SetPolicy(basePolicy)

	/* Event Ring map */
	TCPMonMap = program.MapBuilder("tcpmon_map", Execve, ExecveV53, ExecveV511, ExecveV61, ExecveV611)

	/* Networking and Process Monitoring maps */
	ExecveMap                   = program.MapBuilder("execve_map", Execve, ExecveV53, ExecveV511, ExecveV61, ExecveV611, Fork, Exit, ExecveBprmCommit, procfs.ProcFSWalkKprobe, procfs.ProcFSWalkFentry)
	ProcessNetworkWatermarksMap = program.MapBuilder("tg_pn_watermarks_map", Exit)
	SocketMap                   = program.MapBuilder(socktrackmaps.SocketMapName, Exit)
	SocketStats                 = program.MapBuilder(socktrackmaps.SocketStatsName, Exit)
	SocketVersionMap            = program.MapBuilder(socktrackmaps.SocketVersionMapName, Exit)
	SocketTupleMap              = program.MapBuilder(socktrackmaps.SocketTupleMapName, Exit)
	SocketTupleStats            = program.MapBuilder(socktrackmaps.SocketTupleStatsName, Exit)
	SocketTupleRevMap           = program.MapBuilder(socktrackmaps.SocketTupleRevMapName, Exit)
	SocketTupleHintMap          = program.MapBuilder(socktrackmaps.SocketTupleHintMapName, Exit)
	CfgMap                      = program.MapBuilder(socktrackmaps.SocketCfgMapName, Exit)
	TcpSocketMap                = program.MapBuilder("tg_tcpsocket_map", Exit)
	TcpSocketMapStats           = program.MapBuilder("tg_tcpsocket_map_stats", Exit)
	DNSEndpointIDMap            = program.MapBuilder(dnsparser.DNSEndpointIDMapName, Exit)

	ExecveTailCallsMap = program.MapBuilderType("execve_calls", program.MapTypeProgram, Execve, ExecveV53, ExecveV511, ExecveV61, ExecveV611)

	ExecveJoinMap = program.MapBuilder("tg_execve_joined_info_map", ExecveBprmCommit)

	/* Tetragon runtime configuration */
	TetragonConfMap = program.MapBuilder("tg_conf_map", Execve, ExecveV53, ExecveV511, ExecveV61, ExecveV611, procfs.ProcFSWalkKprobe, procfs.ProcFSWalkFentry)

	/* Internal statistics for debugging */
	ExecveStats          = program.MapBuilder("execve_map_stats", Execve, ExecveV53, ExecveV511, ExecveV61, ExecveV611)
	PNWatermarksMapStats = program.MapBuilder("tg_pn_watermarks_map_stats", Exit)
	ExecveJoinMapStats   = program.MapBuilder("tg_execve_joined_info_map_stats", ExecveBprmCommit)
	StatsMap             = program.MapBuilder("tg_stats_map", Execve)

	/* In BPF memory aggregated data */
	PidDataMap               = program.MapBuilder("tg_ee_pid_data", Execve, ExecveV53, ExecveV511, ExecveV61, ExecveV611, SysEnterProg, procfs.ProcFSWalkKprobe, procfs.ProcFSWalkFentry)
	ProcessTreeId            = program.MapBuilder("tg_tree_id", Execve, ExecveV53, ExecveV511, ExecveV61, ExecveV611, procfs.ProcFSWalkKprobe, procfs.ProcFSWalkFentry)
	ProcessTreeMap           = program.MapBuilder("process_tree_map", Execve, ExecveV53, ExecveV511, ExecveV61, ExecveV611, procfs.ProcFSWalkKprobe, procfs.ProcFSWalkFentry)
	ProcessTreeBinaryUUIDMap = program.MapBuilder("process_tree_binary_uid_map", Execve, ExecveV53, ExecveV511, ExecveV61, ExecveV611, procfs.ProcFSWalkKprobe, procfs.ProcFSWalkFentry)
	ProcessTreeUUIDBinaryMap = program.MapBuilder("process_tree_uid_binary_map", Execve, ExecveV53, ExecveV511, ExecveV61, ExecveV611, procfs.ProcFSWalkKprobe, procfs.ProcFSWalkFentry)
	EndpointIdMap            = program.MapBuilder("tg_endpoint_id_map", Execve, ExecveV53, ExecveV511, ExecveV61, ExecveV611)
	Addr6LpmMap              = program.MapBuilder(lpm.Addr6lpmMapName, Execve, ExecveV53, ExecveV511, ExecveV61, ExecveV611)
	Addr4LpmMap              = program.MapBuilder(lpm.Addr4lpmMapName, Execve, ExecveV53, ExecveV511, ExecveV61, ExecveV611)
	DestinationEndpointMap   = program.MapBuilder("destination_endpoint_map", Execve, ExecveV53, ExecveV511, ExecveV61, ExecveV611)
	ListenEndpointMap        = program.MapBuilder("listen_endpoint_map", Execve, ExecveV53, ExecveV511, ExecveV61, ExecveV611)
	BpfEndpointIdMap         = program.MapBuilder("tg_bpf_endpoint_id_map", Execve, ExecveV53, ExecveV61, ExecveV611)
	ProcessTreeConfigMap     = program.MapBuilder("tg_process_tree_config_map", Execve, procfs.ProcFSWalkKprobe, procfs.ProcFSWalkFentry)
	MatchBinariesSetMap      = program.MapBuilder(mbset.MapName, Execve)
	ErrMetricsMap            = program.MapBuilder(errmetrics.MapName, Execve, ExecveV53, ExecveV511, ExecveV61, ExecveV611)
	SyscallsMap              = program.MapBuilder("tg_syscall_map", SysEnterProg)
	NsIDMap                  = program.MapBuilder("tg_cgroup_namespace_map", Execve, procfs.ProcFSWalkKprobe, procfs.ProcFSWalkFentry)
)

func setupSensor() {
	// execve program tail calls details
	Execve.SetTailCall("tracepoint", ExecveTailCallsMap)
	ExecveV53.SetTailCall("tracepoint", ExecveTailCallsMap)
	ExecveV511.SetTailCall("tracepoint", ExecveTailCallsMap)
	ExecveV61.SetTailCall("tracepoint", ExecveTailCallsMap)

	ks, err := ksyms.KernelSymbols()
	if err == nil {
		has_acct_process := ks.IsAvailable("acct_process")
		has_disassociate_ctty := ks.IsAvailable("disassociate_ctty")

		/* Preffer acct_process over disassociate_ctty */
		if has_acct_process {
			Exit.Attach = "acct_process"
			Exit.Label = "kprobe/acct_process"
		} else if has_disassociate_ctty {
			Exit.Attach = "disassociate_ctty"
			Exit.Label = "kprobe/disassociate_ctty"
		} else {
			log.Fatal("Failed to detect exit probe symbol.")
		}
	}
	logger.GetLogger().Info("Exit probe on " + Exit.Attach)

	entries := ossbase.GetExecveEntries(option.Config.ExecveMapEntries, option.Config.ExecveMapSize)
	ExecveMap.SetMaxEntries(entries)

	logger.GetLogger().Info(fmt.Sprintf("Set execve_map entries %d", entries),
		"size", strutils.SizeWithSuffix(entries*int(unsafe.Sizeof(execvemap.ExecveValue{}))))
}

func GetExecveMap() *program.Map {
	return ExecveMap
}

func GetExecveMapStats() *program.Map {
	return ExecveStats
}

func GetTetragonConfMap() *program.Map {
	return TetragonConfMap
}

func initBaseSensor() *sensors.Sensor {
	sensor := sensors.Sensor{
		Name: basePolicy,
	}
	setupSensor()
	sensor.Progs = GetDefaultPrograms()
	sensor.Maps = GetDefaultMaps()
	return ossbase.ApplyExtensions(&sensor)
}

func initBaseSensorFn() func(tb testing.TB) *sensors.Sensor {
	var (
		s *sensors.Sensor
		m sync.Mutex
	)
	return func(tb testing.TB) *sensors.Sensor {
		m.Lock()
		defer m.Unlock()
		if s == nil {
			s = initBaseSensor()
			tb.Cleanup(func() {
				tb.Logf("cleanup: unloading base sensor")
				s.Unload(true)
				s = nil
			})
		}
		return s
	}
}

var (
	// GetInitialSensor returns the collection of Sensor that is loaded at
	// initialization time.
	GetInitialSensor     = sync.OnceValue(initBaseSensor)
	GetInitialSensorTest = initBaseSensorFn()
)

// LoadDefault loads the default sensor, including any from the configuration
// file.
func LoadDefault(bpfDir string) error {
	// This is technically not a sensor since we are loading this
	// statically when we start, but it allows us to have a single path for
	// loading bpf programs.
	load := GetInitialSensor()
	if err := load.Load(bpfDir); err != nil {
		return fmt.Errorf("hubble-fgs, aborting could not load BPF programs: %w", err)
	}
	return nil
}

func ConfigureMapSizes() {
	// If Process Tree Modeling is enabled also set maps to minimal size
	// to avoid unnecessary memory usage.
	if !enterpriseOption.Config.EnableApplicationModel {
		return
	}

	EndpointIdMap.SetMaxEntries(enterpriseOption.Config.EndpointCacheSize)
	BpfEndpointIdMap.SetMaxEntries(enterpriseOption.Config.BpfEndpointCacheSize)
	PidDataMap.SetMaxEntries(enterpriseOption.Config.ProcessTreeCacheSize)
	ProcessTreeBinaryUUIDMap.SetMaxEntries(enterpriseOption.Config.ProcessTreeCacheSize)
	ProcessTreeUUIDBinaryMap.SetMaxEntries(enterpriseOption.Config.ProcessTreeCacheSize)
	ProcessTreeMap.SetMaxEntries(enterpriseOption.Config.ProcessTreeCacheSize)
	DestinationEndpointMap.SetMaxEntries(enterpriseOption.Config.ProcessTreeCacheSize)
	ListenEndpointMap.SetMaxEntries(enterpriseOption.Config.ProcessTreeCacheSize)
	Addr6LpmMap.SetMaxEntries(enterpriseOption.Config.ProcessTreeCacheSize)
	Addr4LpmMap.SetMaxEntries(enterpriseOption.Config.ProcessTreeCacheSize)
	DNSEndpointIDMap.SetMaxEntries(enterpriseOption.Config.ProcessTreeCacheSize)

	if enterpriseOption.Config.EnableSyscallTracking {
		SyscallsMap.SetMaxEntries(enterpriseOption.Config.ProcessTreeCacheSize)
	}
}

func EnableV611Progs() bool {
	if option.Config.ForceSmallProgs {
		return false
	}
	kernelVer, _, _ := kernels.GetKernelVersion(option.Config.KernelVersion, option.Config.ProcFS)
	return (int64(kernelVer) >= kernels.KernelStringToNumeric("6.11.0"))
}

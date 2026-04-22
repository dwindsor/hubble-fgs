// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package base

import (
	"fmt"
	"log"
	"sync"
	"testing"
	"unsafe"

	"github.com/cilium/tetragon/pkg/config"
	"github.com/cilium/tetragon/pkg/errmetrics"
	"github.com/cilium/tetragon/pkg/execvemapupdater"
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

	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"
	"github.com/isovalent/hubble-fgs/pkg/sensors/base/procfs"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3/lpm"
	socktrackmaps "github.com/isovalent/hubble-fgs/pkg/sensors/socktrack/maps"
)

const (
	RingBufMapName = "tg_rb_events"
)

var (
	Execve = program.Builder(
		"bpf_execve_event.o",
		"sched/sched_process_exec",
		"tracepoint/sys_execve",
		"event_execve",
		"execve",
	).SetPolicy(sensors.BaseSensorName)

	ExecveV53 = program.Builder(
		"bpf_execve_event_v53.o",
		"sched/sched_process_exec",
		"tracepoint/sys_execve",
		"event_execve",
		"execve",
	).SetPolicy(sensors.BaseSensorName)

	ExecveV511 = program.Builder(
		"bpf_execve_event_v511.o",
		"sched/sched_process_exec",
		"tracepoint/sys_execve",
		"event_execve",
		"execve",
	).SetPolicy(sensors.BaseSensorName)

	ExecveV61 = program.Builder(
		"bpf_execve_event_v61.o",
		"sched/sched_process_exec",
		"tracepoint/sys_execve",
		"event_execve",
		"execve",
	).SetPolicy(sensors.BaseSensorName)

	ExecveV612 = program.Builder(
		"bpf_execve_event_v612.o",
		"sched/sched_process_exec",
		"tracepoint/sys_execve",
		"event_execve",
		"execve",
	).SetPolicy(sensors.BaseSensorName)

	// changed from "seccomp" to "socket" because of
	// https://github.com/cilium/ebpf/commit/d9790fefdf5d8f55b9a29c44fbbc0f0ae5dcb4e7
	// and https://github.com/cilium/tetragon/commit/29c6fbf1c
	ExecveMapUpdate = program.Builder(
		config.ExecUpdateObj(),
		"socket",
		"socket",
		"execve_map_update",
		"socket",
	).SetPolicy(sensors.BaseSensorName)

	ExecveBprmCommit = program.Builder(
		"bpf_execve_bprm_commit_creds.o",
		"security_bprm_committing_creds",
		"kprobe/security_bprm_committing_creds",
		"tg_kp_bprm_committing_creds",
		"kprobe",
	).SetPolicy(sensors.BaseSensorName)

	Exit = program.Builder(
		"bpf_exit.o",
		"acct_process",
		"kprobe/acct_process",
		"event_exit",
		"kprobe",
	).SetPolicy(sensors.BaseSensorName)

	ExitV511 = program.Builder(
		"bpf_exit_v511.o",
		"acct_process",
		"kprobe/acct_process",
		"event_exit",
		"kprobe",
	).SetPolicy(sensors.BaseSensorName)

	Fork = program.Builder(
		"bpf_fork.o",
		"wake_up_new_task",
		"kprobe/wake_up_new_task",
		"kprobe_pid_clear",
		"kprobe",
	).SetPolicy(sensors.BaseSensorName)

	ForkV511 = program.Builder(
		"bpf_fork_v511.o",
		"wake_up_new_task",
		"kprobe/wake_up_new_task",
		"kprobe_pid_clear",
		"kprobe",
	).SetPolicy(sensors.BaseSensorName)

	SysEnterProg = program.Builder(
		"bpf_syscall.o",
		"raw_syscalls/sys_enter",
		"tracepoint/sys_enter",
		"sys_enter",
		"tracepoint",
	).SetPolicy(sensors.BaseSensorName)

	/* Event Ring map */
	TCPMonMap     = program.MapBuilder("tcpmon_map", Execve, ExecveV53, ExecveV511, ExecveV61, ExecveV612)
	RingBufEvents = program.MapBuilder(RingBufMapName, ExecveV511, ExecveV61, ExecveV612, ExitV511, ForkV511)

	/* Networking and Process Monitoring maps */
	ExecveMap                   = program.MapBuilder("execve_map", Execve, ExecveV53, ExecveV511, ExecveV61, ExecveV612, Fork, ForkV511, Exit, ExitV511, ExecveBprmCommit, procfs.ProcFSWalkKprobe, procfs.ProcFSWalkFentry, ExecveMapUpdate)
	ProcessNetworkWatermarksMap = program.MapBuilder("tg_l3_wtmk", Exit, ExitV511)
	SocketMap                   = program.MapBuilder(socktrackmaps.SocketMapName, Exit, ExitV511)
	SocketStats                 = program.MapBuilder(socktrackmaps.SocketStatsName, Exit, ExitV511)
	SocketVersionMap            = program.MapBuilder(socktrackmaps.SocketVersionMapName, Exit, ExitV511)
	SocketTupleMap              = program.MapBuilder(socktrackmaps.SocketTupleMapName, Exit, ExitV511)
	SocketTupleStats            = program.MapBuilder(socktrackmaps.SocketTupleStatsName, Exit, ExitV511)
	SocketTupleRevMap           = program.MapBuilder(socktrackmaps.SocketTupleRevMapName, Exit, ExitV511)
	SocketTupleHintMap          = program.MapBuilder(socktrackmaps.SocketTupleHintMapName, Exit, ExitV511)
	CfgMap                      = program.MapBuilder(socktrackmaps.SocketCfgMapName, Exit, ExitV511)
	TcpSocketMap                = program.MapBuilder("tg_l3_tcpsk", Exit, ExitV511)
	TcpSocketMapStats           = program.MapBuilder("tg_l3_tcpsk_stats", Exit, ExitV511)

	ExecveTailCallsMap  = program.MapBuilderType("execve_calls", program.MapTypeProgram, Execve, ExecveV53, ExecveV511, ExecveV61, ExecveV612)
	ExecveMapUpdateData = program.MapBuilder("execve_map_update_data", ExecveMapUpdate)

	ExecveJoinMap = program.MapBuilder("tg_execve_joined_info_map", ExecveBprmCommit)

	/* Tetragon runtime configuration */
	TetragonConfMap = program.MapBuilder("tg_conf_map", Execve, ExecveV53, ExecveV511, ExecveV61, ExecveV612, procfs.ProcFSWalkKprobe, procfs.ProcFSWalkFentry)

	/* Internal statistics for debugging */
	ExecveStats          = program.MapBuilder("execve_map_stats", Execve, ExecveV53, ExecveV511, ExecveV61, ExecveV612)
	PNWatermarksMapStats = program.MapBuilder("tg_l3_wtmk_stats", Exit, ExitV511)
	ExecveJoinMapStats   = program.MapBuilder("tg_execve_joined_info_map_stats", ExecveBprmCommit)
	StatsMap             = program.MapBuilder("tg_stats_map", Execve)

	/* In BPF memory aggregated data */
	PidDataMap               = program.MapBuilder("tg_ee_pid_data", Execve, ExecveV53, ExecveV511, ExecveV61, ExecveV612, SysEnterProg, procfs.ProcFSWalkKprobe, procfs.ProcFSWalkFentry, Exit, ExitV511)
	ProcessTreeId            = program.MapBuilder("tg_tree_id", Execve, ExecveV53, ExecveV511, ExecveV61, ExecveV612, procfs.ProcFSWalkKprobe, procfs.ProcFSWalkFentry, Exit, ExitV511)
	ProcessTreeMap           = program.MapBuilder("process_tree_map", Execve, ExecveV53, ExecveV511, ExecveV61, ExecveV612, procfs.ProcFSWalkKprobe, procfs.ProcFSWalkFentry, Exit, ExitV511)
	ProcessTreeBinaryUUIDMap = program.MapBuilder("process_tree_binary_uid_map", Execve, ExecveV53, ExecveV511, ExecveV61, ExecveV612, procfs.ProcFSWalkKprobe, procfs.ProcFSWalkFentry, Exit, ExitV511)
	EndpointIdMap            = program.MapBuilder("tg_endpoint_id_map", Execve, ExecveV53, ExecveV511, ExecveV61, ExecveV612)
	Addr6LpmMap              = program.MapBuilder(lpm.Addr6lpmMapName, Execve, ExecveV53, ExecveV511, ExecveV61, ExecveV612)
	Addr4LpmMap              = program.MapBuilder(lpm.Addr4lpmMapName, Execve, ExecveV53, ExecveV511, ExecveV61, ExecveV612)
	DestinationEndpointMap   = program.MapBuilder("destination_endpoint_map", Execve, ExecveV53, ExecveV511, ExecveV61, ExecveV612)
	ListenEndpointMap        = program.MapBuilder("listen_endpoint_map", Execve, ExecveV53, ExecveV511, ExecveV61, ExecveV612)
	BpfEndpointIdMap         = program.MapBuilder("tg_bpf_endpoint_id_map", Execve, ExecveV53, ExecveV61, ExecveV612)
	ProcessTreeConfigMap     = program.MapBuilder("tg_process_tree_config_map", Execve, procfs.ProcFSWalkKprobe, procfs.ProcFSWalkFentry, Exit, ExitV511)
	MatchBinariesSetMap      = program.MapBuilder(mbset.MapName, Execve)
	MatchBinariesGenMap      = program.MapBuilder(mbset.GenName, Execve)
	ErrMetricsMap            = program.MapBuilder(errmetrics.MapName, Execve, ExecveV53, ExecveV511, ExecveV61, ExecveV612)
	SyscallsMap              = program.MapBuilder("tg_syscall_map", SysEnterProg)
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
			ExitV511.Attach = "acct_process"
			ExitV511.Label = "kprobe/acct_process"
		} else if has_disassociate_ctty {
			Exit.Attach = "disassociate_ctty"
			Exit.Label = "kprobe/disassociate_ctty"
			ExitV511.Attach = "disassociate_ctty"
			ExitV511.Label = "kprobe/disassociate_ctty"
		} else {
			log.Fatal("Failed to detect exit probe symbol.")
		}
	}
	logger.GetLogger().Info("Exit probe on " + Exit.Attach)

	entries := ossbase.GetExecveEntries(option.Config.ExecveMapEntries, option.Config.ExecveMapSize)
	ExecveMap.SetMaxEntries(entries)

	logger.GetLogger().Info(fmt.Sprintf("Set execve_map entries %d", entries),
		"size", strutils.SizeWithSuffix(entries*int(unsafe.Sizeof(execvemap.ExecveValue{}))))

	if option.Config.EnableProcessEnvironmentVariables {
		Execve.RewriteConstants["ENV_VARS_ENABLED"] = uint8(1)
		ExecveV53.RewriteConstants["ENV_VARS_ENABLED"] = uint8(1)
		ExecveV511.RewriteConstants["ENV_VARS_ENABLED"] = uint8(1)
		ExecveV61.RewriteConstants["ENV_VARS_ENABLED"] = uint8(1)
		ExecveV612.RewriteConstants["ENV_VARS_ENABLED"] = uint8(1)
	}
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
		Name: sensors.BaseSensorName,
	}
	setupSensor()
	if config.EnableLargeProgs() {
		mbset.SetMBSetUpdater(&execvemapupdater.ExecveMapUpdater{
			Load: ExecveMapUpdate,
			Map:  ExecveMapUpdateData,
		})
	}
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
				tb.Log("cleanup: unloading base sensor")
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
	if config.EnableV511Progs() && !option.Config.UsePerfRingBuffer {
		rbSize := config.GetRBSize()
		RingBufEvents.SetMaxEntries(rbSize)
		logger.GetLogger().Info("BPF ring buffer size (bytes)", "total", strutils.SizeWithSuffix(rbSize))
	}
	// If Process Tree Modeling is enabled also set maps to minimal size
	// to avoid unnecessary memory usage.
	if !enterpriseOption.Config.EnableApplicationModel {
		return
	}

	EndpointIdMap.SetMaxEntries(enterpriseOption.Config.EndpointCacheSize)
	BpfEndpointIdMap.SetMaxEntries(enterpriseOption.Config.BpfEndpointCacheSize)
	PidDataMap.SetMaxEntries(enterpriseOption.Config.ProcessTreeCacheSize)
	ProcessTreeBinaryUUIDMap.SetMaxEntries(enterpriseOption.Config.ProcessTreeCacheSize)
	ProcessTreeMap.SetMaxEntries(enterpriseOption.Config.ProcessTreeCacheSize)
	DestinationEndpointMap.SetMaxEntries(enterpriseOption.Config.ProcessTreeCacheSize)
	ListenEndpointMap.SetMaxEntries(enterpriseOption.Config.ProcessTreeCacheSize)
	Addr6LpmMap.SetMaxEntries(enterpriseOption.Config.ProcessTreeCacheSize)
	Addr4LpmMap.SetMaxEntries(enterpriseOption.Config.ProcessTreeCacheSize)

	if enterpriseOption.Config.EnableSyscallTracking {
		SyscallsMap.SetMaxEntries(enterpriseOption.Config.ProcessTreeCacheSize)
	}
}

func EnableV612Progs() bool {
	if option.Config.ForceSmallProgs {
		return false
	}
	kernelVer, _, _ := kernels.GetKernelVersion(option.Config.KernelVersion, option.Config.ProcFS)
	return (int64(kernelVer) >= kernels.KernelStringToNumeric("6.11.0"))
}

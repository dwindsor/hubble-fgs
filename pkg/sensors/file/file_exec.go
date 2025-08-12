//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

//go:build !windows

package file

import (
	"fmt"
	"path"
	"strings"
	"sync/atomic"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/cilium/tetragon/pkg/tracingpolicy"

	"github.com/cilium/tetragon/api/v1/tetragon"

	"github.com/isovalent/hubble-fgs/pkg/api/fileapi"
	"github.com/isovalent/hubble-fgs/pkg/sensors/base"
	pol "github.com/isovalent/hubble-fgs/pkg/sensors/file/policy"
	fm "github.com/isovalent/hubble-fgs/pkg/sensors/file/utils"
)

type observerFileExecSensor struct {
	name string
}

func init() {
	fileExec := &observerFileExecSensor{
		name: "file exec sensor",
	}
	sensors.RegisterProbeType("file_exec_monitoring", fileExec)
	sensors.RegisterPolicyHandlerAtInit(fileExec.name, fileExec)
}

var (
	FileExecHooksLsmDigests = [...]FimHook{
		{"lsm.s", "security_bprm_check", []FimFunc{{"security_bprm_check(struct linux_binprm*)", "bpf_file_exec.o", "bprm_check_security", fm.NewSet[tetragon.FileAction]()}}},
		{"fexit", "security_bprm_check", []FimFunc{{"security_bprm_check(struct linux_binprm*)", "bpf_file_exec.o", "security_bprm_check", fm.NewSet[tetragon.FileAction]()}}},
	}
)

func (k *observerFileExecSensor) PolicyHandler(
	policy tracingpolicy.TracingPolicy,
	fid policyfilter.PolicyID,
) (sensors.SensorIface, error) {
	if !policy.TpSpec().FileExecMonitoring.Enable {
		return nil, nil
	}

	var progs []*program.Program
	var maps []*program.Map
	tpid := atomic.AddUint32(&pol.SensorExecCounter, 1)
	name := fmt.Sprintf("fim_exec_sensor_%d", tpid)
	spec := policy.TpSpec()
	pol.FileExecMonitoringTable.AddFileExec(tpid, pol.FileExecMonitoring{
		PolicyName: policy.TpName(),
	})

	// having support for bpf_ima_file_hash helper means that we have everything that
	// we need to enable process_file_exec events
	if !SupportDigests() {
		return nil, fmt.Errorf("FileExecMonitoring is not supported in this kernel")
	}

	fimProgs := make([]FimProg, 0)
	for _, h := range FileExecHooksLsmDigests {
		if len(h.prog) != 1 {
			return nil, fmt.Errorf("FileExecMonitoring has more than one function prototypes per hook")
		}
		fimProgs = append(fimProgs, FimProg{h.tp, h.name, fixProgName(h.prog[0].progName), h.prog[0].progSection, h.prog[0].actions})
	}

	selState, err := fm.InitKernelExecSelectorState(spec.FileExecMonitoring.Selectors)
	if err != nil {
		return nil, fmt.Errorf("FileExecMonitoring failed to parse selectors: %w", err)
	}

	defaultAction, _, err := fm.GetActions(spec.FileExecMonitoring.DefaultActions)
	if err != nil {
		return nil, fmt.Errorf("FileExecMonitoring failed to parse default actions: %s", err)
	}

	// Block action results also in a post. We can introduce
	// support for nopost later if needed.
	if defaultAction&fm.FileOperationTypeBlock != 0 {
		defaultAction |= fm.FileOperationTypePost
	}

	config := fileapi.FileExecConfigMapValue{
		PolicyId:      uint32(fid),
		NumSelectors:  selState.GetNumSelectors(),
		DefaultAction: defaultAction,
	}

	for _, h := range fimProgs {
		load := program.Builder(
			path.Join(option.Config.HubbleLib, h.progName),
			h.name,
			fmt.Sprintf("%s/%s", h.tp, h.progSection),
			fmt.Sprintf("%s_%s", strings.ReplaceAll(h.tp, ".", "_"), h.name),
			"file_exec_monitoring")
		load.SetLoaderData(FimLoaderData{
			tp: h.tp,
		})

		progs = append(progs, load)

		load.MapLoad = []*program.MapLoad{
			{
				Name: "tg_mb_sel_opts",
				Load: func(outerMap *ebpf.Map, _ string) error {
					return fm.PopulateMatchBinariesMaps(selState, outerMap)
				},
			},
			{
				Name: "tg_mb_paths",
				Load: func(outerMap *ebpf.Map, _ string) error {
					return fm.PopulateMatchBinariesPathsMaps(selState, name, outerMap)
				},
			},
			{
				Name: "file_digests_maps",
				Load: func(m *ebpf.Map, _ string) error {
					if err := fm.GenerateFileDigestsMap(m, selState, name); err != nil {
						return fmt.Errorf("file_digests_maps: %w", err)
					}
					return nil
				},
			},
			{
				Name: "file_capabilities_map",
				Load: func(m *ebpf.Map, _ string) error {
					if err := fm.GenerateFileCapabilitiesMap(m, selState); err != nil {
						return fmt.Errorf("file_capabilities_map: %w", err)
					}
					return nil
				},
			},
			{
				Name: "file_namespaces_map",
				Load: func(m *ebpf.Map, _ string) error {
					if err := fm.GenerateFileNamespacesMap(m, selState); err != nil {
						return fmt.Errorf("file_namespaces_map: %w", err)
					}
					return nil
				},
			},
			{
				Name: "file_actions_map",
				Load: func(m *ebpf.Map, _ string) error {
					if err := fm.GenerateFileActionsMap(m, selState); err != nil {
						return fmt.Errorf("file_actions_map: %w", err)
					}
					return nil
				},
			},
			{
				Name: "file_exec_config_map",
				Load: func(m *ebpf.Map, _ string) error {
					return m.Update(uint32(0), config, ebpf.UpdateAny)
				},
			},
		}

		for _, m := range []string{
			"exec_retprobe_map",
			"file_exec_config_map",
			"tg_mb_sel_opts",
			"tg_mb_paths",
			"file_digests_maps",
			"file_capabilities_map",
			"file_namespaces_map",
			"file_actions_map",
			"file_exec_stats_map",
		} {
			m := program.MapBuilderPolicy(m, load)

			// custom max entries setup
			switch m.Name {
			case "tg_mb_paths":
				m.SetInnerMaxEntries(selState.MatchBinariesPathsMaxEntries())
			case "file_digests_maps":
				m.SetInnerMaxEntries(int(fm.GetMaxInnerEntriesDigestsMap(selState)))
			}
			maps = append(maps, m)
		}
	}

	maps = append(maps, program.MapUserFrom(base.ExecveMap))

	return &sensors.Sensor{
		Name:  name,
		Progs: progs,
		Maps:  maps,
		PreUnloadHook: func() error {
			pol.FileExecMonitoringTable.RmFileExec(tpid)
			return nil
		},
	}, nil
}

// LoadProbe() (called when the eBPF programs are actually loaded)
func (k observerFileExecSensor) LoadProbe(args sensors.LoadProbeArgs) error {
	return loadProbe(args)
}

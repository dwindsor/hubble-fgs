//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

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

	"github.com/isovalent/hubble-fgs/pkg/api/fileapi"
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

func (k *observerFileExecSensor) PolicyHandler(
	policy tracingpolicy.TracingPolicy,
	fid policyfilter.PolicyID,
) (*sensors.Sensor, error) {
	if !policy.TpSpec().FileExecMonitoring.Enable {
		return nil, nil
	}

	var progs []*program.Program
	var maps []*program.Map
	tpid := atomic.AddUint32(&pol.SensorExecCounter, 1)
	name := fmt.Sprintf("fim_exec_sensor_%d", tpid)
	spec := policy.TpSpec()

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
		fimProgs = append(fimProgs, FimProg{h.tp, h.name, fixProgName(h.prog[0].progName), h.prog[0].progSection})
	}

	selState, err := fm.InitKernelExecSelectorState(spec.FileExecMonitoring.Selectors)
	if err != nil {
		return nil, fmt.Errorf("FileExecMonitoring failed to parse selectors: %w", err)
	}

	defaultAction, err := fm.GetActions(spec.FileExecMonitoring.DefaultActions)
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
			sensors.PathJoin(name, fmt.Sprintf("%s_%s", strings.Replace(h.tp, ".", "_", -1), h.name)),
			"file_exec_monitoring")
		load.SetLoaderData(FimLoaderData{
			s:  selState,
			tp: h.tp,
		})
		load.MaxEntriesInnerMap = map[string]uint32{
			"tg_mb_paths":       uint32(selState.MatchBinariesPathsMaxEntries()),
			"file_digests_maps": fm.GetMaxInnerEntriesDigestsMap(selState),
		}

		progs = append(progs, load)

		load.MapLoad = []*program.MapLoad{
			{
				Index: 0,
				Name:  "tg_mb_sel_opts",
				Load: func(outerMap *ebpf.Map, _ uint32) error {
					return fm.PopulateMatchBinariesMaps(selState, outerMap)
				},
			},
			{
				Index: 0,
				Name:  "tg_mb_paths",
				Load: func(outerMap *ebpf.Map, _ uint32) error {
					return fm.PopulateMatchBinariesPathsMaps(selState, name, outerMap)
				},
			},
			{
				Index: 0,
				Name:  "file_digests_maps",
				Load: func(m *ebpf.Map, _ uint32) error {
					if err := fm.GenerateFileDigestsMap(m, selState, name); err != nil {
						return fmt.Errorf("file_digests_maps: %w", err)
					}
					return nil
				},
			},
			{
				Index: 0,
				Name:  "file_capabilities_map",
				Load: func(m *ebpf.Map, _ uint32) error {
					if err := fm.GenerateFileCapabilitiesMap(m, selState); err != nil {
						return fmt.Errorf("file_capabilities_map: %w", err)
					}
					return nil
				},
			},
			{
				Index: 0,
				Name:  "file_namespaces_map",
				Load: func(m *ebpf.Map, _ uint32) error {
					if err := fm.GenerateFileNamespacesMap(m, selState); err != nil {
						return fmt.Errorf("file_namespaces_map: %w", err)
					}
					return nil
				},
			},
			{
				Index: 0,
				Name:  "file_actions_map",
				Load: func(m *ebpf.Map, _ uint32) error {
					if err := fm.GenerateFileActionsMap(m, selState); err != nil {
						return fmt.Errorf("file_actions_map: %w", err)
					}
					return nil
				},
			},
			{
				Index: 0,
				Name:  "file_exec_config_map",
				Load: func(m *ebpf.Map, _ uint32) error {
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
			maps = append(maps, program.MapBuilderPin(m, sensors.PathJoin(name, m), load))
		}
	}

	return &sensors.Sensor{
		Name:  name,
		Progs: progs,
		Maps:  maps,
	}, nil
}

// LoadProbe() (called when the eBPF programs are actually loaded)
func (k observerFileExecSensor) LoadProbe(args sensors.LoadProbeArgs) error {
	return loadProbe(args)
}

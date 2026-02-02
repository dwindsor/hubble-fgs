// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

//go:build !windows

package file

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/selectors"
	"github.com/cilium/tetragon/pkg/sensors/program"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"

	"github.com/isovalent/hubble-fgs/pkg/api/fileapi"
	pol "github.com/isovalent/hubble-fgs/pkg/sensors/file/policy"
	fm "github.com/isovalent/hubble-fgs/pkg/sensors/file/utils"
)

// remove all entries of a map
func cleanupMap[K any, V any](mapPath string) error {
	handle, err := ebpf.LoadPinnedMap(mapPath, nil)
	if err != nil {
		return fmt.Errorf("cannot open pinned map %s", mapPath)
	}
	defer handle.Close()

	var key K
	var val V
	for {
		entries := handle.Iterate()
		keyFound := false
		for entries.Next(&key, &val) {
			handle.Delete(key)
			keyFound = true
			break

		}
		if !keyFound {
			break
		}
	}

	return nil
}

func cleanupArrayMapMbPaths(mapPath string) error {
	handle, err := ebpf.LoadPinnedMap(mapPath, nil)
	if err != nil {
		return fmt.Errorf("cannot open pinned map %s", mapPath)
	}
	defer handle.Close()

	info, _ := handle.Info()
	for i := uint32(0); i < info.MaxEntries; i++ {
		var val int32
		if err := handle.Lookup(i, &val); err == nil {
			if err = handle.Delete(i); err != nil {
				return fmt.Errorf("cleanupArrayMapMbPaths delete failed: %w", err)
			}
		}
	}
	return nil
}

func cleanupArrayMapSelOpts(mapPath string) error {
	handle, err := ebpf.LoadPinnedMap(mapPath, nil)
	if err != nil {
		return fmt.Errorf("cannot open pinned map %s", mapPath)
	}
	defer handle.Close()

	info, _ := handle.Info()
	for i := uint32(0); i < info.MaxEntries; i++ {
		val := selectors.MatchBinariesSelectorOptions{
			Op:    0,
			MapID: 0,
		}
		err := handle.Update(i, &val, 0)
		if err != nil {
			return fmt.Errorf("cleanupArrayMapSelOpts update failed: %w", err)
		}
	}
	return nil
}

// only for testing
// remove all entries of all FIM maps
func cleanupFIMMaps(tc *pol.FileMonitoring) error {
	mapDir := bpf.MapPrefixPath()

	if err := cleanupMap[fileapi.LPMMapKey, fileapi.LPMMapValue](program.PolicyMapPath(mapDir, tc.TpName, "lpm_trie_map_alloc")); err != nil {
		return err
	}
	if err := cleanupMap[fileapi.InodeKey, fileapi.InodeVal](program.PolicyMapPath(mapDir, tc.TpName, "hash_map_inode_alloc")); err != nil {
		return err
	}
	if err := cleanupArrayMapSelOpts(program.PolicyMapPath(mapDir, tc.TpName, "tg_mb_sel_opts")); err != nil {
		return err
	}
	if err := cleanupArrayMapMbPaths(program.PolicyMapPath(mapDir, tc.TpName, "tg_mb_paths")); err != nil {
		return err
	}
	if err := cleanupMap[uint32, uint32](program.PolicyMapPath(mapDir, tc.TpName, "file_ops_maps")); err != nil {
		return err
	}
	if err := cleanupMap[uint32, uint32](program.PolicyMapPath(mapDir, tc.TpName, "file_actions_map")); err != nil {
		return err
	}

	return nil
}

// only for testing
// generate the contents of FIM maps (the maps already exist and are empty)
func generateFIMMaps(tc *pol.FileMonitoring, spec *v1alpha1.FileSpec) error {
	tc.Spec = spec
	mapDir := bpf.MapPrefixPath()
	mapPath := program.PolicyMapPath(mapDir, tc.TpName, "lpm_trie_map_alloc")
	lpmMap, err := ebpf.LoadPinnedMap(mapPath, nil)
	if err != nil {
		return fmt.Errorf("cannot open pinned map %s", mapPath)
	}
	defer lpmMap.Close()

	for _, p := range spec.PathsPatterns {
		if p.Type == "PathPrefix" {
			if err := addFilters(lpmMap, p.PathPrefix.Prefix, fileapi.LPMMapValue{Action: fm.FilterMatch}); err != nil {
				return fmt.Errorf("failed to add WatchPath: %w", err)
			}
		} else {
			return fmt.Errorf("generateFIMMaps: unknown type: %s", p.Type)
		}
	}

	for _, str := range spec.PathsExclude {
		if err := addFilters(lpmMap, str, fileapi.LPMMapValue{Action: fm.FilterIgnore}); err != nil {
			return fmt.Errorf("failed to add ExcludePath: %w", err)
		}
	}

	if spec.MonitorHostFiles {
		if _, err := TracingPolicyInitFsScanner(tc.TpName, *spec, mapDir, tc.TpName, true); err != nil {
			return fmt.Errorf("failed TracingPolicyInitFsScanner: %w", err)
		}
	}

	sel, err := fm.InitKernelSelectorState(spec.Selectors, fm.MaxFimSelectors)
	if err != nil {
		return fmt.Errorf("failed to initialize kernel selector state: %w", err)
	}

	configMapPath := program.PolicyMapPath(mapDir, tc.TpName, "file_config_map")
	configMap, err := ebpf.LoadPinnedMap(configMapPath, nil)
	if err != nil {
		return fmt.Errorf("cannot open pinned map %s", configMapPath)
	}
	defer configMap.Close()

	tc.Config.NumSelectors = sel.GetNumSelectors()
	if err := configMap.Update(uint32(0), *tc.Config, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("failed to insert %v: %w", sel, err)
	}

	mbSelOptsPath := program.PolicyMapPath(mapDir, tc.TpName, "tg_mb_sel_opts")
	mbSelOpts, err := ebpf.LoadPinnedMap(mbSelOptsPath, nil)
	if err != nil {
		return fmt.Errorf("cannot open pinned map %s", mbSelOptsPath)
	}
	defer mbSelOpts.Close()

	if err := fm.PopulateMatchBinariesMaps(sel, mbSelOpts); err != nil {
		return fmt.Errorf("failed to populate tg_mb_sel_opts: %w", err)
	}

	mbPathsPath := program.PolicyMapPath(mapDir, tc.TpName, "tg_mb_paths")
	mbPaths, err := ebpf.LoadPinnedMap(mbPathsPath, nil)
	if err != nil {
		return fmt.Errorf("cannot open pinned map %s", mbPathsPath)
	}
	defer mbPaths.Close()

	if err := fm.PopulateMatchBinariesPathsMaps(sel, tc.PinPathPrefix, mbPaths); err != nil {
		return fmt.Errorf("failed to populate tg_mb_paths: %w", err)
	}

	selOpsMapPath := program.PolicyMapPath(mapDir, tc.TpName, "file_ops_maps")
	selOpsHandle, err := ebpf.LoadPinnedMap(selOpsMapPath, nil)
	if err != nil {
		return fmt.Errorf("cannot open pinned map %s", selOpsMapPath)
	}
	defer selOpsHandle.Close()

	if err := fm.GenerateFileOpsMap(selOpsHandle, sel, tc.PinPathPrefix); err != nil {
		return fmt.Errorf("failed to populate file_ops_maps: %w", err)
	}

	selActionsMapPath := program.PolicyMapPath(mapDir, tc.TpName, "file_actions_map")
	selActionsHandle, err := ebpf.LoadPinnedMap(selActionsMapPath, nil)
	if err != nil {
		return fmt.Errorf("cannot open pinned map %s", selActionsMapPath)
	}
	defer selActionsHandle.Close()

	if err := fm.GenerateFileActionsMap(selActionsHandle, sel); err != nil {
		return fmt.Errorf("failed to populate file_actions_map")
	}

	return nil
}

// only for testing
// cleanup and re-generate the contents of FIM maps
// the maps (and programs) are loaded during the whole time of this procedure
func reGenerateFimMaps(spec *v1alpha1.FileSpec) error {
	tc, put, err := pol.FileMonitoringTable.GetOneLockedOrFail()
	if err != nil {
		return err
	}
	defer put()

	if err := cleanupFIMMaps(tc); err != nil {
		return err
	}

	return generateFIMMaps(tc, spec)
}

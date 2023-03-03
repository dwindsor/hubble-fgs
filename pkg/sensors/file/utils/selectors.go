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
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/selectors"
	"github.com/cilium/tetragon/pkg/sensors/tracing"
	"github.com/isovalent/hubble-fgs/pkg/sensors/base"
)

func writeBinaryMap(m *ebpf.Map, id uint32, path string) error {
	p := [256]byte{0}
	copy(p[:], path)
	k := &tracing.BinaryMapKey{PathName: p}
	v := &tracing.BinaryMapValue{Id: uint32(id)}
	return m.Update(k, v, ebpf.UpdateAny)
}

func UpdateNamesMap(mapDir string, sel *selectors.KernelSelectorState) error {
	m, err := ebpf.LoadPinnedMap(filepath.Join(mapDir, base.NamesMap.Name), nil)
	if err != nil {
		return err
	}
	defer m.Close()

	for i, path := range sel.GetNewBinaryMappings() {
		if err := writeBinaryMap(m, i, path); err != nil {
			return err
		}
	}
	return nil
}

func parseSelector(k *selectors.KernelSelectorState, fileSel *v1alpha1.FileSelector) error {
	if err := selectors.ParseMatchBinaries(k, fileSel.MatchBinaries); err != nil {
		return fmt.Errorf("parseMatchBinaries error: %w", err)
	}
	return nil
}

func InitKernelSelectorState(fileSel []v1alpha1.FileSelector) (*selectors.KernelSelectorState, error) {
	if len(fileSel) > 1 {
		return nil, fmt.Errorf("file monitoring supports up to 1 selector")
	}

	kernelSelectors := &selectors.KernelSelectorState{}
	for _, s := range fileSel {
		if err := parseSelector(kernelSelectors, &s); err != nil {
			return nil, err
		}
	}
	return kernelSelectors, nil
}

// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package lpm

import (
	"fmt"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/bpf"
)

func NewLPM() (LPMMap, error) {
	fileLpm4 := filepath.Join(bpf.MapPrefixPath(), Addr4lpmMapName)
	addr4lpm, err := ebpf.LoadPinnedMap(fileLpm4, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to load addr4 LPM map from pin %s: %w", fileLpm4, err)
	}

	fileLpm6 := filepath.Join(bpf.MapPrefixPath(), Addr6lpmMapName)
	addr6lpm, err := ebpf.LoadPinnedMap(fileLpm6, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to load addr6 LPM map from pin %s: %w", fileLpm4, err)
	}

	return &lpmMapImpl{
		addr6: addr6lpm,
		addr4: addr4lpm,
	}, nil
}

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
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
)

func NewLPM() (LPMMap, error) {
	fileLpm4 := filepath.Join(bpf.MapPrefixPath(), Addr4lpmMapName)
	addr4lpm, err := ebpf.LoadPinnedMap(fileLpm4, nil)
	if err != nil {
		logger.GetLogger().Error(fmt.Sprintf("failed to pin addr4 LPM Map (%s)", fileLpm4), logfields.Error, err)
		return nil, err
	}

	fileLpm6 := filepath.Join(bpf.MapPrefixPath(), Addr6lpmMapName)
	addr6lpm, err := ebpf.LoadPinnedMap(fileLpm6, nil)
	if err != nil {
		logger.GetLogger().Error(fmt.Sprintf("failed to pin addr6 LPM Map (%s)", fileLpm6), logfields.Error, err)
		return nil, err
	}

	return &lpmMapImpl{
		addr6: addr6lpm,
		addr4: addr4lpm,
	}, nil
}

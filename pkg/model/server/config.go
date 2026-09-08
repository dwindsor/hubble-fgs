// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package server

import (
	"errors"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"

	"github.com/isovalent/hubble-fgs/pkg/api/modelapi"
)

var cfgMapName = "tg_process_tree_config_map"

type CfgProcessModel struct {
	Enable       bool
	EnableBpfId  bool
	TrackExecIds bool
}

func configureSettings(cfg *CfgProcessModel) error {
	modelapi.ConfigMu.Lock()
	defer modelapi.ConfigMu.Unlock()

	c := &ebpf.MapSpec{
		Name:       cfgMapName,
		Type:       bpf.BPF_MAP_TYPE_ARRAY,
		KeySize:    uint32(unsafe.Sizeof(modelapi.ProcessTreeConfigKey{})),
		ValueSize:  uint32(unsafe.Sizeof(modelapi.ProcessTreeConfigValue{})),
		MaxEntries: 1,
		Pinning:    ebpf.PinByName,
	}
	opts := ebpf.MapOptions{
		PinPath: bpf.MapPrefixPath(),
	}
	m, err := ebpf.NewMapWithOptions(c, opts)
	if err != nil {
		return err
	}
	defer m.Close()

	key := &modelapi.ProcessTreeConfigKey{
		Zero: uint32(0),
	}

	// Carry PolicyGeneration forward instead of resetting it. This function runs
	// again at runtime, not only at startup: applying a parser-enabled
	// TracingPolicy re-enters NewServer through the layer3 PolicyHandler. The
	// datapath compares each socket's stamped generation against this counter, so
	// zeroing it can leave a stale socket's cached value matching the counter
	// again, which skips its re-resolve and misses a policy applied mid-connection.
	// A fresh array map reads back 0, which is fine: the first record change bumps
	// the counter to 1, and a socket stamped 0 is stale against any nonzero value.
	value := &modelapi.ProcessTreeConfigValue{}
	existing := &modelapi.ProcessTreeConfigValue{}
	if err := m.Lookup(key, existing); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		logger.GetLogger().Warn("reading policy generation; carrying zero forward", logfields.Error, err)
	}
	value.PolicyGeneration = existing.PolicyGeneration
	if cfg.EnableBpfId {
		value.EnableBpfId = 1
	} else {
		value.EnableBpfId = 0
	}
	if cfg.Enable {
		value.EnableProcessTree = 1
	} else {
		value.EnableProcessTree = 0
	}
	if cfg.TrackExecIds {
		value.TrackExecIds = 1
	} else {
		value.TrackExecIds = 0
	}

	err = m.Put(key, value)
	if err != nil {
		logger.GetLogger().Warn("Model configuration could not update map", logfields.Error, err)
		return err
	}
	return nil
}

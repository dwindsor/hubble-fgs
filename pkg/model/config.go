//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package model

import (
	"fmt"
	"sync"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/logger"
)

var (
	confMutex  sync.Mutex
	cfgMapName = "tg_process_tree_config_map"
)

type ConfigKey struct {
	Zero uint32
}

func (k *ConfigKey) String() string {
	return fmt.Sprintf("Key: %d\n", k.Zero)
}

type CfgProcessModel struct {
	Enable bool
	EnableBpfId bool
}

type ConfigValue struct {
	EnableBpfId uint64
}

func (v *ConfigValue) String() string {
	return fmt.Sprintf("EnableBpfIds: %d", v.EnableBpfId)
}

func configureSettings(cfg *CfgProcessModel) error {
	confMutex.Lock()
	defer confMutex.Unlock()

	c := &ebpf.MapSpec{
		Name:       cfgMapName,
		Type:       bpf.BPF_MAP_TYPE_ARRAY,
		KeySize:    uint32(unsafe.Sizeof(ConfigKey{})),
		ValueSize:  uint32(unsafe.Sizeof(ConfigValue{})),
		MaxEntries: 1,
		Pinning:    ebpf.PinByName,
	}
	opts := ebpf.MapOptions{
		PinPath: bpf.MapPrefixPath(),
	}
	m, err := ebpf.NewMapWithOptions(c, opts)
	if err != nil {
		return nil
	}
	defer m.Close()

	key := &ConfigKey{
		Zero: uint32(0),
	}

	value := &ConfigValue{}
	if cfg.EnableBpfId {
		value.EnableBpfId = 1
	} else {
		value.EnableBpfId = 0
	}

	err = m.Put(key, cfg)
	if err != nil {
		logger.GetLogger().WithError(err).Warn("Model configuration could not update map")
		return err
	}
	return nil
}

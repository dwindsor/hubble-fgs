// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package modelapi

import (
	"fmt"
	"sync"
)

// ConfigMu serializes every read-modify-write of the single
// tg_process_tree_config_map entry.
var ConfigMu sync.Mutex

type ProcFSConfigKey struct {
	Zero uint32
}

type ProcFSConfigValue struct {
	SignalHit uint8 `align:"signal_hit"`
	Enabled   uint8 `align:"enabled"`
}

// ProcessTreeConfigKey and ProcessTreeConfigValue mirror struct
// process_tree_config and its map tg_process_tree_config_map in
// bpf/process/process_tree.h. They live in this leaf package so a package that
// cannot import pkg/model/server can still share the layout. pkg/model/server
// already depends on pkg/model/datapath.
type ProcessTreeConfigKey struct {
	Zero uint32
}

func (k *ProcessTreeConfigKey) String() string {
	return fmt.Sprintf("Key: %d\n", k.Zero)
}

type ProcessTreeConfigValue struct {
	EnableProcessTree uint64
	EnableBpfId       uint64
	TrackExecIds      uint64
}

func (v *ProcessTreeConfigValue) String() string {
	return fmt.Sprintf("Enable: %d EnableBpfIds: %d", v.EnableProcessTree, v.EnableBpfId)
}

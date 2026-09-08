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

// ConfigMu serializes every read-modify-write of tg_process_tree_config_map. The
// model server writes the enable flags and the datapath bumps PolicyGeneration,
// and both touch the single map entry, so they share one lock.
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
// bpf/process/process_tree.h. The model server writes the enable flags and the
// datapath programmer bumps PolicyGeneration, so both packages need the layout.
// It lives in this leaf package to avoid an import cycle. pkg/model/server
// already depends on pkg/model/datapath, so the datapath cannot import the type
// from the server.
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
	// PolicyGeneration is bumped on every datapath record add or remove so
	// established connections re-resolve their cached verdict.
	PolicyGeneration uint32
	Pad              uint32
}

func (v *ProcessTreeConfigValue) String() string {
	return fmt.Sprintf("Enable: %d EnableBpfIds: %d PolicyGeneration: %d", v.EnableProcessTree, v.EnableBpfId, v.PolicyGeneration)
}

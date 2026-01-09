// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package policy

import (
	"maps"
	"slices"
	"sync"
)

type FileExecMonitoring struct {
	PolicyName string
}

type FileExecTable struct {
	mu sync.Mutex
	mp map[uint32]FileExecMonitoring
}

var (
	FileExecMonitoringTable = FileExecTable{
		mp: make(map[uint32]FileExecMonitoring),
	}
	SensorExecCounter uint32
)

func (t *FileExecTable) AddFileExec(id uint32, tp FileExecMonitoring) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.mp[id] = tp
}

func (t *FileExecTable) RmFileExec(id uint32) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.mp, id)
}

func (t *FileExecTable) GetValuesFileExec() []FileExecMonitoring {
	t.mu.Lock()
	defer t.mu.Unlock()
	return slices.Collect(maps.Values(t.mp))
}

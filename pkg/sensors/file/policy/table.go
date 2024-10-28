//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package policy

import (
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/isovalent/hubble-fgs/pkg/api/fileapi"
	fm "github.com/isovalent/hubble-fgs/pkg/sensors/file/utils"
)

var (
	FileMonitoringTable = FimTable{
		mp: make(map[uint32]*FileMonitoring),
	}
	SensorCounter     uint32
	SensorExecCounter uint32
)

func ResetFIMTracingPolicies() {
	FileMonitoringTable = FimTable{
		mp: make(map[uint32]*FileMonitoring),
	}
	atomic.StoreUint32(&SensorCounter, 0)
	atomic.StoreUint32(&SensorExecCounter, 0)
}

type FileMonitoring struct {
	Spec          *v1alpha1.FileSpec
	PinPathPrefix string
	TpName        string
	TpRules       map[int]string
	Config        *fileapi.FileConfigMapValue
	DigestPaths   []string
	PathMetadata  map[string][]fm.DigestPathMetadata
}

type FimTable struct {
	mu sync.Mutex
	mp map[uint32]*FileMonitoring
}

func (t *FimTable) AddFIM(id uint32, tp *FileMonitoring) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.mp[id] = tp
}

func (t *FimTable) GetFIM(id uint32) (FileMonitoring, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if val, ok := t.mp[id]; ok {
		return *val, nil
	}
	return FileMonitoring{}, fmt.Errorf("fim table: invalid id:%d", id)
}

func (t *FimTable) RmFIM(id uint32) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.mp, id)
}

func (t *FimTable) GetOneLockedOrFail() (*FileMonitoring, func(), error) {
	t.mu.Lock()
	if len(FileMonitoringTable.mp) != 1 {
		t.mu.Unlock()
		return nil, nil, fmt.Errorf("file sensor has more than one tracing policies")
	}

	var tc *FileMonitoring
	for _, val := range FileMonitoringTable.mp {
		tc = val
	}

	return tc, func() { t.mu.Unlock() }, nil
}

func (t *FimTable) GetTpName(id uint32) string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if val, ok := t.mp[id]; ok {
		return val.TpName
	}
	return "<unresolved_policy>"
}

func (t *FimTable) GetTpRule(tpID, ruleID uint32) string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if val, ok := t.mp[tpID]; ok {
		if rl, ok := val.TpRules[int(ruleID)]; ok {
			return rl
		}
		return "<unresolved_rule>"
	}
	return "<unresolved_policy>"
}

func (t *FimTable) GetValuesFIM() []fm.SpecPinPath {
	var vals []fm.SpecPinPath
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, elem := range t.mp {
		vals = append(vals, fm.SpecPinPath{
			PolicyName:   elem.TpName,
			PinPath:      elem.PinPathPrefix,
			Spec:         *elem.Spec,
			DigestPaths:  elem.DigestPaths,
			PathMetadata: elem.PathMetadata,
		})
	}
	return vals
}

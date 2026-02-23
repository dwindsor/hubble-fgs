// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package datapath

import (
	"fmt"
	"sync"

	"github.com/isovalent/hubble-fgs/pkg/model/record"
)

var (
	dummyProcessLock = sync.Mutex{}
	dummyUIDMap      = make(map[string]uint64)
	dummyUserUID     = uint32(0)
)

type DummyBpfProgrammer struct {
	Add      uint64
	AddError uint64
	Del      uint64
	DelError uint64
}

func (p *DummyBpfProgrammer) Start() error {
	return nil
}

func (p *DummyBpfProgrammer) AddRecords(_ []*record.DatapathRecord, _ bool) error {
	return nil
}

func (p *DummyBpfProgrammer) RemoveRecords(_ []*record.DatapathRecord) error {
	return nil
}

func (p *DummyBpfProgrammer) FlushCachedEntries() error {
	return nil
}

func (p *DummyBpfProgrammer) GetBinaryId(binaryName string, ignoreArgs bool) (uint64, error) {
	dummyUserCPU := uint32(0xffffffff)

	dummyProcessLock.Lock()
	defer dummyProcessLock.Unlock()

	id, ok := dummyUIDMap[binaryName]
	if ok {
		return id, nil
	}

	dummyUserUID++
	fmt.Printf("dummy ID %s->%d (ignore_args=%v)\n", binaryName, dummyUserUID, ignoreArgs)

	// Set the cpu field with the ignore_args bit
	cpu := dummyUserCPU & 0x7FFFFFFF // Clear the top bit
	if ignoreArgs {
		cpu |= 0x80000000 // Set the top bit for ignore_args
	}

	id = uint64(uint64(dummyUserUID) | (uint64(cpu) << 32))
	dummyUIDMap[binaryName] = id
	return id, nil
}

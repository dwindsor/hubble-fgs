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
	"sync"

	"github.com/isovalent/hubble-fgs/pkg/endpoint"
	"github.com/isovalent/hubble-fgs/pkg/model/record"
	"github.com/isovalent/hubble-fgs/pkg/model/types"
	"github.com/isovalent/hubble-fgs/pkg/netpol/library"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3/lpm"
)

type Interface interface {
	// Add a set of records to the datapath. 'force' decides if we need
	// push update even if a higher precedent one exists.
	AddRecords(records []record.DatapathRecord, force bool) error

	// Remove a set of records to the datapath.
	RemoveRecords(record []record.DatapathRecord) error

	// FlushCachedEntries removes all BPF-created cached entries from the destination map.
	// Useful in tests to clear stale state between subtests.
	FlushCachedEntries() error

	// Binray UID are sync'd with the datapath.
	GetBinaryId(binary string, ignoreArgs bool) (uint64, error)
}

type recordBackend interface {
	addRecord(r record.DatapathRecord, force bool) error
	removeRecord(r record.DatapathRecord) error
}

type BPFProgrammer struct {
	recordBackend

	initProgrammerOnce sync.Once
	binaryMap          mapInterfaceTyped[processTreeBinaryUIDKey, processTreeID]

	recordsMu sync.Mutex
	records   map[record.RecordKey]record.DatapathRecord
}

type bpfRecordBackend struct {
	dstMap mapInterfaceTyped[types.DestinationEndpointKey, types.DestinationEndpointValue]
	lpmMap lpm.LPMMap

	endpointAdder            endpoint.EndpointAdder
	policyRepositoryIDReader library.PolicyRepositoryIDReader
}

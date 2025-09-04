package datapath

import (
	"sync"

	"github.com/cilium/ebpf"
	"github.com/isovalent/hubble-fgs/pkg/model/record"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3/lpm"
)

type Interface interface {
	// Add a specific record to the datapath. 'force' decides if we need
	// push update even if a higher precedent one exists.
	AddSingleRecord(record *record.DatapathRecord, force bool) error

	// Add a set of records to the datapath. 'force' decides if we need
	// push update even if a higher precedent one exists.
	AddRecords(records []*record.DatapathRecord, force bool) error

	// Remove a specific record to the datapath.
	RemoveSingleRecord(record *record.DatapathRecord) error

	// Remove a set of records to the datapath.
	RemoveRecords(record []*record.DatapathRecord) error

	// Binray UID are sync'd with the datapath.
	GetBinaryId(binary string) (uint64, error)
}

type BpfProgrammer struct {
	Add      uint64
	AddError uint64
	Del      uint64
	DelError uint64

	initProgrammerOnce sync.Once
	dstMap             *ebpf.Map
	binaryMap          *ebpf.Map
	uidBpfMap          *ebpf.Map
	lpmMap             *lpm.LPMMap
}

package datapath

import (
	"github.com/isovalent/hubble-fgs/pkg/model/record"
)

type Interface interface {
	// Add a specific record to the datapath.
	AddSingleRecord(record *record.DatapathRecord) error

	// Add a set of records to the datapath.
	AddRecords(records []*record.DatapathRecord) error

	// Remove a specific record to the datapath.
	RemoveSingleRecord(record *record.DatapathRecord) error

	// Remove a set of records to the datapath.
	RemoveRecords(record []*record.DatapathRecord) (int, error)
}

type BpfProgrammer struct {
	Add      uint64
	AddError uint64
	Del      uint64
	DelError uint64
}

package datapath

import (
	"fmt"
	"sync"

	"github.com/isovalent/hubble-fgs/pkg/model/record"
	"github.com/isovalent/hubble-fgs/pkg/model/server/dpu"
)

var (
	initDPUProgrammerOnce sync.Once
)

type DPUProgrammer struct {
	Add      uint64
	AddError uint64
	Del      uint64
	DelError uint64

	DpuListener *dpu.DPUListener
}

func (p *DPUProgrammer) initDPU() error {
	return nil
}

func (p *DPUProgrammer) AddRecords(records []*record.DatapathRecord, force bool) error {
	for _, r := range records {
		p.AddSingleRecord(r, force)
	}
	return nil
}

// src *types.ProcessTreeKey, ep *endpoint.Endpoint, quota, reset, deny uint64, init bool) error {
// what was init for again?
func (p *DPUProgrammer) AddSingleRecord(r *record.DatapathRecord, _ bool) error {
	initDPUProgrammerOnce.Do(func() { p.initDPU() })

	p.DpuListener.SubmitUpdateToDPU(r)

	// Its not obvious to me that we need to do anything special for the
	// Default rule case in DPU, but leaving a note here in case we need
	// to update.

	p.Add++
	return nil
}

func (p *DPUProgrammer) RemoveSingleRecord(r *record.DatapathRecord) error {
	initDPUProgrammerOnce.Do(func() { p.initDPU() })

	p.DpuListener.SubmitDeleteToDPU(r)

	// Its not obvious to me that we need to do anything special for the
	// Default rule case in DPU, but leaving a note here in case we need
	// to delete.

	p.Del++
	return nil
}

func (p *DPUProgrammer) RemoveRecords(records []*record.DatapathRecord) error {
	for _, r := range records {
		p.RemoveSingleRecord(r)
	}
	return nil
}

func (p *DPUProgrammer) GetBinaryId(_ string, _ bool) (uint64, error) {
	return 0, fmt.Errorf("not supported on DPU offload engine")
}

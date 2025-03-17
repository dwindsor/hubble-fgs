package record

import (
	"github.com/isovalent/hubble-fgs/pkg/endpoint"
	"github.com/isovalent/hubble-fgs/pkg/model/types"
)

// For initial landing lets ignore process hierarchy in this unrolled
// key. In general its possible that you could build policy by Path and
// args, but mark that TBD.
type recordKey struct {
	CgroupId uint64
	Self     uint64
	EP       endpoint.Endpoint
}

type DatapathAction struct {
	Quota uint64
	Reset uint64
	Deny  uint64
}

type DatapathRecord struct {
	Src    *types.ProcessTreeKey
	EP     *endpoint.Endpoint
	Action *DatapathAction
	Init   bool // temporary field until we fix order-of-ops on DNS, UDP, TCP sensors
}

// Set difference operator, A - B. We burn some memory and have to
// walk both records so time is ~[len(A) + len(B)]. One idea would
// be to always store records in this form and then it would be
// simply len(A). []Records might be rather large when used to
// slice up namespaces.
//
// Let the benchmarks judge us.
//
// Warning: When we want to do enforcement by process hierarchy not
// just simple process this needs to be improved to include Path in
// the key. Imagine apache can only launch from systemd or some
// such rule.
func Diff(A, B []*DatapathRecord) []*DatapathRecord {
	var C []*DatapathRecord
	bMap := make(map[recordKey]*DatapathRecord)

	for _, r := range B {
		key := recordKey{
			CgroupId: r.Src.CgroupId,
			Self:     r.Src.Self,
		}
		if r.EP != nil {
			key.EP = *r.EP
		}
		bMap[key] = r
	}

	for _, r := range A {
		key := recordKey{
			CgroupId: r.Src.CgroupId,
			Self:     r.Src.Self,
		}
		if r.EP != nil {
			key.EP = *r.EP
		}
		_, ok := bMap[key]
		if !ok {
			C = append(C, r)
		}
	}
	return C
}

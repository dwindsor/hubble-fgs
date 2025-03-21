package record

import (
	"fmt"

	"github.com/isovalent/hubble-fgs/pkg/endpoint"
	"github.com/isovalent/hubble-fgs/pkg/model/types"
)

const (
	PolicyNone  = uint64(0x00)
	PolicyAllow = uint64(0x01)
	PolicyDeny  = uint64(0x02)
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

func (a *DatapathAction) String() string {
	policy := ""
	switch a.Deny {
	case PolicyNone:
		policy = "none"
	case PolicyAllow:
		policy = "allow"
	case PolicyDeny:
		policy = "deny"
	}
	return fmt.Sprintf("Quota %d Reset %d Policy %s", a.Quota, a.Reset, policy)
}

type DatapathRecord struct {
	Src    *types.ProcessTreeKey
	EP     *endpoint.Endpoint
	Action *DatapathAction
	Init   bool // temporary field until we fix order-of-ops on DNS, UDP, TCP sensors
}

func (r *DatapathRecord) String() string {
	src := ""
	ep := ""
	action := ""

	if r.Src != nil {
		src = fmt.Sprintf("%d:%d", r.Src.CgroupId, r.Src.Self)
	}
	if r.EP != nil {
		ep = fmt.Sprintf("%s", r.EP.String())
	}
	if r.Action != nil {
		action = fmt.Sprintf("%s", r.Action)
	}
	return fmt.Sprintf("Src %s EP %s Action %s", src, ep, action)
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

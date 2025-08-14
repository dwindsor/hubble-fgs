package record

import (
	"fmt"

	"github.com/isovalent/hubble-fgs/pkg/endpoint"
	"github.com/isovalent/hubble-fgs/pkg/model/types"
)

// Precedence order is assumed to same as numeric order which
// is required by BPF datapath implementation. So that order
// is Deny >> Allow >> None.
const (
	PolicyNone     = uint64(0x00)
	PolicyAllow    = uint64(0x01)
	PolicyDeny     = uint64(0x02)
	PolicyFallthru = uint64(0x04)
)

// Policy mask out datapath bookkeeping bits.
const (
	PolicyMask = uint64(3)
)

// For initial landing lets ignore process hierarchy in this unrolled
// key. In general its possible that you could build policy by Path and
// args, but mark that TBD.
type recordKey struct {
	CgroupId uint64
	Self     uint64
	Port     uint32
	EP       endpoint.Endpoint
	SrcIp    string
	SrcPort  uint32
}

type DatapathAction struct {
	// Quota limit in bytes
	QuotaLimit uint64
	// Reset time in nanoseconds
	ResetTime uint64
	// Action that could be none, allow or deny
	Action uint64
}

func (a *DatapathAction) String() string {
	policy := ""
	switch a.Action {
	case PolicyNone:
		policy = "none"
	case PolicyAllow:
		policy = "allow"
	case PolicyDeny:
		policy = "deny"
	}
	return fmt.Sprintf("Quota %d Reset %d Policy %s", a.QuotaLimit, a.ResetTime, policy)
}

// For now only expose IP:Port because we only have a middlebox user at the
// moment. VM and K8s use cases are specified using the Src key. The purist
// would tell us (and they would be correct) to extend Src key directly, but
// hacking a new field type keeps separate things separate for the time being.
type DatapathSource struct {
	Ip   string
	Port uint32
}

type DatapathEndpoint struct {
	EP   *endpoint.Endpoint
	Port uint32
}

func (r DatapathEndpoint) String() string {
	if r.EP == nil {
		return "nil"
	}

	if r.Port != 0 {
		return fmt.Sprintf("%s : %d", r.EP, r.Port)
	}
	return fmt.Sprint(r.EP)
}

type Policy struct {
	Name string
	Rule string
}

func (p Policy) String() string {
	return fmt.Sprint(p.Name)
}

type DatapathRecord struct {
	Policy   Policy
	Src      *types.ProcessTreeKey
	L3Src    DatapathSource
	Endpoint DatapathEndpoint
	Action   *DatapathAction
	Init     bool // temporary field until we fix order-of-ops on DNS, UDP, TCP sensors
}

func (r *DatapathRecord) String() string {
	src := ""
	action := ""

	if r.Src != nil {
		src = fmt.Sprintf("%d:%d", r.Src.NSID, r.Src.Self)
	}

	ep := fmt.Sprint(r.Endpoint.String())

	if r.Action != nil {
		action = r.Action.String()
	}
	return fmt.Sprintf("Policy %s Src %s Endpoint %s Action %s", r.Policy.Name, src, ep, action)
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
		key := recordKey{}

		if r.Src != nil {
			key.CgroupId = r.Src.NSID
			key.Self = r.Src.Self
		}

		if r.Endpoint.EP != nil {
			key.EP = *r.Endpoint.EP
			key.Port = r.Endpoint.Port
		}

		key.SrcIp = r.L3Src.Ip
		key.SrcPort = r.L3Src.Port

		bMap[key] = r
	}

	for _, r := range A {
		key := recordKey{}

		if r.Src != nil {
			key.CgroupId = r.Src.NSID
			key.Self = r.Src.Self
		}
		if r.Endpoint.EP != nil {
			key.EP = *r.Endpoint.EP
			key.Port = r.Endpoint.Port
		}

		key.SrcIp = r.L3Src.Ip
		key.SrcPort = r.L3Src.Port

		_, ok := bMap[key]
		if !ok {
			C = append(C, r)
		}
	}
	return C
}

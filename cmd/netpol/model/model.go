package model

import (
	"cmp"
	"iter"
	"net/netip"
	"slices"

	"github.com/isovalent/hubble-fgs/cmd/netpol/types"
)

type Model struct {
	lpm4        LPM4[BitMap]
	lpm6        LPM6[BitMap]
	bitMapSize  int
	emptyBitMap BitMap
	rules       []types.Rule
}

func NewModel(policies ...types.Policy) (*Model, error) {
	m := &Model{
		lpm4: NewLPM4[BitMap](),
		lpm6: NewLPM6[BitMap](),
	}

	for _, p := range policies {
		// Fill in original indexes before they get sorted
		for i := range p.Rules {
			p.Rules[i].Index = i
		}
		m.rules = append(m.rules, p.Rules...)
	}
	m.bitMapSize = len(m.rules)
	m.emptyBitMap = NewBitMap(m.bitMapSize)

	// Sort the rules from all the policies to insert them in the
	// right order into the LPMs to ensure the bitmaps are populated
	// correctly, e.g. 10.1.0.0/24 inherits rules of 10.0.0.0/8.
	SortRules(m.rules)

	// Calculate a lookup table for the final bitmap order with denies first
	lookup := make([]int, len(m.rules))
	pos := 0
	for i, r := range m.rules {
		if r.Action == Deny {
			lookup[i] = pos
			pos++
		}
	}
	for i, r := range m.rules {
		if r.Action == Allow {
			lookup[i] = pos
			pos++
		}
	}

	// Populate LPMs in the prefix/port order.
	for i, policy := range m.rules {
		m.setPolicyBit(policy.Source.Prefix, lookup[i])
		m.setPolicyBit(policy.Destination.Prefix, lookup[i])
	}

	// Sort the rules into the final order with denies first.
	slices.SortStableFunc(m.rules, func(a, b types.Rule) int {
		if a.Action != b.Action {
			if a.Action == Deny {
				return -1
			}
			return 1
		}
		return 0
	})
	return m, nil
}

func SortRules(rules []types.Rule) {
	slices.SortStableFunc(rules, func(a, b types.Rule) int {
		return cmp.Or(
			types.PrefixCompare(a.Source.Prefix, b.Source.Prefix),
			types.PrefixCompare(a.Destination.Prefix, b.Destination.Prefix),
			cmp.Compare(b.Source.NumPorts(), a.Source.NumPorts()),
			cmp.Compare(b.Destination.NumPorts(), a.Destination.NumPorts()),
			cmp.Compare(a.Source.Protocol, b.Source.Protocol),
		)
	})
}

func (m *Model) setPolicyBit(prefix netip.Prefix, index int) {
	var lpm LPMAPI[BitMap]
	if prefix.Addr().Is4() {
		lpm = m.lpm4
	} else {
		lpm = m.lpm6
	}
	bitMap, found := lpm.LookupPrefix(prefix)
	if !found {
		bitMap = NewBitMap(m.bitMapSize)
	} else {
		bitMap = bitMap.Clone()
	}
	bitMap.Set(index)
	lpm.Insert(prefix, bitMap)
}

func (m *Model) lookup(addr netip.Addr) (bm BitMap) {
	found := false
	if addr.Is4() {
		bm, found = m.lpm4.LookupAddr(addr)
	} else {
		bm, found = m.lpm6.LookupAddr(addr)
	}
	if !found {
		return m.emptyBitMap
	}
	return
}

func (m *Model) Evaluate(flow types.Flow) (int, types.Action) {
	/*log := slog.With(
		"src",
		flow.Source,
		"srcPort",
		flow.SourcePort,
		"dst",
		flow.Destination,
		"dstPort",
		flow.DestinationPort,
		"proto",
		flow.Protocol,
	)*/

	// Find rules that match the source address
	srcRules := m.lookup(flow.Source)

	// Find rules that match the destination address
	dstRules := m.lookup(flow.Destination)

	for i := range AndBits(srcRules, dstRules) {
		rule := m.rules[i]
		matches :=
			flow.SourceVlan == rule.Source.Vlan &&
				flow.DestinationVlan == rule.Destination.Vlan &&
				flow.Protocol == rule.Source.Protocol &&
				flow.SourceVrf == rule.Source.Vrf &&
				flow.DestinationVrf == rule.Destination.Vrf &&
				uint16(flow.SourcePort) >= rule.Source.MinPort &&
				uint16(flow.SourcePort) <= rule.Source.MaxPort &&
				uint16(flow.DestinationPort) >= rule.Destination.MinPort &&
				uint16(flow.DestinationPort) <= rule.Destination.MaxPort &&
				rule.Source.Prefix.Contains(flow.Source) &&
				rule.Destination.Prefix.Contains(flow.Destination)

		if matches {
			//log.Info("rule found", "index", i, "action", rule.Action)
			return rule.Index, rule.Action
		}
	}
	return -1, NoMatch
}

func Diff(m1, m2 *Model, flows iter.Seq[types.Flow]) (diff FlowDiff) {
skip:
	for flow := range flows {
		diff.NumFlowsAnalyzed++

		i1, v1 := m1.Evaluate(flow)
		i2, v2 := m2.Evaluate(flow)

		flow.Action = v2
		if v2 == NoMatch {
			flow.Action = Deny // Default deny
		}
		switch {
		case v1 == v2 || v1 == NoMatch && v2 == NoMatch:
			// Skip flows that have the same verdict or that don't match any of the rules
			continue skip
		case v1 == Allow && (v2 == Deny || v2 == NoMatch):
			diff.AllowToDeny = append(diff.AllowToDeny, flow)
		case v1 == Deny && v2 == Allow:
			diff.DenyToAllow = append(diff.DenyToAllow, flow)
		}
		diff.Flows = append(diff.Flows, types.FlowDiff{
			Flow: &flow,
			I1:   i1,
			I2:   i2,
			V1:   v1,
			V2:   v2,
		})
	}
	return
}

type FlowDiff struct {
	AllowToDeny      []types.Flow
	DenyToAllow      []types.Flow
	Flows            []types.FlowDiff
	NumFlowsAnalyzed int
}

const (
	Allow   = types.Allow
	Deny    = types.Deny
	NoMatch = types.NoMatch
)

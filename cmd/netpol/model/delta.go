package model

import (
	"bytes"
	"cmp"
	"fmt"
	"io"
	"iter"
	"maps"
	"math/bits"
	"net/netip"
	"slices"
	"text/tabwriter"
	"time"

	"github.com/isovalent/hubble-fgs/cmd/netpol/types"
)

type interval struct {
	src                    netip.Prefix
	srcMinPort, srcMaxPort uint16
	srcVlan                uint16
	srcVrf                 string

	dst                    netip.Prefix
	dstMinPort, dstMaxPort uint16
	dstVlan                uint16
	dstVrf                 string

	proto types.Protocol
}

func (a interval) compare(b interval) int {
	numPorts := func(minPort, maxPort uint16) int {
		return 1 + int(minPort) - int(maxPort)
	}
	return cmp.Or(
		cmp.Compare(a.srcVlan, b.srcVlan),
		cmp.Compare(a.srcVrf, b.srcVrf),
		cmp.Compare(a.dstVlan, b.dstVlan),
		cmp.Compare(a.dstVrf, b.dstVrf),
		types.PrefixCompare(a.src, b.src),
		types.PrefixCompare(a.dst, b.dst),
		cmp.Compare(numPorts(a.srcMinPort, a.srcMaxPort), numPorts(b.srcMinPort, b.srcMaxPort)),
		cmp.Compare(numPorts(a.dstMinPort, a.dstMaxPort), numPorts(b.dstMinPort, b.dstMaxPort)),
		cmp.Compare(a.proto, b.proto),
	)
}

type name struct {
	policyName, ruleName string
}

type verdict struct {
	interval
	rule    types.Rule
	verdict types.Action
}

func (a verdict) compare(b verdict) int {
	verdictCmp := 0
	switch {
	case a.verdict == Deny && b.verdict != Deny:
		verdictCmp = -1
	case b.verdict == Deny && a.verdict != Deny:
		verdictCmp = 1
	}
	return cmp.Or(
		a.interval.compare(b.interval),
		verdictCmp,
	)
}
func (a verdict) ruleCompare(b verdict) int {
	return a.rule.Compare(b.rule)
}

// evaluateVerdicts returns verdicts for each of the intervals.
// This returns all verdicts even for rules that were shadowed by other rules,
// this property is used to be able to merge verdicts with verdicts from another
// policy and to then calculate which of the verdicts wins for that interval.
func evaluateVerdicts(intervals []interval, rules []types.Rule) [][]verdict {
	// Sort the rules by VRF for faster lookup
	slices.SortFunc(rules, func(a, b types.Rule) int {
		return cmp.Compare(a.Source.Vrf, b.Source.Vrf)
	})
	rulesForVRF := func(vrf string) iter.Seq[types.Rule] {
		// Binary search to find the first rule with this VRF.
		idx, _ := slices.BinarySearchFunc(
			rules,
			types.Rule{Source: types.Subject{Vrf: vrf}},
			func(r types.Rule, target types.Rule) int {
				c := cmp.Compare(r.Source.Vrf, target.Source.Vrf)
				if c == 0 {
					return 1
				}
				return c
			},
		)
		return func(yield func(types.Rule) bool) {
			if idx >= len(rules) || rules[idx].Source.Vrf != vrf {
				return
			}
			for _, r := range rules[idx:] {
				if r.Source.Vrf != vrf {
					return
				}
				if !yield(r) {
					return
				}
			}
		}
	}

	verdicts := make([][]verdict, len(intervals))
	for i, ival := range intervals {
		for r := range rulesForVRF(ival.srcVrf) {
			overlaps :=
				ival.proto == r.Source.Protocol &&
					ival.srcVlan == r.Source.Vlan &&
					ival.srcVrf == r.Source.Vrf &&
					ival.dstVlan == r.Destination.Vlan &&
					ival.dstVrf == r.Destination.Vrf &&
					portsOverlap(ival.srcMinPort, ival.srcMaxPort, r.Source.MinPort, r.Source.MaxPort) &&
					portsOverlap(ival.dstMinPort, ival.dstMaxPort, r.Destination.MinPort, r.Destination.MaxPort) &&
					ival.src.Overlaps(r.Source.Prefix) &&
					ival.dst.Overlaps(r.Destination.Prefix)
			if overlaps {
				// The rules overlap, record a verdict for the overlapping range.
				verdicts[i] = append(
					verdicts[i],
					verdict{
						rule: r,
						interval: interval{
							src:        minPrefix(ival.src, r.Source.Prefix),
							dst:        minPrefix(ival.dst, r.Destination.Prefix),
							srcMinPort: max(ival.srcMinPort, r.Source.MinPort),
							srcMaxPort: min(ival.srcMaxPort, r.Source.MaxPort),
							dstMinPort: max(ival.dstMinPort, r.Destination.MinPort),
							dstMaxPort: min(ival.dstMaxPort, r.Destination.MaxPort),
							srcVlan:    r.Source.Vlan,
							srcVrf:     r.Source.Vrf,
							dstVlan:    r.Destination.Vlan,
							dstVrf:     r.Destination.Vrf,
						},
						verdict: r.Action,
					},
				)
			}
		}
	}
	return verdicts
}

func gatherIntervals(ruleSets ...[]types.Rule) (intervals []interval) {
	for _, rules := range ruleSets {
		for _, rule := range rules {
			intervals = append(intervals, interval{
				src:        rule.Source.Prefix,
				dst:        rule.Destination.Prefix,
				srcMinPort: rule.Source.MinPort,
				srcMaxPort: rule.Source.MaxPort,
				dstMinPort: rule.Destination.MinPort,
				dstMaxPort: rule.Destination.MaxPort,
				proto:      rule.Source.Protocol,
				srcVlan:    rule.Source.Vlan,
				srcVrf:     rule.Source.Vrf,
				dstVlan:    rule.Destination.Vlan,
				dstVrf:     rule.Destination.Vrf,
			})
		}
	}
	// Sort and dedup intervals
	slices.SortFunc(intervals, interval.compare)
	return slices.Compact(intervals)
}

func PrintDelta(w io.Writer, base types.Policy, oldPolicy, newPolicy types.Policy) {
	const debugDelta = false
	t0 := time.Now()
	td := time.Now()
	printTimeDelta := func(x string) {
		if debugDelta {
			fmt.Printf("%s: %s (%s)\n", x, time.Since(td), time.Since(t0))
			td = time.Now()
		}
	}

	// Gather intervals to test from the old and new version of the policy
	intervals := gatherIntervals(oldPolicy.Rules, newPolicy.Rules)
	printTimeDelta(fmt.Sprintf("intervals (%d)", len(intervals)))

	// Evaluate the intervals against the base verdicts
	baseVerdicts := evaluateVerdicts(intervals, base.Rules)
	for i := range baseVerdicts {
		baseVerdicts[i] = compactVerdicts(baseVerdicts[i])
	}

	printTimeDelta(fmt.Sprintf("eval base (%d rules)", len(base.Rules)))

	// Evaluate the intervals against the old version of the policy and merge with
	// base verdicts and remove shadowed verdicts.
	verdicts1 := evaluateVerdicts(intervals, oldPolicy.Rules)
	for i := range verdicts1 {
		verdicts1[i] = compactVerdicts(append(verdicts1[i], baseVerdicts[i]...))
	}

	printTimeDelta("eval old")
	verdicts2 := evaluateVerdicts(intervals, newPolicy.Rules)
	for i := range verdicts2 {
		verdicts2[i] = compactVerdicts(append(verdicts2[i], baseVerdicts[i]...))
	}
	printTimeDelta("eval new")

	type diffResult struct {
		ival     interval
		old, new []verdict
	}
	diff := []diffResult{}
	for i, vs1 := range verdicts1 {
		vs2 := verdicts2[i]
		if !slices.EqualFunc(vs1, vs2, func(a, b verdict) bool { return a.compare(b) == 0 }) {
			diff = append(diff, diffResult{intervals[i], vs1, vs2})
		}
	}
	printTimeDelta("diff")

	for _, r := range diff {

		var rdiff []struct {
			old bool
			r   types.Rule
		}
	outer1:
		for _, v := range r.old {
			for _, v2 := range r.new {
				if v2.rule.CompareContent(v.rule) == 0 {
					continue outer1
				}
			}
			rdiff = append(rdiff, struct {
				old bool
				r   types.Rule
			}{true, v.rule})
		}
	outer2:
		for _, v := range r.new {
			for _, v2 := range r.old {
				if v2.rule.PolicyName == oldPolicy.Name &&
					v2.rule.CompareContent(v.rule) == 0 {
					continue outer2
				}
			}
			rdiff = append(rdiff, struct {
				old bool
				r   types.Rule
			}{false, v.rule})
		}
		slices.SortFunc(rdiff, func(a, b struct {
			old bool
			r   types.Rule
		}) int {
			oldCmp := 0
			if a.old {
				oldCmp = -1
			}
			return cmp.Or(oldCmp, a.r.Compare(b.r))
		})
		rdiff = slices.Compact(rdiff)

		fmt.Fprintf(w, "%s:%s -> %s:%s\n",
			r.ival.src, types.ShowPort(r.ival.srcMinPort, r.ival.srcMaxPort),
			r.ival.dst, types.ShowPort(r.ival.dstMinPort, r.ival.dstMaxPort),
		)

		tw := tabwriter.NewWriter(w, 2, 2, 2, ' ', 0)
		fmt.Fprintln(tw, "   \tRule\tProto\tSrc\tSrcPort\tSrcVLAN\tSrcVRF\tDst\tDstPort\tDstVLAN\tDstVRF\tAction")
		for _, rd := range rdiff {
			var buf bytes.Buffer
			if rd.old {
				fmt.Fprintf(&buf, "  -\t")
			} else {
				fmt.Fprintf(&buf, "  +\t")
			}
			r := rd.r
			r.PrintRule(&buf)
			tw.Write(buf.Bytes())
		}
		tw.Flush()
		fmt.Fprintln(w)
	}
}

func ComputeMinimal(base types.Policy, oldPolicy, newPolicy types.Policy) ([]types.Rule, []types.Rule, *Filter) {
	intervals := gatherIntervals(oldPolicy.Rules, newPolicy.Rules)

	// Evaluate the intervals against the base verdicts
	baseVerdicts := evaluateVerdicts(intervals, base.Rules)
	for i := range baseVerdicts {
		// Remove verdicts that are shadowed by wider verdicts
		baseVerdicts[i] = compactVerdicts(baseVerdicts[i])
	}

	// Evaluate the intervals against the old version of the policy and merge with
	// base verdicts and remove shadowed verdicts.
	verdicts1 := evaluateVerdicts(intervals, oldPolicy.Rules)
	for i := range verdicts1 {
		verdicts1[i] = compactVerdicts(append(verdicts1[i], baseVerdicts[i]...))
	}

	verdicts2 := evaluateVerdicts(intervals, newPolicy.Rules)
	for i := range verdicts2 {
		verdicts2[i] = compactVerdicts(append(verdicts2[i], baseVerdicts[i]...))
	}

	relevantOldRules := map[types.Rule]bool{}
	relevantNewRules := map[types.Rule]bool{}

	for i, vs1 := range verdicts1 {
		vs2 := verdicts2[i]
		if !slices.EqualFunc(vs1, vs2, func(a, b verdict) bool { return a.compare(b) == 0 }) {
			for _, v := range vs1 {
				relevantOldRules[v.rule] = true
			}
			for _, v := range vs2 {
				relevantNewRules[v.rule] = true
			}
		}
	}

	filter := NewFilter()
	for _, ival := range intervals {
		filter.AddVLAN(ival.srcVlan)
		filter.AddVLAN(ival.dstVlan)
		filter.AddVRF(ival.srcVrf)
		filter.AddVRF(ival.dstVrf)
		filter.AddProtocol(ival.proto)
		filter.AddSource(ival.src, ival.srcMinPort, ival.srcMaxPort)
		filter.AddDestination(ival.dst, ival.dstMinPort, ival.dstMaxPort)
	}
	return slices.SortedFunc(maps.Keys(relevantOldRules), types.Rule.Compare),
		slices.SortedFunc(maps.Keys(relevantNewRules), types.Rule.Compare),
		filter
}

func portsOverlap(aMin, aMax, bMin, bMax uint16) bool {
	return min(int(aMax), int(bMax))-max(int(aMin), int(bMin)) >= 0
}

// minPrefix returns the more specific prefix from two overlapping prefixes
func minPrefix(a, b netip.Prefix) netip.Prefix {
	switch {
	case a.Addr().BitLen() < b.Addr().BitLen():
		return a
	case b.Addr().BitLen() < a.Addr().BitLen():
		return b
	case a.Bits() > b.Bits():
		return a
	case b.Bits() > a.Bits():
		return b
	case a.Addr().Less(b.Addr()):
		return a
	default:
		return b
	}
}

func removeShadowed[T any](xs []T, cmp func(T, T) int, shadowed func(T, T) bool) []T {
	// Sort first to bring the "larger" items to the front
	slices.SortFunc(xs, cmp)

	wasShadowed := NewBitMap(len(xs))
	result := make([]T, 0, len(xs))
outer:
	for i := range xs {
		for j := range i {
			if !wasShadowed.Get(j) && shadowed(xs[j], xs[i]) {
				wasShadowed.Set(i)
				continue outer
			}
		}
		result = append(result, xs[i])
	}
	return result
}

// compactVerdicts removes verdicts that are shadowed by more general ones.
func compactVerdicts(vs []verdict) []verdict {
	return removeShadowed(vs, verdict.ruleCompare, verdictContains)
}

func verdictContains(a, b verdict) bool {
	return intervalContains(a.interval, b.interval) &&
		ruleOverrides(a.rule, b.rule) &&
		(a.verdict == b.verdict || a.verdict == Deny)
}

func compactRules(rs []types.Rule) []types.Rule {
	nrs := removeShadowed(rs, types.Rule.Compare, ruleOverrides)
	if len(rs) != len(nrs) {
		fmt.Printf("compactRules: removed %d shadowed rules\n", len(rs)-len(nrs))
	}
	return nrs
}

/*
func compactIntervals(intervals []interval) []interval {
	return removeShadowed(intervals, interval.compare, intervalContains)
}

func compactPrefixes(prefixes []netip.Prefix) []netip.Prefix {
	return removeShadowed(prefixes, types.PrefixCompare, prefixContains)
}*/

func intervalContains(a, b interval) bool {
	return a.srcMinPort <= b.srcMinPort &&
		a.srcMaxPort >= b.srcMaxPort &&
		a.dstMinPort <= b.dstMinPort &&
		a.dstMaxPort >= b.dstMaxPort &&
		prefixContains(a.src, b.src) &&
		prefixContains(a.dst, b.dst)
}

// prefixContains returns true if the prefix [a] contains all of [b]
func prefixContains(a, b netip.Prefix) bool {
	if a.Bits() > b.Bits() {
		return false
	}
	numBits := a.Bits()
	if a.Addr().Is4() {
		numBits += 12 * 8
	}
	return hasCommonPrefix(
		a.Masked().Addr().As16(),
		b.Masked().Addr().As16(),
		numBits)
}

func hasCommonPrefix(a, b [16]byte, bits int) bool {
	if bits > 128 {
		panic("too many bits")
	}
	i := 0
	for bits >= 8 {
		if a[i] != b[i] {
			return false
		}
		bits -= 8
		i++
	}
	if bits > 0 {
		mask := byte(0xff << (8 - bits) & 0xff)
		return a[i]&mask == b[i]&mask
	}
	return true
}

func ruleOverrides(a, b types.Rule) bool {
	return (a.Action == b.Action || a.Action == Deny) &&
		a.Source.Protocol == b.Source.Protocol &&
		a.Source.Vlan == b.Source.Vlan &&
		a.Source.Vrf == b.Source.Vrf &&
		a.Source.MinPort <= b.Source.MinPort &&
		a.Source.MaxPort >= b.Source.MaxPort &&
		a.Destination.MinPort <= b.Destination.MinPort &&
		a.Destination.MaxPort >= b.Destination.MaxPort &&
		prefixContains(a.Source.Prefix, b.Source.Prefix) &&
		prefixContains(a.Destination.Prefix, b.Destination.Prefix)
}

type ShadowedRule struct {
	Rule       types.Rule
	ShadowedBy []types.Rule
}

func FindShadowedRules(rules []types.Rule) []ShadowedRule {
	slices.SortFunc(rules, types.Rule.Compare)
	result := map[name]ShadowedRule{}
	for i := range rules {
		for j := range i {
			if ruleOverrides(rules[j], rules[i]) {
				result[ruleToName(&rules[i])] =
					ShadowedRule{rules[i], append(result[ruleToName(&rules[i])].ShadowedBy, rules[j])}
			}
		}
	}
	return slices.SortedFunc(maps.Values(result),
		func(sr1, sr2 ShadowedRule) int {
			return cmp.Or(
				cmp.Compare(sr1.Rule.PolicyName, sr2.Rule.PolicyName),
				cmp.Compare(sr1.Rule.RuleName, sr2.Rule.RuleName),
			)
		})
}

func ruleToName(r *types.Rule) name {
	return name{r.PolicyName, r.RuleName}
}

type Filter struct {
	VLANMin, VLANMax               uint16
	VRFs                           []string
	Protocols                      []types.Protocol
	SourceV4Prefix, SourceV6Prefix netip.Prefix
	SourceMinPort, SourceMaxPort   uint16
	DestV4Prefix, DestV6Prefix     netip.Prefix
	DestMinPort, DestMaxPort       uint16
}

func NewFilter() *Filter {
	return &Filter{
		SourceMinPort: 65535,
		SourceMaxPort: 0,
		DestMinPort:   65535,
		DestMaxPort:   0,
		VLANMin:       4096,
		VLANMax:       0,
	}
}

func (f *Filter) AddVLAN(vlan uint16) {
	f.VLANMin = min(f.VLANMin, vlan)
	f.VLANMax = max(f.VLANMax, vlan)
}

func (f *Filter) AddVRF(vrf string) {
	if vrf != "" && !slices.Contains(f.VRFs, vrf) {
		f.VRFs = append(f.VRFs, vrf)
	}
}

func (f *Filter) AddSource(prefix netip.Prefix, minPort, maxPort uint16) {
	if prefix.Addr().Is4() {
		f.SourceV4Prefix = makeCommonPrefix(f.SourceV4Prefix, prefix)
	} else {
		f.SourceV6Prefix = makeCommonPrefix(f.SourceV6Prefix, prefix)
	}
	f.SourceMinPort = min(f.SourceMinPort, minPort)
	f.SourceMaxPort = max(f.SourceMaxPort, maxPort)
}

func (f *Filter) AddDestination(prefix netip.Prefix, minPort, maxPort uint16) {
	if prefix.Addr().Is4() {
		f.DestV4Prefix = makeCommonPrefix(f.DestV4Prefix, prefix)
	} else {
		f.DestV6Prefix = makeCommonPrefix(f.DestV6Prefix, prefix)
	}
	f.DestMinPort = min(f.DestMinPort, minPort)
	f.DestMaxPort = max(f.DestMaxPort, maxPort)
}

func (f *Filter) AddProtocol(proto types.Protocol) {
	if !slices.Contains(f.Protocols, proto) {
		f.Protocols = append(f.Protocols, proto)
	}
}

func makeCommonPrefix(a, b netip.Prefix) netip.Prefix {
	switch {
	case !a.Addr().IsValid():
		return b
	case !b.Addr().IsValid():
		return a
	case a.Addr().Is4() != b.Addr().Is4():
		panic("Cannot mix IPv4 and IPV6 prefixes")
	}
	var common [16]byte
	aAddr, bAddr := a.Masked().Addr().As16(), b.Masked().Addr().As16()
	commonBits := 0
	numBits := min(a.Bits(), b.Bits())
	i := 0
	if a.Addr().Is4() {
		copy(common[:], aAddr[:12])
		i = 12
	}
	// Compare the prefix byte at a time
	for numBits >= 8 {
		if aAddr[i] != bAddr[i] {
			break
		}
		numBits -= 8
		commonBits += 8
		common[i] = aAddr[i]
		i++
	}
	numBits = min(8, numBits)

	// Compare the remaining bits
	if numBits > 0 {
		commonBits += min(numBits, bits.LeadingZeros8(aAddr[i]^bAddr[i]))
		// AND to get the shared bits. The returned prefix is masked.
		common[i] = aAddr[i] & bAddr[i]
	}
	commonAddr := netip.AddrFrom16(common).Unmap()
	return netip.PrefixFrom(commonAddr, commonBits).Masked()
}

package types

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// Table-based parsing of policies. The input is a text file
// containing a table header, separator and rows of rule data:
//
//   Rule     Action  Proto  Src         SrcPort  ...
//   example  Allow   TCP    10.0.0.0/8  80
//
// The column order matters. Whitespace does not, e.g.
// columns are separated by any number of spaces or tabs.

type column[T any] struct {
	name  string
	parse func(string, *T)
	get   func(*T) string
}

type table[T any] []column[T]

func (t table[T]) getColumnName(column int) string {
	return t[column].name
}

func (t table[T]) getColumn(x *T, column int) (name string, content string) {
	return t[column].name, t[column].get(x)
}

func (t table[T]) parsers() map[string]func(string, *T) {
	m := make(map[string]func(string, *T), len(t))
	for _, col := range t {
		m[col.name] = col.parse
	}
	return m
}

var policyTable = table[Rule]{
	{"Rule", func(s string, r *Rule) { r.RuleName = parseRuleName(s) }, func(r *Rule) string { return r.FullName() }},
	{"Proto", func(s string, r *Rule) {
		p := parseProtocol(s)
		r.Source.Protocol = p
		r.Destination.Protocol = p
	}, func(r *Rule) string { return string(r.Source.Protocol) }},
	{"Src", func(s string, r *Rule) { r.Source.Prefix = netip.MustParsePrefix(s) }, func(r *Rule) string { return r.Source.Prefix.String() }},
	{"SrcPort", func(s string, r *Rule) { r.Source.MinPort, r.Source.MaxPort = parsePort(s) }, func(r *Rule) string { return showPort(r.Source.MinPort, r.Source.MaxPort) }},
	{"SrcVLAN", func(s string, r *Rule) { r.Source.Vlan = parseVlan(s) }, func(r *Rule) string { return strconv.FormatUint(uint64(r.Source.Vlan), 10) }},
	{"SrcVRF", func(s string, r *Rule) { r.Source.Vrf = s }, func(r *Rule) string { return r.Source.Vrf }},
	{"Dst", func(s string, r *Rule) { r.Destination.Prefix = netip.MustParsePrefix(s) }, func(r *Rule) string { return r.Destination.Prefix.String() }},
	{"DstPort", func(s string, r *Rule) { r.Destination.MinPort, r.Destination.MaxPort = parsePort(s) }, func(r *Rule) string { return showPort(r.Destination.MinPort, r.Destination.MaxPort) }},
	{"DstVLAN", func(s string, r *Rule) { r.Destination.Vlan = parseVlan(s) }, func(r *Rule) string { return strconv.FormatUint(uint64(r.Destination.Vlan), 10) }},
	{"DstVRF", func(s string, r *Rule) { r.Destination.Vrf = s }, func(r *Rule) string { return r.Destination.Vrf }},
	{"Action", func(s string, r *Rule) { r.Action = parseAction(s) }, func(r *Rule) string { return string(r.Action) }},
}

func isRuleNameAllowedRune(r rune) bool {
	switch {
	case 'a' <= r && r <= 'z':
		return true
	case 'A' <= r && r <= 'Z':
		return true
	case '0' <= r && r <= '9':
		return true
	case r == '_' || r == '-' || r == '/':
		return true
	}
	return false
}

func parseRuleName(s string) string {
	runes := []rune(s)
	for i, r := range runes {
		if !isRuleNameAllowedRune(r) {
			runes[i] = '_'
		}
	}
	return string(runes)
}

func parseVlan(s string) uint16 {
	vlan, err := strconv.ParseUint(s, 10, 12)
	if err != nil {
		panic(err)
	}
	return uint16(vlan)
}

func parsePort(s string) (minPort, maxPort uint16) {
	if s == "" || s == "0" || s == "*" {
		return 0, 65535
	}
	if before, after, found := strings.Cut(s, "-"); found {
		v, err := strconv.ParseUint(before, 10, 16)
		if err != nil {
			panic(err)
		}
		minPort = uint16(v)
		v, err = strconv.ParseUint(after, 10, 16)
		if err != nil {
			panic(err)
		}
		maxPort = uint16(v)
		return
	}
	v, err := strconv.ParseInt(s, 10, 16)
	if err != nil {
		panic(err)
	}
	minPort = uint16(v)
	maxPort = minPort
	return
}

func parseProtocol(s string) Protocol {
	switch strings.ToLower(s) {
	case "tcp":
		return TCP
	case "udp":
		return UDP
	case "icmp":
		return ICMP
	default:
		panic(fmt.Sprintf("unrecognized protocol %q, expected 'tcp', 'udp' or 'icmp'", s))
	}
}

func parseAction(s string) Action {
	switch strings.ToLower(s) {
	case "allow":
		return Allow
	case "deny":
		return Deny
	default:
		panic(fmt.Sprintf("unrecognized policy action %q, expected 'allow' or 'deny'", s))
	}
}

func ParsePolicyTable(filename string, src io.Reader) (Policy, error) {
	rules, err := ParseTable[Rule](
		filename,
		src,
		policyTable.parsers(),
	)
	return Policy{
		Name:  filename,
		Rules: rules,
	}, err
}

func ParseTable[T any](
	filename string,
	r io.Reader,
	columnParsers map[string]func(string, *T),
) (rows []T, err error) {
	// To keep the parsing code simple we're using panic/recover for error handling.
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("%v", e)
		}
	}()

	s := bufio.NewScanner(r)

	// Parse the header to figure out column order and parsers for each
	// column.
	for s.Text() == "" {
		if !s.Scan() {
			return nil, errors.New("expected header")
		}
	}

	parsers := []func(string, *T){}
	for _, col := range strings.Fields(s.Text()) {
		p, ok := columnParsers[col]
		if !ok {
			return nil, fmt.Errorf("unrecognized column %q, expected one of %v", col, slices.Collect(maps.Keys(columnParsers)))
		}
		parsers = append(parsers, p)
	}

	lineNum := 2
	for s.Scan() {
		var r T
		line := strings.TrimSpace(s.Text())
		if line == "" {
			// Skip empty lines
			continue
		}
		for i, value := range strings.Fields(line) {
			if i >= len(parsers) {
				return nil, fmt.Errorf("%s:%d: too many columns", filename, lineNum)
			}
			parsers[i](value, &r)
		}
		rows = append(rows, r)

		lineNum++
	}
	return rows, s.Err()
}

var flowTable = table[Flow]{
	{"Proto", func(s string, f *Flow) {
		p := parseProtocol(s)
		f.Protocol = p
	}, func(f *Flow) string { return string(f.Protocol) }},
	{"Src", func(s string, f *Flow) { f.Source = netip.MustParseAddr(s) }, func(f *Flow) string { return f.Source.String() }},
	{"SrcPort", func(s string, f *Flow) { f.SourcePort, _ = parsePort(s) }, func(f *Flow) string { return showPort(f.SourcePort, f.SourcePort) }},
	{"SrcVLAN", func(s string, f *Flow) { f.SourceVlan = parseVlan(s) }, func(f *Flow) string { return strconv.FormatUint(uint64(f.SourceVlan), 10) }},
	{"SrcVRF", func(s string, f *Flow) { f.SourceVrf = s }, func(f *Flow) string { return f.SourceVrf }},
	{"Dst", func(s string, f *Flow) { f.Destination = netip.MustParseAddr(s) }, func(f *Flow) string { return f.Destination.String() }},
	{"DstPort", func(s string, f *Flow) { f.DestinationPort, _ = parsePort(s) }, func(f *Flow) string { return showPort(f.DestinationPort, f.DestinationPort) }},
	{"DstVLAN", func(s string, f *Flow) { f.DestinationVlan = parseVlan(s) }, func(f *Flow) string { return strconv.FormatUint(uint64(f.DestinationVlan), 10) }},
	{"DstVRF", func(s string, f *Flow) { f.DestinationVrf = s }, func(f *Flow) string { return f.DestinationVrf }},
	{"Verdict", func(s string, f *Flow) {
		switch strings.ToLower(s) {
		case "allow":
			f.Action = Allow
		case "deny":
			f.Action = Deny
		default:
			f.Action = Unknown
		}
	}, func(f *Flow) string { return string(f.Action) }},
}

func ParseFlowTable(filename string, src io.Reader) ([]Flow, error) {
	return ParseTable[Flow](
		filename,
		src,
		flowTable.parsers(),
	)
}

package types

import (
	"bytes"
	"cmp"
	"fmt"
	"io"
	"net/netip"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

type Protocol string

const (
	TCP  = Protocol("TCP")
	UDP  = Protocol("UDP")
	ICMP = Protocol("ICMP")
)

type Action string

const (
	Allow   = Action("allow")
	Deny    = Action("deny")
	NoMatch = Action("no-match")
	Unknown = Action("unknown")
)

type Subject struct {
	Prefix           netip.Prefix
	MinPort, MaxPort uint16
	Vlan             uint16
	Vrf              string
	Protocol         Protocol
}

func (s *Subject) NumPorts() int {
	return 1 + int(s.MaxPort) - int(s.MinPort)
}

func (s *Subject) Ports() string {
	return showPort(s.MinPort, s.MaxPort)
}

type Rule struct {
	Index               int
	PolicyName          string
	RuleName            string
	Source, Destination Subject
	Action              Action
	Highlight           bool
}

func (r *Rule) FullName() string {
	if r.PolicyName != "" {
		return r.PolicyName + "/" + r.RuleName
	}
	return r.RuleName
}

func (r Rule) Compare(other Rule) int {
	return cmp.Or(
		r.CompareContent(other),
		cmp.Compare(r.PolicyName, other.PolicyName),
		cmp.Compare(r.RuleName, other.RuleName),
	)
}

func (r Rule) String() string {
	var buf bytes.Buffer
	r.PrintRule(&buf)
	b := buf.Bytes()
	b = bytes.ReplaceAll(b, []byte{'\t'}, []byte{' '})
	return string(b[:len(b)-1])
}

func (r *Rule) PrintRule(w io.Writer) error {
	name := r.RuleName
	if r.PolicyName != "" {
		name = r.PolicyName + "/" + r.RuleName
	}
	_, err := fmt.Fprintf(w,
		"%s\t%s\t%s\t%s\t%d\t%s\t%s\t%s\t%d\t%s\t%s\n",
		name,
		r.Source.Protocol,
		r.Source.Prefix,
		ShowPort(r.Source.MinPort, r.Source.MaxPort),
		r.Source.Vlan,
		r.Source.Vrf,
		r.Destination.Prefix,
		ShowPort(r.Destination.MinPort, r.Destination.MaxPort),
		r.Destination.Vlan,
		r.Destination.Vrf,
		r.Action)
	return err
}

func ShowPort(minPort, maxPort uint16) string {
	switch {
	case minPort == maxPort:
		return fmt.Sprintf("%d", minPort)
	case minPort == 0 && maxPort == 65535:
		return "*"
	default:
		return fmt.Sprintf("%d-%d", minPort, maxPort)
	}
}

func (r *Rule) CompareContent(other Rule) int {
	switch {
	case r.Action == Deny && other.Action != Deny:
		return -1
	case other.Action == Deny && r.Action != Deny:
		return 1
	}
	return cmp.Or(
		cmp.Compare(r.Source.Vrf, other.Source.Vrf),
		cmp.Compare(r.Destination.Vrf, other.Destination.Vrf),
		cmp.Compare(r.Source.Vlan, other.Source.Vlan),
		cmp.Compare(r.Destination.Vlan, other.Destination.Vlan),
		PrefixCompare(r.Source.Prefix, other.Source.Prefix),
		PrefixCompare(r.Destination.Prefix, other.Destination.Prefix),
		cmp.Compare(other.Source.NumPorts(), r.Source.NumPorts()),
		cmp.Compare(other.Destination.NumPorts(), r.Destination.NumPorts()),
		cmp.Compare(r.Source.Protocol, other.Source.Protocol),
	)
}

type Policy struct {
	Name       string
	Generation int64
	Rules      []Rule
}

// Clear implements tview.TableContent.
func (p Policy) Clear() {
	panic("unimplemented")
}

var (
	headerStyle         = tcell.Style{}.Bold(false).Underline(tcell.UnderlineStyleSolid)
	headerSelectedStyle = tcell.Style{}.Bold(true).Underline(tcell.UnderlineStyleSolid)
	highlightColor      = tcell.ColorValid | tcell.ColorIsRGB | 0x405040
)

// GetCell implements tview.TableContent.
func (p Policy) GetCell(row int, column int) *tview.TableCell {
	if row < 0 || row >= 1+len(p.Rules) || column < 0 || column >= len(policyTable) {
		return nil
	}
	if row == 0 {
		return tview.NewTableCell(policyTable.getColumnName(column)).
			SetStyle(headerStyle).SetSelectable(false)
	}
	rule := &p.Rules[row-1]
	bgColor := tcell.ColorBlack
	if rule.Highlight {
		bgColor = highlightColor
	}

	name, content := policyTable.getColumn(rule, column)
	cell := tview.NewTableCell(content).SetReference(rule).SetBackgroundColor(bgColor)

	switch name {
	case "Action":
		switch rule.Action {
		case Allow:
			cell.SetTextColor(tcell.ColorGreen)
		case Deny:
			cell.SetTextColor(tcell.ColorRed)
		}
	}
	return cell
}

// GetColumnCount implements tview.TableContent.
func (p Policy) GetColumnCount() int {
	return len(policyTable)
}

// GetRowCount implements tview.TableContent.
func (p Policy) GetRowCount() int {
	return 1 + len(p.Rules)
}

// InsertColumn implements tview.TableContent.
func (p Policy) InsertColumn(_ int) {
	panic("unimplemented")
}

// InsertRow implements tview.TableContent.
func (p Policy) InsertRow(_ int) {
	panic("unimplemented")
}

// RemoveColumn implements tview.TableContent.
func (p Policy) RemoveColumn(_ int) {
	panic("unimplemented")
}

// RemoveRow implements tview.TableContent.
func (p Policy) RemoveRow(_ int) {
	panic("unimplemented")
}

// SetCell implements tview.TableContent.
func (p Policy) SetCell(_ int, _ int, _ *tview.TableCell) {
	panic("unimplemented")
}

var _ tview.TableContent = Policy{}

type Flow struct {
	Source                      netip.Addr
	Destination                 netip.Addr
	SourcePort, DestinationPort uint16
	SourceVlan, DestinationVlan uint16
	SourceVrf, DestinationVrf   string
	Protocol                    Protocol
	Action                      Action
}

func (f *Flow) String() string {
	return fmt.Sprintf("%s:%d -> %s:%d %s %s",
		f.Source, f.SourcePort,
		f.Destination, f.DestinationPort,
		f.Protocol,
		f.Action,
	)
}

type FlowDiff struct {
	Flow      *Flow
	I1, I2    int
	V1, V2    Action
	Highlight bool
}

func PrefixCompare(p, p2 netip.Prefix) int {
	if c := cmp.Compare(p.Addr().BitLen(), p2.Addr().BitLen()); c != 0 {
		return c
	}
	if c := cmp.Compare(p.Bits(), p2.Bits()); c != 0 {
		return c
	}
	return p.Addr().Compare(p2.Addr())
}

package types

import (
	"regexp"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

type FlowDiffTable struct {
	tview.TableContentReadOnly

	filter       *regexp.Regexp
	filterColumn int

	allFlowDiffs      []FlowDiff
	filteredFlowDiffs []FlowDiff
}

func (fdt *FlowDiffTable) applyFilter() {
	if fdt.filter == nil {
		fdt.filteredFlowDiffs = fdt.allFlowDiffs
		return
	}
	fdt.filteredFlowDiffs = fdt.filteredFlowDiffs[:0]
	for _, f := range fdt.allFlowDiffs {
		_, content := flowTable.getColumn(f.Flow, fdt.filterColumn)
		if fdt.filter.MatchString(content) {
			fdt.filteredFlowDiffs = append(fdt.filteredFlowDiffs, f)
		}
	}
}

func (fdt *FlowDiffTable) NextFilterColumn() {
	fdt.filterColumn++
	if fdt.filterColumn >= len(flowTable) {
		fdt.filterColumn = 0
	}
}

func (fdt *FlowDiffTable) SetFilter(filter string) error {
	re, err := regexp.Compile(filter)
	if err != nil {
		return err
	}
	fdt.filter = re
	fdt.applyFilter()
	return nil
}

func (fdt *FlowDiffTable) Reset() {
	fdt.allFlowDiffs = nil
	fdt.filteredFlowDiffs = nil
}

func (fdt *FlowDiffTable) Append(fds ...FlowDiff) {
	for _, fd := range fds {
		fdt.allFlowDiffs = append(fdt.allFlowDiffs, fd)
		if fdt.filter != nil {
			_, content := flowTable.getColumn(fd.Flow, fdt.filterColumn)
			if fdt.filter.MatchString(content) {
				fdt.filteredFlowDiffs = append(fdt.filteredFlowDiffs, fd)
			}
		} else {
			fdt.filteredFlowDiffs = fdt.allFlowDiffs
		}
	}
}

func (fdt *FlowDiffTable) GetCell(row, column int) *tview.TableCell {
	if row < 0 || row >= 1+len(fdt.filteredFlowDiffs) || column < 0 || column >= 2+len(flowTable) {
		return nil
	}
	delta := column - len(flowTable)
	if row == 0 {
		switch delta {
		case 0:
			return tview.NewTableCell("Old").SetStyle(headerStyle).SetSelectable(false)
		case 1:
			return tview.NewTableCell("New").SetStyle(headerStyle).SetSelectable(false)
		default:
			style := headerStyle
			if fdt.filterColumn == column {
				style = headerSelectedStyle
			}
			return tview.NewTableCell(flowTable.getColumnName(column)).SetStyle(style).SetSelectable(false)
		}
	}

	fd := &fdt.filteredFlowDiffs[row-1]
	v1 := fd.V1
	v2 := fd.V2

	var cell *tview.TableCell
	switch delta {
	case 0:
		cell = tview.NewTableCell(string(v1))
		if v2 != NoMatch && v1 != v2 {
			cell.SetAttributes(tcell.AttrStrikeThrough)
		}
		switch v1 {
		case Allow:
			cell.SetTextColor(tcell.ColorGreen)
		case Deny:
			cell.SetTextColor(tcell.ColorRed)
		}
	case 1:
		cell = tview.NewTableCell(string(v2))
		switch v2 {
		case Allow:
			cell.SetTextColor(tcell.ColorGreen)
		case Deny:
			cell.SetTextColor(tcell.ColorRed)
		}
	default:
		flow := fd.Flow
		_, content := flowTable.getColumn(flow, column)
		cell = tview.NewTableCell(content).SetReference(flow)
	}
	if fd.Highlight {
		cell.SetBackgroundColor(highlightColor)
	}
	cell.SetReference(fd)
	return cell
}

// GetColumnCount implements tview.TableContent.
func (fdt *FlowDiffTable) GetColumnCount() int {
	return 2 + len(flowTable)
}

// GetRowCount implements tview.TableContent.
func (fdt *FlowDiffTable) GetRowCount() int {
	return 1 + len(fdt.filteredFlowDiffs)
}

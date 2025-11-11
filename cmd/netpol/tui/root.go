package tui

import (
	"context"
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"io"
	"os"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"github.com/spf13/cobra"

	"github.com/isovalent/hubble-fgs/cmd/netpol/model"
	"github.com/isovalent/hubble-fgs/cmd/netpol/timescape"
	"github.com/isovalent/hubble-fgs/cmd/netpol/types"
)

var selectedStyle = tcell.Style{}.Background(tcell.ColorValid | tcell.ColorIsRGB | 0x505050)

var Command = func() *cobra.Command {
	var tsConfig timescape.Config
	cmd := &cobra.Command{
		Use:   "tui",
		Short: "Text-mode user interface for validating policy changes",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			err := tsConfig.Parse(cmd.Flags())
			if err != nil {
				return err
			}
			tsClient, err := timescape.NewClient(tsConfig)
			if err != nil {
				return err
			}
			runTUI(tsClient, args[0], args[1])
			return nil
		},
	}
	tsConfig.Flags(cmd.Flags())
	return cmd
}()

func runTUI(tsClient *timescape.Client, prodDir, stagingDir string) {

	grid := tview.NewGrid()
	grid.SetColumns(-1)
	grid.SetRows(-1, -1, -1)

	var tabFlows, tabV1, tabV2 *tview.Table

	tabV1 = tview.NewTable()
	tabV1.SetBorder(true).SetTitle("Old policy")
	tabV1.SetFixed(1, 11)
	tabV1.SetSelectable(false, false)
	tabV1.SetSelectedStyle(selectedStyle)
	tabV1.SetFocusFunc(func() {
		tabV1.SetSelectable(true, false)
		for v1row := range tabV1.GetRowCount() {
			if v1row == 0 {
				continue
			}
			v1 := tabV1.GetCell(v1row, 0).GetReference()
			if v1 != nil {
				v1.(*types.Rule).Highlight = false
			}
		}
	})
	tabV1.SetBlurFunc(func() {
		tabV1.SetSelectable(false, false)
	})
	tabV1.SetSelectionChangedFunc(func(row, column int) {
		if row < 1 {
			return
		}
		ref := tabV1.GetCell(row, column).GetReference()
		if ref == nil {
			return
		}
		// Unset the highlights
		for v2row := range tabV2.GetRowCount() {
			if v2row == 0 {
				continue
			}
			v2 := tabV2.GetCell(v2row, 0).GetReference()
			if v2 != nil {
				v2.(*types.Rule).Highlight = false
			}
		}
		for frow := range tabFlows.GetRowCount() {
			if frow == 0 {
				continue
			}
			fref := tabFlows.GetCell(frow, 0).GetReference()
			if fref == nil {
				continue
			}
			flow := fref.(*types.FlowDiff)
			flow.Highlight = false

			if flow.I1 == row-1 {
				flow.Highlight = true

				// Also highlight the V2 policy that also matched this
				if flow.I2 >= 0 {
					v2 := tabV2.GetCell(flow.I2+1, 0).GetReference()
					if v2 != nil {
						v2.(*types.Rule).Highlight = true
					}
				}
			}
		}
	})
	grid.AddItem(tabV1, 0, 0, 1, 1, 0, 0, true)

	tabV2 = tview.NewTable()
	tabV2.SetBorder(true).SetTitle("New policy")
	tabV2.SetFixed(1, 11)
	tabV2.SetSelectable(false, false)
	tabV2.SetSelectedStyle(selectedStyle)
	tabV2.SetFocusFunc(func() {
		tabV2.SetSelectable(true, false)
		for v2row := range tabV2.GetRowCount() {
			if v2row == 0 {
				continue
			}
			v2 := tabV2.GetCell(v2row, 0).GetReference()
			if v2 != nil {
				v2.(*types.Rule).Highlight = false
			}
		}
	})
	tabV2.SetBlurFunc(func() {
		tabV2.SetSelectable(false, false)
	})
	tabV2.SetSelectionChangedFunc(func(row, column int) {
		if row < 1 {
			return
		}
		ref := tabV2.GetCell(row, column).GetReference()
		if ref == nil {
			return
		}
		// Unset the highlights
		for v1row := range tabV1.GetRowCount() {
			if v1row == 0 {
				continue
			}
			v1 := tabV1.GetCell(v1row, 0).GetReference()
			if v1 != nil {
				v1.(*types.Rule).Highlight = false
			}
		}
		// Highlight the flows that match this policy.
		for frow := range tabFlows.GetRowCount() {
			if frow == 0 {
				continue
			}
			fref := tabFlows.GetCell(frow, 0).GetReference()
			if fref == nil {
				continue
			}
			flow := fref.(*types.FlowDiff)
			flow.Highlight = false
			if flow.I2 == row-1 {
				flow.Highlight = true

				// Also highlight the V1 policy that also matched this
				if flow.I1 >= 0 {
					v1 := tabV1.GetCell(flow.I1+1, 0).GetReference()
					if v1 != nil {
						v1.(*types.Rule).Highlight = true
					}
				}
			}
		}
	})
	grid.AddItem(tabV2, 1, 0, 1, 1, 0, 0, false)

	tabFlows = tview.NewTable()
	tabFlows.SetBorder(true).SetTitle("Connections with verdict differences (updates every 10s)")
	tabFlows.SetFixed(1, 12)
	tabFlows.SetFocusFunc(func() {
		if tabFlows.GetRowCount() > 1 {
			tabFlows.SetSelectable(true, false)
		}
		for frow := range tabFlows.GetRowCount() {
			if frow == 0 {
				continue
			}
			fref := tabFlows.GetCell(frow, 0).GetReference()
			if fref == nil {
				continue
			}
			flow := fref.(*types.FlowDiff)
			flow.Highlight = false
		}
	})
	tabFlows.SetSelectable(false, false)
	tabFlows.SetSelectedStyle(selectedStyle)
	tabFlows.SetBlurFunc(func() {
		tabFlows.SetSelectable(false, false)
	})
	tabFlows.SetSelectionChangedFunc(func(row, column int) {
		if row < 1 {
			return
		}

		ref := tabFlows.GetCell(row, column).GetReference()
		if ref == nil {
			return
		}
		diff := ref.(*types.FlowDiff)

		for v1row := range tabV1.GetRowCount() {
			if v1row == 0 {
				continue
			}
			v1 := tabV1.GetCell(v1row, 0).GetReference()
			if v1 != nil {
				v1.(*types.Rule).Highlight = diff.I1 == v1row-1
			}
		}
		for v2row := range tabV2.GetRowCount() {
			if v2row == 0 {
				continue
			}
			v2 := tabV2.GetCell(v2row, 0).GetReference()
			if v2 != nil {
				v2.(*types.Rule).Highlight = diff.I2 == v2row-1
			}
		}
	})
	grid.AddItem(tabFlows, 2, 0, 1, 1, 0, 0, false)

	flexbox := tview.NewFlex().SetDirection(tview.FlexRow)
	flexbox.AddItem(grid, 0, 1, false)

	usage := tview.NewTextView().
		SetDynamicColors(true).
		SetText(`[red]Escape[white]: Quit [red]Tab[white]: Change focus [red]Ctrl-R[white]: Reload policies [red]Ctrl-N[white]: Next connection search column | Select rule or connection to highlight matches`)
	flexbox.AddItem(usage, 1, 1, true)

	var flowDiffTable types.FlowDiffTable
	tabFlows.SetContent(&flowDiffTable)

	var search *tview.InputField
	placeholderStyle := tcell.StyleDefault.
		Background(tcell.ColorBlack).
		Foreground(tcell.ColorGrey)
	search = tview.NewInputField().
		SetLabel("Filter flows: ").
		SetPlaceholderStyle(placeholderStyle).
		SetPlaceholder("<regexp>").
		SetFieldBackgroundColor(tcell.ColorDarkGreen).
		SetDoneFunc(func(_ tcell.Key) {
			text := search.GetText()
			if err := flowDiffTable.SetFilter(text); err != nil {
				search.SetFieldBackgroundColor(tcell.ColorDarkRed)
			} else {
				search.SetFieldBackgroundColor(tcell.ColorDarkGreen)
			}
		})
	flexbox.AddItem(search, 1, 1, false)

	app := tview.NewApplication()
	app.EnableMouse(true)
	app.SetRoot(flexbox, true)

	focus := 0
	focusElements := []tview.Primitive{
		search, tabV1, tabV2, tabFlows,
	}
	cycleFocus := func() {
		focus++
		if focus >= len(focusElements) {
			focus = 0
		}
		app.SetFocus(focusElements[focus])
	}

	v1, v2, filter := loadAndUpdate(prodDir, stagingDir, tabV1, tabV2)

	app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyEscape {
			app.Stop()
			return nil
		} else if event.Key() == tcell.KeyTab {
			cycleFocus()
		} else if event.Key() == tcell.KeyCtrlN {
			flowDiffTable.NextFilterColumn()
		} else if event.Key() == tcell.KeyCtrlR {
			v1, v2, filter = loadAndUpdate(prodDir, stagingDir, tabV1, tabV2)
			flowDiffTable.Reset()
			tabFlows.SetSelectable(false, false)
			tabV1.SetTitle("Old policy (reloaded!)")
			tabV2.SetTitle("New policy (reloaded!)")
			go app.QueueUpdateDraw(func() {
				// Blocks the event loop but it's fine.
				time.Sleep(200 * time.Millisecond)
				tabV1.SetTitle("Old policy")
				tabV2.SetTitle("New policy")
			})
		}
		return event
	})

	window := 10 * time.Second

	go func() {
		until := time.Now()
		since := until.Add(-window)
		bloom := newFlowBloom()
		for {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			flows, err := tsClient.GetConnections(
				ctx,
				since, until, filter)
			cancel()
			if err != nil {
				app.Stop()
				fmt.Fprintf(os.Stderr, "Error fetching connections: %s\n", err)
				return
			}
			flowsDedupped := func(yield func(types.Flow) bool) {
				for f := range flows {
					if bloom.contains(&f) {
						continue
					}
					bloom.insert(&f)
					if !yield(f) {
						return
					}
				}
			}
			diff := model.Diff(
				v1,
				v2,
				flowsDedupped,
			)
			app.QueueUpdateDraw(func() {
				flowDiffTable.Append(diff.Flows...)
				if len(diff.Flows) > 0 {
					// Don't enable selection until there's actual data. tview seems to go into a loop
					// otherwise.
					tabFlows.SetSelectable(true, false)
				}
			})
			// Shift the window forward and wait.
			since = since.Add(window)
			until = until.Add(window)
			time.Sleep(10 * time.Second)
		}
	}()

	app.Run()
}

func loadAndUpdate(prodDir, stagingDir string, v1tab, v2tab *tview.Table) (v1, v2 *model.Model, filter *model.Filter) {
	prodPolicy, err := types.ParsePolicyDir(prodDir)
	if err != nil {
		panic("TODO")
	}
	stagingPolicy, err := types.ParsePolicyDir(stagingDir)
	if err != nil {
		panic("TODO")
	}
	prodPolicy, oldPolicy := types.SplitPolicies(prodPolicy, stagingPolicy)
	oldRules, newRules, filter := model.ComputeMinimal(prodPolicy, oldPolicy, stagingPolicy)
	v1, err = model.NewModel(types.Policy{Rules: oldRules})
	if err != nil {
		panic(err)
	}
	v2, err = model.NewModel(types.Policy{Rules: newRules})
	if err != nil {
		panic(err)
	}
	v1tab.SetContent(types.Policy{Rules: oldRules})
	v2tab.SetContent(types.Policy{Rules: newRules})
	return v1, v2, filter
}

// flowBloom is a simple bloom filter to check if we've likely seen this flow already.
type flowBloom struct {
	numBits uint64
	bits    []byte
}

func newFlowBloom() *flowBloom {
	// With 500k bits (61KB), 3 hash functions and 1000 items the probability of a false
	// positive is 1 in 4.6 million.
	const numBits = 500_000
	return &flowBloom{
		numBits: numBits,
		bits:    make([]byte, (numBits+7)/8),
	}
}

func (fb *flowBloom) hashFlow(f *types.Flow) (h1v, h2v, h3v uint64) {
	writeFlow := func(f *types.Flow, w io.Writer) {
		w.Write(f.Source.AsSlice())
		w.Write(f.Destination.AsSlice())
		w.Write(binary.NativeEndian.AppendUint16(nil, f.SourcePort))
		w.Write(binary.NativeEndian.AppendUint16(nil, f.SourceVlan))
		w.Write([]byte(f.SourceVrf))
		w.Write(binary.NativeEndian.AppendUint16(nil, f.DestinationPort))
		w.Write(binary.NativeEndian.AppendUint16(nil, f.DestinationVlan))
		w.Write([]byte(f.DestinationVrf))
		w.Write([]byte(f.Protocol))
	}
	h1 := fnv.New64()
	writeFlow(f, h1)
	h1v = h1.Sum64() % fb.numBits
	h2 := fnv.New64a()
	writeFlow(f, h2)
	h2v = h2.Sum64() % fb.numBits
	h3v = (h1v + h2v) % fb.numBits
	return

}

func (fb *flowBloom) insert(f *types.Flow) {
	h1v, h2v, h3v := fb.hashFlow(f)
	fb.bits[h1v/8] |= 1 << (h1v % 8)
	fb.bits[h2v/8] |= 1 << (h2v % 8)
	fb.bits[h3v/8] |= 1 << (h3v % 8)
}

func (fb *flowBloom) contains(f *types.Flow) bool {
	h1v, h2v, h3v := fb.hashFlow(f)
	return fb.bits[h1v/8]&(1<<(h1v%8)) != 0 ||
		fb.bits[h2v/8]&(1<<(h2v%8)) != 0 ||
		fb.bits[h3v/8]&(1<<(h3v%8)) != 0
}

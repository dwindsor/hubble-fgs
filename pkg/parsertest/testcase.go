//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.
//

package parsertest

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"path"
	"sort"
	"text/scanner"
	"unsafe"

	"github.com/isovalent/hubble-fgs/pkg/api"
	"github.com/isovalent/hubble-fgs/pkg/bpf"
	"github.com/yalue/native_endian"
)

//
// Test case and step definitions
//

type TestCase struct {
	// Name of the test case. Derived from filename.
	Name string

	// Test tags
	Tags []string

	// The test steps to execute.
	Steps []TestStep
}

func (tc *TestCase) IsBroken() bool {
	sort.Strings(tc.Tags)
	return sort.SearchStrings(tc.Tags, "broken") != len(tc.Tags)
}

type TestStepError struct {
	Position    scanner.Position
	Description string
	Inner       error
}

func (e *TestStepError) Error() string {
	return fmt.Sprintf("%s error at %s: %s", e.Description, e.Position, e.Inner)
}

type TestStep interface {
	Exec(ctx *TestContext) *TestStepError
}

type TestStepPacket struct {
	Position    scanner.Position
	Description string
	Payload     []byte
}

//
// Egress step
//

type TestStepEgress TestStepPacket

func (e *TestStepEgress) Exec(ctx *TestContext) *TestStepError {
	ctx.t.Logf("EGRESS  %-20s => %d bytes\n", e.Description, len(e.Payload))
	if err := ctx.emitEgress(e.Payload); err != nil {
		return &TestStepError{
			Position:    e.Position,
			Description: "INGRESS",
			Inner:       err,
		}
	}
	return nil
}

//
// Ingress step
//

type TestStepIngress TestStepPacket

func (e *TestStepIngress) Exec(ctx *TestContext) *TestStepError {
	ctx.t.Logf("INGRESS %-20s <= %d bytes\n", e.Description, len(e.Payload))
	if err := ctx.emitIngress(e.Payload); err != nil {
		return &TestStepError{
			Position:    e.Position,
			Description: "INGRESS",
			Inner:       err,
		}
	}
	return nil
}

//
// Event matching step
//

type TestStepEvent struct {
	Position scanner.Position
	Op       int
	Matchers []AnnMatcher
}

func (e *TestStepEvent) Exec(ctx *TestContext) *TestStepError {
	event, ok := ctx.waitForEvent(e.Op)
	if !ok {
		return &TestStepError{e.Position, "waitForEvent", fmt.Errorf("EOF on op %d event channel", e.Op)}
	}
	r := bytes.NewReader(event)
	ctx.t.Logf("EVENT op=%d bytes=%d\n", e.Op, len(event))
	for _, m := range e.Matchers {
		_, err := m.Match(ctx, r)
		if err != nil {
			return &TestStepError{m.Position, "match", err}
		}
	}

	n, _ := io.Copy(io.Discard, r)
	if n != 0 {
		return &TestStepError{e.Position, "match", fmt.Errorf("%d unmatched bytes remain", n)}
	}

	return nil
}

//
// Multiple unordered event matching step
//

type Subevent struct {
	Position scanner.Position
	Matchers []AnnMatcher
}

func (s *Subevent) Match(ctx *TestContext, event []byte) *TestStepError {
	r := bytes.NewReader(event)
	for _, m := range s.Matchers {
		_, err := m.Match(ctx, r)
		if err != nil {
			return &TestStepError{m.Position, "match", err}
		}
	}
	return nil
}

type TestStepEvents struct {
	Position  scanner.Position
	Op        int
	Subevents []*Subevent
}

func (e *TestStepEvents) Exec(ctx *TestContext) *TestStepError {
	remaining := make(map[int]*Subevent)
	for i, s := range e.Subevents {
		remaining[i] = s
	}

	for len(remaining) > 0 {
		event, ok := ctx.waitForEvent(e.Op)
		if !ok {
			return &TestStepError{e.Position, "waitForEvent", fmt.Errorf("EOF on op %d event channel", e.Op)}
		}
		ctx.t.Logf("EVENT op=%d bytes=%d\n", e.Op, len(event))

		var lastError *TestStepError
		for i, s := range remaining {
			lastError = s.Match(ctx, event)
			if lastError == nil {
				delete(remaining, i)
				break
			}
		}
		if lastError != nil {
			return lastError
		}
	}
	return nil
}

//
// Event dumping step
//

type TestStepEventDump struct {
	Position scanner.Position
	Op       int
	OpName   string
}

func (e *TestStepEventDump) Exec(ctx *TestContext) *TestStepError {
	event, ok := ctx.waitForEvent(e.Op)
	if !ok {
		return &TestStepError{e.Position, "waitForEvent", nil}
	}

	fmt.Printf("-- EVENTDUMP %s --\n", e.OpName)

	fmt.Printf("EVENT %s\n", e.OpName)

	var common api.MsgCommon
	err := binary.Read(bytes.NewReader(event), native_endian.NativeEndian(), &common)
	if err != nil {
		return &TestStepError{e.Position, "Read MsgCommon", err}
	}

	fmt.Printf("  ## Common\n")
	fmt.Printf("  $ %02x 00 00 00 # op + pad\n", common.Op)
	fmt.Printf("  h4 %-10d # size\n", common.Size)
	fmt.Printf("  ? 8           # ktime\n")
	event = event[unsafe.Sizeof(common):]

	for i := range event {
		if (i % 16) == 0 {
			fmt.Printf("\n  $")
		}
		fmt.Printf(" %02x", event[i])
	}
	fmt.Printf("\n")
	fmt.Printf("END\n")

	fmt.Printf("-- cut to here--\n")

	return nil
}

const (
	CLOSE_SERVER = iota
	CLOSE_CLIENT
	CLOSE_LISTENER
	CLOSE_ALL
)

type TestStepClose struct {
	Position scanner.Position
	which    int
}

func (e *TestStepClose) Exec(ctx *TestContext) *TestStepError {
	var err error
	switch e.which {
	case CLOSE_SERVER:
		err = ctx.ingressConn.Close()
	case CLOSE_CLIENT:
		err = ctx.egressConn.Close()
	case CLOSE_LISTENER:
		err = ctx.listener.Close()
	case CLOSE_ALL:
		err = ctx.closeConns()
	}
	if err != nil {
		return &TestStepError{e.Position, "CLOSE", err}
	}
	return nil
}

//
// Assertion step
//

type AssertType int

const (
	AssertMapCount = iota
)

type TestStepAssert struct {
	Position scanner.Position
	MapName  string
	Type     AssertType
	Count    int
}

func (a *TestStepAssert) Exec(ctx *TestContext) *TestStepError {
	m, err := bpf.OpenMap(path.Join(bpf.MapPrefixPath(), a.MapName))
	if err != nil {
		return &TestStepError{a.Position, "ASSERT MAP", err}
	}

	switch a.Type {
	case AssertMapCount:
		count, err := m.Count()
		if err != nil {
			return &TestStepError{a.Position, "ASSERT MAP", fmt.Errorf("failed to get map count: %w", err)}
		}
		if a.Count != count {
			return &TestStepError{a.Position, "ASSERT MAP",
				fmt.Errorf("expected %d elements, but map %s has %d element(s)", a.Count, a.MapName, count)}
		}
	}
	return nil
}

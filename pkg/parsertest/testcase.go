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
	"fmt"
	"io"
	"text/scanner"
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

	fmt.Printf("EVENT %s", e.OpName)

	for i := range event {
		if (i % 16) == 0 {
			fmt.Printf("\n  $")
		}
		fmt.Printf(" %02x", event[i])
	}
	fmt.Printf("\n")
	fmt.Printf("  # ^ %d bytes\n", len(event))
	fmt.Printf("END\n")

	fmt.Printf("-- cut to here--\n")

	return nil
}

const (
	CLOSE_SERVER = iota
	CLOSE_CLIENT
	CLOSE_BOTH
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
	case CLOSE_BOTH:
		err = ctx.closeConns()
	}
	if err != nil {
		return &TestStepError{e.Position, "CLOSE", err}
	}
	return nil
}

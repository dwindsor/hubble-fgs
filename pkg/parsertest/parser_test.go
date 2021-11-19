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
	"testing"

	"github.com/isovalent/hubble-fgs/pkg/api"
)

var expectedPacketPayload = []byte{
	22, 22, 63, 170, 139, 122, 23, 211, 11, 59, 222, 127, 105, 188, 168, 80, 55,
	98, 60, 170, 139, 122, 23, 211, 11, 59, 222, 127, 105, 188, 168, 80, 55, 98,
	60, 170, 139, 122, 23, 211, 11, 59, 222, 127, 105, 188, 168, 80, 55, 98, 60,
	185, 127, 63, 22, 199, 255, 255, 255, 255, 255, 255, 199, 127, 0, 0, 1, 0, 0,
	0, 0, 255, 255, 255, 255, 102, 111, 111, 98, 97, 114, 102, 111, 111, 98, 97,
	114, 98, 97, 122, 13, 10, 10, 97, 32, 114, 97, 119, 32, 115, 116, 114, 105,
	110, 103, 10, 1, 63, 18, 31, 104, 101, 108, 108, 111, 119, 111, 114, 108, 100,
}

func TestParse(t *testing.T) {

	tc, err := ParseTestCase("testdata/parser-testfile")
	if err != nil {
		t.Errorf("parse of parser-testfile failed: %s", err)
	}
	if tc == nil {
		t.Fatalf("nil *TestCase")
	}

	if tc.Name != "parser-testfile" {
		t.Fatalf("expected parser-testfile as name, but got %s", tc.Name)
	}

	if len(tc.Tags) != 2 || tc.Tags[0] != "foo" || tc.Tags[1] != "bar" {
		t.Fatalf("expected tags 'foo', 'bar', got tags %s", tc.Tags)
	}

	if len(tc.Steps) != 4 {
		t.Errorf("expected 4 steps, got %d steps", len(tc.Steps))
	}

	if egressStep, ok := tc.Steps[0].(*TestStepEgress); !ok {
		t.Errorf("first step was not EGRESS step: %T", tc.Steps[0])
	} else {
		expectedLine := 4
		if egressStep.Position.Line != expectedLine {
			t.Errorf("expected EGRESS step to be defined at line %d, but it was %d",
				expectedLine, egressStep.Position.Line)
		}

		if egressStep.Description != "test egress" {
			t.Errorf("expected \"test egress\" as step description, got %s", egressStep.Description)
		}

		if !bytes.Equal(egressStep.Payload, expectedPacketPayload) {
			t.Errorf("unexpected payload: %v", egressStep.Payload)
		}
	}

	if ingressStep, ok := tc.Steps[1].(*TestStepIngress); !ok {
		t.Errorf("second step was not EGRESS step: %T", tc.Steps[1])
	} else {
		expectedLine := 35
		if ingressStep.Position.Line != expectedLine {
			t.Errorf("expected INGRESS step to be defined at line %d, but it was %d",
				expectedLine, ingressStep.Position.Line)
		}

		if ingressStep.Description != "test ingress" {
			t.Errorf("expected \"test ingress\" as step description, got %s", ingressStep.Description)
		}

		if !bytes.Equal(ingressStep.Payload, expectedPacketPayload) {
			t.Errorf("unexpected payload: %v", ingressStep.Payload)
		}
	}

	if eventStep, ok := tc.Steps[2].(*TestStepEvent); !ok {
		t.Errorf("third step was not EVENT step: %T", tc.Steps[2])
	} else {
		expectedLine := 67
		if eventStep.Position.Line != expectedLine {
			t.Errorf("expected EVENT step to be defined at line %d, but it was %d",
				expectedLine, eventStep.Position.Line)
		}

		if eventStep.Op != api.MSG_OP_TLS {
			t.Errorf("expected op %d, got %d", api.MSG_OP_TLS, eventStep.Op)
		}

		r := bytes.NewReader(expectedPacketPayload)
		var ctx TestContext
		for _, m := range eventStep.Matchers {
			_, err := m.Match(&ctx, r)
			if err != nil {
				t.Errorf("matcher at %s failed: %s",
					m.Position, err)
			}
		}
	}

	if eventDumpStep, ok := tc.Steps[3].(*TestStepEventDump); !ok {
		t.Errorf("fourth step was not EVENTDUMP step: %T", tc.Steps[3])
	} else {
		expectedLine := 98
		if eventDumpStep.Position.Line != expectedLine {
			t.Errorf("expected EVENTDUMP step to be defined at line %d, but it was %d",
				expectedLine, eventDumpStep.Position.Line)
		}

		if eventDumpStep.Op != api.MSG_OP_HTTP {
			t.Errorf("expected op %d, got %d", api.MSG_OP_TLS, eventDumpStep.Op)
		}
	}

}

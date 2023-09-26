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

//
// This file contains helpers to test the parsertest itself (i.e. the domain specific
// language for defining test cases and the resulting step/matcher types).
//

import (
	"bytes"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

type TestCaseTester struct {
	Name        string
	IngressPort int
	EgressPort  int
	Tags        []string
	Steps       []TestStepTester
}

func (tester *TestCaseTester) Assert(t *testing.T, tc *TestCase) bool {
	// Check test Name
	if !assert.Equal(t, tester.Name, tc.Name, "expected %s as name, but got %s", tester.Name, tc.Name) {
		return false
	}

	// Check test Tags
	for _, tag := range tester.Tags {
		if !assert.Contains(t, tc.Tags, tag, "expected tag %s not present in test case", tag) {
			return false
		}
	}
	if !assert.Equal(t, len(tester.Tags), len(tc.Tags), "expected %d tags, but got %d", len(tester.Tags), len(tc.Tags)) {
		return false
	}

	// Check test IngressPort and EgressPort
	if !assert.Equal(t, tester.IngressPort, tc.IngressPort, "expected %d as ingress port, but got %d", tester.IngressPort, tc.IngressPort) {
		return false
	}
	if !assert.Equal(t, tester.EgressPort, tc.EgressPort, "expected %d as ingress port, but got %d", tester.EgressPort, tc.EgressPort) {
		return false
	}

	// Check test steps
	expectedSteps := len(tester.Steps)
	nSteps := len(tc.Steps)
	for i, stepTester := range tester.Steps {
		if i == nSteps {
			// Break here since the step length assertion will catch the mismatch
			break
		}
		if !assert.True(t, stepTester.Assert(t, tc.Steps[i]), "mismatch in test step %d", i) {
			return false
		}
	}
	if !assert.Equal(t, expectedSteps, nSteps, "expected %d steps, got %d", expectedSteps, nSteps) {
		return false
	}

	return true
}

type TestStepTester interface {
	Assert(t *testing.T, step TestStep) bool
}

type TestStepEgressTester struct {
	Description string
	Data        []byte
}

func (tester *TestStepEgressTester) Assert(t *testing.T, step TestStep) bool {
	ts, ok := step.(*TestStepEgress)
	if !assert.True(t, ok, "expected EGRESS step, got %T", step) {
		return false
	}

	if !assert.Equal(t, tester.Description, ts.Description, "expected \"%s\" as test step description, got \"%s\"", tester.Description, ts.Description) {
		return false
	}

	if !assert.Equal(t, tester.Data, ts.Payload, "unexpected payload in EGRESS step") {
		return false
	}

	return true
}

type TestStepIngressTester struct {
	Description string
	Data        []byte
}

func (tester *TestStepIngressTester) Assert(t *testing.T, step TestStep) bool {
	ts, ok := step.(*TestStepIngress)
	if !assert.True(t, ok, "expected INGRESS step, got %T", step) {
		return false
	}

	if !assert.Equal(t, tester.Description, ts.Description, "expected \"%s\" as test step description, got \"%s\"", tester.Description, ts.Description) {
		return false
	}

	if !assert.Equal(t, tester.Data, ts.Payload, "unexpected payload in INGRESS step") {
		return false
	}

	return true
}

type TestStepEventTester struct {
	Op   int
	Data []byte
}

func (tester *TestStepEventTester) Assert(t *testing.T, step TestStep) bool {
	ts, ok := step.(*TestStepEvent)
	if !assert.True(t, ok, "expected EVENT step, got %T", step) {
		return false
	}

	if !assert.Equal(t, tester.Op, ts.Op, "expected %d as event op, got %d", tester.Op, ts.Op) {
		return false
	}

	r := bytes.NewReader(tester.Data)
	var ctx TestContext
	for _, m := range ts.Matchers {
		_, err := m.Match(&ctx, r)
		if !assert.NoError(t, err, "matcher at %s failed: %v", m.Position, err) {
			return false
		}
	}
	n, _ := io.Copy(io.Discard, r)
	if !assert.Equal(t, int64(0), n, "%d unmatched bytes remain", n) {
		return false
	}

	return true
}

type TestStepEventDumpTester struct {
	Op     int
	OpName string
}

func (tester *TestStepEventDumpTester) Assert(t *testing.T, step TestStep) bool {
	ts, ok := step.(*TestStepEventDump)
	if !assert.True(t, ok, "expected EVENTDUMP step, got %T", step) {
		return false
	}

	if !assert.Equal(t, tester.Op, ts.Op, "expected %d as event op, got %d", tester.Op, ts.Op) {
		return false
	}

	if !assert.Equal(t, tester.OpName, ts.OpName, "expected %s as event op name, got %s", tester.OpName, ts.OpName) {
		return false
	}

	return true
}

type TestStepSleepTester struct {
	Duration time.Duration
}

func (tester *TestStepSleepTester) Assert(t *testing.T, step TestStep) bool {
	ts, ok := step.(*TestStepSleep)
	if !assert.True(t, ok, "expected SLEEP step, got %T", step) {
		return false
	}

	if !assert.Equal(t, tester.Duration, ts.Duration, "expected %v as duration, got %v", tester.Duration, ts.Duration) {
		return false
	}

	return true
}

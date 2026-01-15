// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

// go test ./pkg/sensors/file/utils -test.run TestGlob

package file

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGlobFSM(t *testing.T) {
	for _, c := range GlobTestCases {
		fsm, err := CompileGlob(c.Pattern)
		assert.Equal(t, err, nil, "%w", err)
		if err == nil {
			assert.Equal(t, c.Match, fsm.Match(c.Path), "pattern: %s path: %s", c.Pattern, c.Path)
		}
	}
}

func TestGlobFSMMulti(t *testing.T) {
	for _, c := range GlobTestCases {
		allPatterns := map[string][]int32{
			c.Pattern: {1},
		}
		literals, knownMap := GetLiterals(allPatterns)
		nfa := BuildMultiNFA(allPatterns)
		dfa := ToDFA(nfa, literals)
		res := MatchString(dfa, c.Path, knownMap)
		if c.Match {
			assert.ElementsMatch(t, []int32{1}, res, "pattern: %s input: %s", c.Pattern, c.Path)
		} else {
			assert.Len(t, res, 0, "pattern: %s input: %s", c.Pattern, c.Path)
		}
	}
}

func TestGlobFSMMultiAll(t *testing.T) {
	for _, c := range GlobTestCasesMulti {
		literals, knownMap := GetLiterals(c.Patterns)
		nfa := BuildMultiNFA(c.Patterns)
		dfa := ToDFA(nfa, literals)
		for _, ts := range c.Tests {
			assert.ElementsMatch(t, ts.Values, MatchString(dfa, ts.Path, knownMap))
		}
	}
}

//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

// go test -gcflags="" -c ./pkg/sensors/file/utils -o go-tests/file-utils.test
// ./go-tests/file-utils.test -test.run TestPrefixTree

package file

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

type prefixTreeCase struct {
	prefix, suffix string
	rule           uint32
}

func TestPrefixTree1(t *testing.T) {
	testCases := []prefixTreeCase{
		{prefix: "/home/", suffix: ".txt", rule: 0},
		{prefix: "/home/apapag/", suffix: ".sh", rule: 1},
		{prefix: "/home/pizza/", suffix: ".go", rule: 2},
		{prefix: "/sys/kernel/", rule: 3},
	}

	prefixTree := NewPrefixTree()
	for _, tc := range testCases {
		prefixTree.Insert(PrefixSuffixFileMatcher{Prefix: tc.prefix, Suffix: tc.suffix}, tc.rule)
	}

	prefixes := prefixTree.Traverse()
	assert.Equal(t, 2, len(prefixes))
	assert.Contains(t, prefixes, PrefixSuffixFileMatchers{WalkPrefix: "/sys/kernel",
		Matchers: map[PrefixSuffixFileMatcherRule]struct{}{
			{Matcher: PrefixSuffixFileMatcher{Prefix: "/sys/kernel/"}, Rule: 3}: struct{}{},
		}})
	assert.Contains(t, prefixes, PrefixSuffixFileMatchers{
		WalkPrefix: "/home",
		Matchers: map[PrefixSuffixFileMatcherRule]struct{}{
			{Matcher: PrefixSuffixFileMatcher{Prefix: "/home/", Suffix: ".txt"}, Rule: 0}:       struct{}{},
			{Matcher: PrefixSuffixFileMatcher{Prefix: "/home/apapag/", Suffix: ".sh"}, Rule: 1}: struct{}{},
			{Matcher: PrefixSuffixFileMatcher{Prefix: "/home/pizza/", Suffix: ".go"}, Rule: 2}:  struct{}{},
		},
	})
}

func TestPrefixTree2(t *testing.T) {
	testCases := []prefixTreeCase{
		{prefix: "/home/", suffix: ".ssh/authorized_keys", rule: 0},
		{prefix: "/home/", suffix: ".ssh/known_hosts", rule: 1},
		{prefix: "/home/", suffix: ".ssh/id_rsa", rule: 2},
	}

	prefixTree := NewPrefixTree()
	for _, tc := range testCases {
		prefixTree.Insert(PrefixSuffixFileMatcher{Prefix: tc.prefix, Suffix: tc.suffix}, tc.rule)
	}

	assert.Equal(t, prefixTree.Traverse(),
		[]PrefixSuffixFileMatchers{
			{
				WalkPrefix: "/home",
				Matchers: map[PrefixSuffixFileMatcherRule]struct{}{
					{Matcher: PrefixSuffixFileMatcher{Prefix: "/home/", Suffix: ".ssh/authorized_keys"}, Rule: 0}: struct{}{},
					{Matcher: PrefixSuffixFileMatcher{Prefix: "/home/", Suffix: ".ssh/known_hosts"}, Rule: 1}:     struct{}{},
					{Matcher: PrefixSuffixFileMatcher{Prefix: "/home/", Suffix: ".ssh/id_rsa"}, Rule: 2}:          struct{}{},
				},
			},
		},
	)
}

func TestPrefixTree3(t *testing.T) {
	testCases := []prefixTreeCase{
		{prefix: "/home/", suffix: ".ssh/authorized_keys", rule: 0},
	}

	prefixTree := NewPrefixTree()
	for _, tc := range testCases {
		prefixTree.Insert(PrefixSuffixFileMatcher{Prefix: tc.prefix, Suffix: tc.suffix}, tc.rule)
	}

	assert.Equal(t, prefixTree.Traverse(),
		[]PrefixSuffixFileMatchers{
			{
				WalkPrefix: "/home",
				Matchers: map[PrefixSuffixFileMatcherRule]struct{}{
					{Matcher: PrefixSuffixFileMatcher{Prefix: "/home/", Suffix: ".ssh/authorized_keys"}, Rule: 0}: struct{}{},
				},
			},
		},
	)
}

func TestPrefixTreeEmpty(t *testing.T) {
	prefixTree := NewPrefixTree()
	assert.Equal(t, prefixTree.Traverse(), []PrefixSuffixFileMatchers(nil))
}

// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package file

type GlobTestCase struct {
	Pattern string
	Path    string
	Match   bool
}

var GlobTestCases = []GlobTestCase{
	{Pattern: "/home/*/.bash*", Path: "/home/apapag/.bash_profile", Match: true},
	{Pattern: "home/*/.bash*", Path: "/home/apapag/.bash_profile", Match: false},
	{Pattern: "*.txt", Path: "/home/.bash_profile.txt", Match: true},
	{Pattern: "*.txt", Path: "tasos.txta", Match: false},
	{Pattern: "/home/*/.bash*", Path: "/home/apapag/.bas_profile/.bash_profile", Match: true},
	{Pattern: "*.*", Path: "test.txt", Match: true},
	{Pattern: "*.*", Path: "test", Match: false},
	{Pattern: "/home/*/.bash*t", Path: "/home/apapag/.bas_profile/.bash_profilea/.bash_profilet", Match: true},
	{Pattern: "*abcd*", Path: "qabczabuuuuabcde", Match: true},
	{Pattern: "a*b*ab", Path: "aabaabaab", Match: true},
	{Pattern: "a*", Path: "aabaabaab", Match: true},
	{Pattern: "aa*", Path: "aabaabaab", Match: true},
	{Pattern: "aaba*", Path: "aabaabaab", Match: true},
	{Pattern: "*d", Path: "abcdd", Match: true},
	{Pattern: "*d*", Path: "abcdd", Match: true},
	{Pattern: "a*baab", Path: "aabaabqqbaab", Match: true},
	{Pattern: "/foo/*/blig", Path: "/foo/bar/baz/xlig/fig/blig", Match: true},
	{Pattern: "/foo/*/blig", Path: "/foo/bar/baz/blig/fig/blig", Match: true},
	{Pattern: "a*baab", Path: "aabaabaab", Match: true},
	{Pattern: "*.txt", Path: "a.tx.txt", Match: true},
	{Pattern: "*", Path: "a.tx.txt", Match: true},
	{Pattern: "*", Path: "ababa", Match: true},
	{Pattern: "*a*b*c*d*e*f*g", Path: "ababadlufgasijkldhfgakljhsdgfjklagsdkfjlhhagsdkjfghasdkjfgakjsdhgfkajsdgfkayueirgfjkhzsdvbcajkhgdevfrkjuyagvda", Match: false},
	{Pattern: "?", Path: "a", Match: true},
	{Pattern: "?", Path: "aa", Match: false},
	{Pattern: "a?a", Path: "aba", Match: true},
	{Pattern: "a?a", Path: "abba", Match: false},
	{Pattern: "a?a*", Path: "abadsafgadsjkhfgahsjk", Match: true},
	{Pattern: "*.t?t", Path: "test.txt", Match: true},
	{Pattern: "*.t?t", Path: "test.tat", Match: true},
	{Pattern: "*.t?t", Path: "test.txxt", Match: false},
	{Pattern: "*.t?t", Path: "test.tx", Match: false},
	{Pattern: "a*b?c", Path: "aabcc", Match: true},
	{Pattern: "a*b?c", Path: "aabbcc", Match: true},
	{Pattern: "a*b?c", Path: "abc", Match: false},
	{Pattern: "a*b?c", Path: "aabbbc", Match: true},
	{Pattern: "a*b?c", Path: "aabbbbc", Match: true},
	{Pattern: "/home/apapag/.cache/go-build/*.go", Path: "/usr/local/go/src/math/j0.go", Match: false},
	{Pattern: "a*", Path: "a", Match: true},
	{Pattern: "a*b", Path: "ab", Match: true},
	{Pattern: "*a", Path: "a", Match: true},
	{Pattern: "a*?boo", Path: "axboo", Match: true},
}

type GlobTestCaseMulti struct {
	Patterns map[string][]int32
	Tests    []struct {
		Path   string
		Values []int32
	}
}

var GlobTestCasesMulti = []GlobTestCaseMulti{
	{
		Patterns: map[string][]int32{
			"abc*":    {1, 3},
			"a?c":     {2},
			"a[cd]b":  {6},
			"a[!cd]c": {8},
		},
		Tests: []struct {
			Path   string
			Values []int32
		}{
			{Path: "abc", Values: []int32{1, 2, 3, 8}},
			{Path: "acb", Values: []int32{6}},
			{Path: "azc", Values: []int32{2, 8}},
			{Path: "pizza", Values: []int32{}},
		},
	},
	{
		Patterns: map[string][]int32{
			"foo*":   {1},
			"*bar":   {2},
			"foobar": {3},
			"f*r":    {4},
		},
		Tests: []struct {
			Path   string
			Values []int32
		}{
			{Path: "foobar", Values: []int32{1, 2, 3, 4}},
			{Path: "foor", Values: []int32{1, 4}},
			{Path: "fbar", Values: []int32{2, 4}},
		},
	},
	{
		Patterns: map[string][]int32{
			"*":  {100}, // Match everything
			"":   {200}, // Match only empty string
			"a*": {300},
			"*z": {400},
		},
		Tests: []struct {
			Path   string
			Values []int32
		}{
			{Path: "", Values: []int32{100, 200}},
			{Path: "az", Values: []int32{100, 300, 400}},
			{Path: "supercalifragilistic", Values: []int32{100}},
		},
	},
	{
		Patterns: map[string][]int32{
			"id-[a-f]":   {1}, // Matches id-a, id-b, ... id-f
			"val-[2-9]":  {2}, // Matches val-0 to val-9
			"val-[!0-5]": {3},
			"val-[01]":   {4},
		},
		Tests: []struct {
			Path   string
			Values []int32
		}{
			{Path: "id-c", Values: []int32{1}},
			{Path: "id-g", Values: []int32{}},
			{Path: "val-0", Values: []int32{4}},
			{Path: "val-1", Values: []int32{4}},
			{Path: "val-2", Values: []int32{2}},
			{Path: "val-3", Values: []int32{2}},
			{Path: "val-4", Values: []int32{2}},
			{Path: "val-5", Values: []int32{2}},
			{Path: "val-6", Values: []int32{2, 3}},
			{Path: "val-7", Values: []int32{2, 3}},
			{Path: "val-8", Values: []int32{2, 3}},
			{Path: "val-9", Values: []int32{2, 3}},
		},
	},
}

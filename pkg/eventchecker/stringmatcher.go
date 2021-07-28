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
package eventchecker

import (
	"fmt"
	"strings"
)

type StrMatch int

const (
	StrFullMatch StrMatch = iota // NB: 0
	StrPrefixMatch
	StrSuffixMatch
	StrContainsMatch
)

type StringMatcher struct {
	s string
	m StrMatch
}

type StringArg interface {
	// string -> FullMatch
	// StringMatcher
}

func stringMatcherFromArg(arg StringArg) StringMatcher {
	switch v := arg.(type) {
	case StringMatcher:
		return v
	case string:
		return FullStringMatch(v)
	}

	panic(fmt.Sprintf("stringMatcherFromArg: Unexpected type: %T", arg))
}

func FullStringMatch(s string) StringMatcher {
	return StringMatcher{s: s, m: StrFullMatch}
}

func PrefixStringMatch(s string) StringMatcher {
	return StringMatcher{s: s, m: StrPrefixMatch}
}

func SuffixStringMatch(s string) StringMatcher {
	return StringMatcher{s: s, m: StrSuffixMatch}
}

func ContainsStringMatch(s string) StringMatcher {
	return StringMatcher{s: s, m: StrContainsMatch}
}

func (sm StringMatcher) GetMatcher() func(string) error {
	switch sm.m {
	case StrFullMatch:
		return func(x string) error {
			if x == sm.s {
				return nil
			}
			return fmt.Errorf("'%s' does not match full string '%s'", x, sm.s)
		}
	case StrPrefixMatch:
		return func(x string) error {
			if strings.HasPrefix(x, sm.s) {
				return nil
			}
			return fmt.Errorf("'%s' does not match prefix '%s'", x, sm.s)
		}
	case StrSuffixMatch:
		return func(x string) error {
			if strings.HasSuffix(x, sm.s) {
				return nil
			}
			return fmt.Errorf("'%s' does not match suffix '%s'", x, sm.s)
		}
	case StrContainsMatch:
		return func(x string) error {
			if strings.Contains(x, sm.s) {
				return nil
			}
			return fmt.Errorf("'%s' does not contain '%s'", x, sm.s)
		}
	}
	return func(x string) error {
		return fmt.Errorf("internal error: Unknown matcher: %d", sm.m)
	}
}

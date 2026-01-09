// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package eventchecker

// LabelMatch matches key, value pairs on labels
type LabelMatch struct {
	Key string
	Val StringMatcher
}

// LabelMatchVal constructs a new LabelMatch that matches over full values
func LabelMatchVal(key string, val string) LabelMatch {
	return LabelMatch{
		Key: key,
		Val: FullStringMatch(val),
	}
}

// LabelMatchValPrefix constructs a new LabelMatch that matches over value prefixes
func LabelMatchValPrefix(key string, valPrefix string) LabelMatch {
	return LabelMatch{
		Key: key,
		Val: PrefixStringMatch(valPrefix),
	}
}

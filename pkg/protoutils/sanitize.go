// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package protoutils

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// SanitizeString takes a string that may contain invalid UTF-8 byte sequences
// and returns a valid UTF-8 string where any invalid bytes are replaced with
// their hex representation in the form \xXX (e.g., \xFF for byte 0xFF).
//
// This ensures that all strings can be safely serialized in protobuf messages,
// which require valid UTF-8 encoding.
func SanitizeString(s string) string {
	if utf8.ValidString(s) {
		return s
	}

	var result strings.Builder
	// Pre-allocate with some extra space for escape sequences
	result.Grow(len(s) + 16)

	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			// Invalid UTF-8 byte - replace with \xXX hex notation
			result.WriteString(fmt.Sprintf("\\x%02X", s[i]))
			i++
		} else {
			// Valid UTF-8 character - write it as-is
			result.WriteRune(r)
			i += size
		}
	}

	return result.String()
}

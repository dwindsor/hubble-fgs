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
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
)

func TestSanitizeString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "valid UTF-8 string",
			input:    "Hello, World!",
			expected: "Hello, World!",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "single invalid byte",
			input:    "test\xffdata",
			expected: "test\\xFFdata",
		},
		{
			name:     "multiple invalid bytes",
			input:    "\xff\xfe\xfd",
			expected: "\\xFF\\xFE\\xFD",
		},
		{
			name:     "mixed valid and invalid",
			input:    "Hello\xff World\xfe!",
			expected: "Hello\\xFF World\\xFE!",
		},
		{
			name:     "invalid at start",
			input:    "\xffHello",
			expected: "\\xFFHello",
		},
		{
			name:     "invalid at end",
			input:    "Hello\xff",
			expected: "Hello\\xFF",
		},
		{
			name:     "special characters remain",
			input:    "path/to/file\nwith\ttabs",
			expected: "path/to/file\nwith\ttabs",
		},
		{
			name:     "null byte handling",
			input:    "test\x00null",
			expected: "test\x00null",
		},
		{
			name:     "high bit set but valid UTF-8",
			input:    "café",
			expected: "café",
		},
		{
			name:     "process name with invalid bytes",
			input:    "/usr/bin/app\xff",
			expected: "/usr/bin/app\\xFF",
		},
		{
			name:     "arguments with invalid bytes",
			input:    "--config=/path\xfe/config.json",
			expected: "--config=/path\\xFE/config.json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizeString(tt.input)
			assert.Equal(t, tt.expected, result, "SanitizeString output mismatch")

			// Verify result is valid UTF-8
			assert.True(t, utf8.ValidString(result), "Result should be valid UTF-8")
		})
	}
}

func TestSanitizeString_Idempotent(t *testing.T) {
	// Sanitizing an already sanitized string should not change it
	input := "test\xffdata"
	firstPass := SanitizeString(input)
	secondPass := SanitizeString(firstPass)

	assert.Equal(t, firstPass, secondPass, "SanitizeString should be idempotent")
	assert.Equal(t, "test\\xFFdata", firstPass)
}

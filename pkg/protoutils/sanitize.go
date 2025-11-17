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
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

const invalidUTF8Replacement = "(invalid utf-8)"

// SanitizeUTF8AndMarshalJSON walks through a protobuf message, replaces any invalid UTF-8
// string values with "(invalid utf-8)", and then marshals the sanitized message to JSON.
// This addresses issues where invalid UTF-8 in string fields causes JSON marshaling to fail.
// Having a sanitized version that marshals correctly ensures that valuable debugging output
// can be obtained even when the original data is malformed.
func SanitizeUTF8AndMarshalJSON(msg proto.Message) ([]byte, error) {
	// Create a copy of the message to avoid modifying the original
	msgCopy := proto.Clone(msg)

	// Walk through all fields and sanitize string values
	err := sanitizeUTF8Strings(msgCopy.ProtoReflect())
	if err != nil {
		return nil, err
	}

	// Marshal the sanitized message to JSON
	return json.Marshal(msgCopy)
}

// sanitizeUTF8Strings recursively walks through a protobuf message and replaces
// invalid UTF-8 string values with the replacement string.
func sanitizeUTF8Strings(msg protoreflect.Message) error {
	// Walk through all fields in the message
	msg.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		if fd.Kind() == protoreflect.StringKind {
			// Handle string fields
			str := v.String()
			if !utf8.ValidString(str) {
				msg.Set(fd, protoreflect.ValueOfString(invalidUTF8Replacement))
			}
		} else if fd.Kind() == protoreflect.MessageKind {
			// Recursively handle nested messages
			if fd.IsList() {
				// Handle repeated message fields
				list := v.List()
				for i := 0; i < list.Len(); i++ {
					if list.Get(i).Message().IsValid() {
						sanitizeUTF8Strings(list.Get(i).Message())
					}
				}
			} else if fd.IsMap() {
				// Handle map fields
				mapVal := v.Map()
				mapVal.Range(func(_ protoreflect.MapKey, v protoreflect.Value) bool {
					if v.Message().IsValid() {
						sanitizeUTF8Strings(v.Message())
					}
					return true
				})
			} else {
				// Handle singular message fields
				if v.Message().IsValid() {
					sanitizeUTF8Strings(v.Message())
				}
			}
		} else if fd.IsList() && fd.Kind() == protoreflect.StringKind {
			// Handle repeated string fields
			list := v.List()
			for i := 0; i < list.Len(); i++ {
				str := list.Get(i).String()
				if !utf8.ValidString(str) {
					list.Set(i, protoreflect.ValueOfString(invalidUTF8Replacement))
				}
			}
		}
		return true
	})

	return nil
}

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

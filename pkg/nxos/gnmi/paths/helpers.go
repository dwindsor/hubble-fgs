// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package paths

import (
	"strings"

	gnmiproto "github.com/openconfig/gnmi/proto/gnmi"
)

// PathToString converts a gNMI path to a string.
func PathToString(prefix, path *gnmiproto.Path) string {
	var result strings.Builder

	// Add origin if present
	if prefix != nil && prefix.Origin != "" {
		result.WriteString(prefix.Origin)
		result.WriteString(":")
	}

	// Combine prefix and path elements
	var allElems []*gnmiproto.PathElem
	if prefix != nil {
		allElems = append(allElems, prefix.GetElem()...)
	}
	if path != nil {
		allElems = append(allElems, path.GetElem()...)
	}

	// Build path string
	for i, elem := range allElems {
		if i > 0 || result.Len() > 0 {
			result.WriteString("/")
		}
		result.WriteString(elem.Name)

		// Add keys
		if len(elem.Key) > 0 {
			result.WriteString("[")
			first := true
			for k, v := range elem.Key {
				if !first {
					result.WriteString(",")
				}
				result.WriteString(k)
				result.WriteString("=")
				result.WriteString(v)
				first = false
			}
			result.WriteString("]")
		}
	}

	return result.String()
}

// StringToPath converts a string path to a gNMI Path.
// Path format: "device:/System/sas-items/svc-items/..." or "/System/sas-items/..."
// If the path contains an origin prefix (e.g., "device:"), it will be parsed and set.
func StringToPath(pathStr string) *gnmiproto.Path {
	if pathStr == "" {
		return &gnmiproto.Path{}
	}

	var origin string

	// Check for origin prefix (e.g., "device:/System/...")
	if colonIdx := indexOf(pathStr, ':'); colonIdx > 0 {
		// Make sure this is an origin prefix and not part of a key value
		if bracketIdx := indexOf(pathStr, '['); bracketIdx == -1 || colonIdx < bracketIdx {
			origin = pathStr[:colonIdx]
			pathStr = pathStr[colonIdx+1:]
		}
	}

	// Remove leading slash
	if len(pathStr) > 0 && pathStr[0] == '/' {
		pathStr = pathStr[1:]
	}

	// Split path into elements
	parts := splitPath(pathStr)
	elems := make([]*gnmiproto.PathElem, 0, len(parts))

	for _, part := range parts {
		if part == "" {
			continue
		}

		elem := &gnmiproto.PathElem{Name: part}

		// Check for keys in format name[key=value]
		if idx := indexOf(part, '['); idx > 0 {
			elem.Name = part[:idx]
			keysStr := part[idx+1:]
			if len(keysStr) > 0 && keysStr[len(keysStr)-1] == ']' {
				keysStr = keysStr[:len(keysStr)-1]
			}

			// Parse keys
			elem.Key = make(map[string]string)
			keyPairs := splitKeys(keysStr)
			for _, kp := range keyPairs {
				if eqIdx := indexOf(kp, '='); eqIdx > 0 {
					elem.Key[kp[:eqIdx]] = kp[eqIdx+1:]
				}
			}
		}

		elems = append(elems, elem)
	}

	return &gnmiproto.Path{Origin: origin, Elem: elems}
}

// splitPath splits a path string by '/' but respects brackets.
func splitPath(path string) []string {
	var result []string
	var current string
	bracketDepth := 0

	for _, c := range path {
		switch c {
		case '[':
			bracketDepth++
			current += string(c)
		case ']':
			bracketDepth--
			current += string(c)
		case '/':
			if bracketDepth == 0 {
				if current != "" {
					result = append(result, current)
				}
				current = ""
			} else {
				current += string(c)
			}
		default:
			current += string(c)
		}
	}

	if current != "" {
		result = append(result, current)
	}

	return result
}

// splitKeys splits key-value pairs by ','.
func splitKeys(keys string) []string {
	var result []string
	var current string

	for _, c := range keys {
		if c == ',' {
			if current != "" {
				result = append(result, current)
			}
			current = ""
		} else {
			current += string(c)
		}
	}

	if current != "" {
		result = append(result, current)
	}

	return result
}

// indexOf returns the index of the first occurrence of c in s, or -1 if not found.
func indexOf(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}

// IndexOfString returns the index of substr in s, or -1 if not found.
func IndexOfString(s, substr string) int {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

// IndexOfStringAfter returns the index of substr in s starting from start, or -1 if not found.
func IndexOfStringAfter(s, substr string, start int) int {
	for i := start; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

// ContainsString checks if s contains substr.
func ContainsString(s, substr string) bool {
	return IndexOfString(s, substr) >= 0
}

// ExtractNamesFromJSON recursively searches JSON data for a given key and returns all string values.
func ExtractNamesFromJSON(data interface{}, key string) []string {
	var results []string

	switch v := data.(type) {
	case map[string]interface{}:
		if val, ok := v[key]; ok {
			if s, ok := val.(string); ok {
				results = append(results, s)
			}
		}
		for _, val := range v {
			results = append(results, ExtractNamesFromJSON(val, key)...)
		}
	case []interface{}:
		for _, item := range v {
			results = append(results, ExtractNamesFromJSON(item, key)...)
		}
	}

	return results
}

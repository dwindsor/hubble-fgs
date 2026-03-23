// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package mock

import (
	"encoding/json"
	"strings"

	gnmiproto "github.com/openconfig/gnmi/proto/gnmi"
)

// makeStringUpdate creates a gNMI Update with a string value.
func makeStringUpdate(val string) *gnmiproto.Update {
	return &gnmiproto.Update{
		Val: &gnmiproto.TypedValue{
			Value: &gnmiproto.TypedValue_StringVal{StringVal: val},
		},
	}
}

// makeUintUpdate creates a gNMI Update with an unsigned integer value.
func makeUintUpdate(val uint64) *gnmiproto.Update {
	return &gnmiproto.Update{
		Val: &gnmiproto.TypedValue{
			Value: &gnmiproto.TypedValue_UintVal{UintVal: val},
		},
	}
}

// TreeToFlat recursively walks a nested tree (as produced by pathsToTree / show --json)
// and returns a flat map of gNMI path → value string suitable for SetAndNotify.
func TreeToFlat(tree map[string]interface{}) map[string]string {
	result := make(map[string]string)
	treeToFlatRecurse(tree, "", result)
	return result
}

func treeToFlatRecurse(node map[string]interface{}, prefix string, result map[string]string) {
	for key, val := range node {
		path := key
		if prefix != "" {
			path = prefix + "/" + key
		}
		switch v := val.(type) {
		case map[string]interface{}:
			treeToFlatRecurse(v, path, result)
		default:
			jsonBytes, err := json.Marshal(v)
			if err != nil {
				continue
			}
			s := string(jsonBytes)
			// Unwrap quoted strings so SetAndNotify gets the plain value
			if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
				var unquoted string
				if err := json.Unmarshal(jsonBytes, &unquoted); err == nil {
					s = unquoted
				}
			}
			result[path] = s
		}
	}
}

// normalizePath removes origin prefix and leading slashes from a path.
func normalizePath(path string) string {
	// Remove origin prefix (e.g., "device:/System/..." -> "System/...")
	if colonIdx := strings.Index(path, ":"); colonIdx > 0 {
		// Make sure this is an origin prefix and not part of a key value
		if bracketIdx := strings.Index(path, "["); bracketIdx == -1 || colonIdx < bracketIdx {
			path = path[colonIdx+1:]
		}
	}

	// Remove leading slash
	return strings.TrimPrefix(path, "/")
}

// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package gnmi

import (
	"encoding/json"
	"fmt"
	"math"

	gnmiproto "github.com/openconfig/gnmi/proto/gnmi"
)

// extractStrings extracts string values from a gNMI GetResponse.
func extractStrings(resp *gnmiproto.GetResponse) []string {
	var strs []string
	for _, notif := range resp.Notification {
		for _, update := range notif.GetUpdate() {
			if s, ok := ExtractStringValue(update.GetVal()); ok {
				strs = append(strs, s)
			}
		}
	}
	return strs
}

// ExtractStringValue attempts to extract a string value from a gNMI value.
func ExtractStringValue(value any) (string, bool) {
	if value == nil {
		return "", false
	}
	switch v := value.(type) {
	case *gnmiproto.TypedValue:
		if v == nil {
			return "", false
		}
		switch v.GetValue().(type) {
		case *gnmiproto.TypedValue_StringVal:
			return v.GetStringVal(), true
		case *gnmiproto.TypedValue_BytesVal:
			return string(v.GetBytesVal()), true
		case *gnmiproto.TypedValue_ProtoBytes:
			return string(v.GetProtoBytes()), true
		case *gnmiproto.TypedValue_JsonVal:
			return unquoteJSONString(v.GetJsonVal()), true
		case *gnmiproto.TypedValue_JsonIetfVal:
			return unquoteJSONString(v.GetJsonIetfVal()), true
		default:
			return "", false
		}
	case string:
		return v, true
	case []byte:
		return string(v), true
	default:
		return "", false
	}
}

// ExtractUint32Value attempts to extract a uint32 value from a gNMI value.
func ExtractUint32Value(value any) (uint32, bool) {
	if value == nil {
		return 0, false
	}
	switch v := value.(type) {
	case *gnmiproto.TypedValue:
		if v == nil {
			return 0, false
		}
		switch v.GetValue().(type) {
		case *gnmiproto.TypedValue_UintVal:
			u := v.GetUintVal()
			if u > math.MaxUint32 {
				return 0, false
			}
			return uint32(u), true
		case *gnmiproto.TypedValue_IntVal:
			i := v.GetIntVal()
			if i < 0 || i > math.MaxUint32 {
				return 0, false
			}
			return uint32(i), true
		case *gnmiproto.TypedValue_FloatVal:
			f := v.GetFloatVal()
			if f < 0 || f > math.MaxUint32 {
				return 0, false
			}
			return uint32(f), true
		case *gnmiproto.TypedValue_DoubleVal:
			d := v.GetDoubleVal()
			if d < 0 || d > math.MaxUint32 {
				return 0, false
			}
			return uint32(d), true
		default:
			return 0, false
		}
	case uint32:
		return v, true
	case int:
		if v < 0 || v > math.MaxUint32 {
			return 0, false
		}
		return uint32(v), true
	case int64:
		if v < 0 || v > math.MaxUint32 {
			return 0, false
		}
		return uint32(v), true
	case uint64:
		if v > math.MaxUint32 {
			return 0, false
		}
		return uint32(v), true
	case float64:
		if v < 0 || v > math.MaxUint32 {
			return 0, false
		}
		return uint32(v), true
	default:
		return 0, false
	}
}

// unquoteJSONString attempts to JSON-unmarshal raw bytes as a string to strip
// JSON encoding (e.g. `"10.6(2s)"` → `10.6(2s)`). If the bytes are not a JSON
// string (e.g. an object or array), it returns the raw bytes as a string.
func unquoteJSONString(b []byte) string {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		return s
	}
	return string(b)
}

// ExtractJSONObject extracts a JSON object from a gNMI TypedValue.
// Used when subscribing at list-entry level, where the value is a full JSON object.
func ExtractJSONObject(value *gnmiproto.TypedValue) (map[string]interface{}, bool) {
	if value == nil {
		return nil, false
	}
	var raw []byte
	switch v := value.GetValue().(type) {
	case *gnmiproto.TypedValue_JsonVal:
		raw = v.JsonVal
	case *gnmiproto.TypedValue_JsonIetfVal:
		raw = v.JsonIetfVal
	default:
		return nil, false
	}
	var obj map[string]interface{}
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, false
	}
	return obj, true
}

// marshalJSONValue converts a Go value to a JSON string for gNMI Set operations.
// NX-OS gNMI only accepts JSON-encoded values.
func marshalJSONValue(value any) (string, error) {
	if value == nil {
		return "{}", nil
	}
	switch v := value.(type) {
	case string:
		return v, nil
	case []byte:
		return string(v), nil
	default:
		b, err := json.Marshal(value)
		if err != nil {
			return "", fmt.Errorf("failed to marshal value: %w", err)
		}
		return string(b), nil
	}
}

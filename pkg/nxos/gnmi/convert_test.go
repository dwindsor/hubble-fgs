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
	"testing"

	gnmiproto "github.com/openconfig/gnmi/proto/gnmi"
)

func TestExtractStringValue_StringVal(t *testing.T) {
	tv := &gnmiproto.TypedValue{
		Value: &gnmiproto.TypedValue_StringVal{StringVal: "hello"},
	}
	s, ok := ExtractStringValue(tv)
	if !ok || s != "hello" {
		t.Fatalf("expected (hello, true), got (%q, %v)", s, ok)
	}
}

func TestExtractStringValue_JsonVal_QuotedString(t *testing.T) {
	// Simulates what NX-OS returns for a leaf string value via JSON encoding:
	// the raw bytes are a JSON-encoded string like `"10.6(2s)"`.
	tv := &gnmiproto.TypedValue{
		Value: &gnmiproto.TypedValue_JsonVal{JsonVal: []byte(`"10.6(2s)"`)},
	}
	s, ok := ExtractStringValue(tv)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if s != "10.6(2s)" {
		t.Fatalf("expected unquoted string '10.6(2s)', got %q", s)
	}
}

func TestExtractStringValue_JsonVal_Object(t *testing.T) {
	// JSON object should be returned as-is (raw string).
	jsonObj := `{"model":"N9K-C9364C","swVer":"10.6(2s)"}`
	tv := &gnmiproto.TypedValue{
		Value: &gnmiproto.TypedValue_JsonVal{JsonVal: []byte(jsonObj)},
	}
	s, ok := ExtractStringValue(tv)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if s != jsonObj {
		t.Fatalf("expected raw JSON object, got %q", s)
	}
}

func TestExtractStringValue_JsonIetfVal_QuotedString(t *testing.T) {
	tv := &gnmiproto.TypedValue{
		Value: &gnmiproto.TypedValue_JsonIetfVal{JsonIetfVal: []byte(`"supervisor"`)},
	}
	s, ok := ExtractStringValue(tv)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if s != "supervisor" {
		t.Fatalf("expected unquoted string 'supervisor', got %q", s)
	}
}

func TestExtractStringValue_Nil(t *testing.T) {
	s, ok := ExtractStringValue(nil)
	if ok || s != "" {
		t.Fatalf("expected ('', false), got (%q, %v)", s, ok)
	}
}

func TestExtractStringValue_NilTypedValue(t *testing.T) {
	var tv *gnmiproto.TypedValue
	s, ok := ExtractStringValue(tv)
	if ok || s != "" {
		t.Fatalf("expected ('', false), got (%q, %v)", s, ok)
	}
}

func TestExtractStringValue_BytesVal(t *testing.T) {
	tv := &gnmiproto.TypedValue{
		Value: &gnmiproto.TypedValue_BytesVal{BytesVal: []byte("raw-bytes")},
	}
	s, ok := ExtractStringValue(tv)
	if !ok || s != "raw-bytes" {
		t.Fatalf("expected (raw-bytes, true), got (%q, %v)", s, ok)
	}
}

func TestUnquoteJSONString(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  string
	}{
		{"quoted string", []byte(`"10.6(2s)"`), "10.6(2s)"},
		{"empty quoted string", []byte(`""`), ""},
		{"json object", []byte(`{"key":"val"}`), `{"key":"val"}`},
		{"json array", []byte(`[1,2,3]`), `[1,2,3]`},
		{"json number", []byte(`42`), `42`},
		{"bare string (invalid json)", []byte(`hello`), `hello`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := unquoteJSONString(tt.input)
			if got != tt.want {
				t.Errorf("unquoteJSONString(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestExtractStringValue_EmptyStringVal(t *testing.T) {
	// A TypedValue explicitly set to an empty string should return ("", true).
	tv := &gnmiproto.TypedValue{
		Value: &gnmiproto.TypedValue_StringVal{StringVal: ""},
	}
	s, ok := ExtractStringValue(tv)
	if !ok {
		t.Fatal("expected ok=true for explicitly set empty string")
	}
	if s != "" {
		t.Fatalf("expected empty string, got %q", s)
	}
}

func TestExtractStringValue_EmptyBytesVal(t *testing.T) {
	// A TypedValue explicitly set to empty bytes should return ("", true).
	tv := &gnmiproto.TypedValue{
		Value: &gnmiproto.TypedValue_BytesVal{BytesVal: []byte{}},
	}
	s, ok := ExtractStringValue(tv)
	if !ok {
		t.Fatal("expected ok=true for explicitly set empty bytes")
	}
	if s != "" {
		t.Fatalf("expected empty string, got %q", s)
	}
}

func TestExtractStringValue_UintValNotString(t *testing.T) {
	// A TypedValue set to a uint should not be extracted as a string.
	tv := &gnmiproto.TypedValue{
		Value: &gnmiproto.TypedValue_UintVal{UintVal: 42},
	}
	_, ok := ExtractStringValue(tv)
	if ok {
		t.Fatal("expected ok=false for UintVal")
	}
}

func TestExtractUint32Value_UintVal(t *testing.T) {
	tv := &gnmiproto.TypedValue{
		Value: &gnmiproto.TypedValue_UintVal{UintVal: 100},
	}
	v, ok := ExtractUint32Value(tv)
	if !ok || v != 100 {
		t.Fatalf("expected (100, true), got (%d, %v)", v, ok)
	}
}

func TestExtractUint32Value_UintVal_Zero(t *testing.T) {
	// A TypedValue explicitly set to 0 should return (0, true).
	tv := &gnmiproto.TypedValue{
		Value: &gnmiproto.TypedValue_UintVal{UintVal: 0},
	}
	v, ok := ExtractUint32Value(tv)
	if !ok {
		t.Fatal("expected ok=true for explicitly set zero UintVal")
	}
	if v != 0 {
		t.Fatalf("expected 0, got %d", v)
	}
}

func TestExtractUint32Value_IntVal(t *testing.T) {
	tv := &gnmiproto.TypedValue{
		Value: &gnmiproto.TypedValue_IntVal{IntVal: 42},
	}
	v, ok := ExtractUint32Value(tv)
	if !ok || v != 42 {
		t.Fatalf("expected (42, true), got (%d, %v)", v, ok)
	}
}

func TestExtractUint32Value_IntVal_Zero(t *testing.T) {
	// A TypedValue explicitly set to 0 should return (0, true).
	tv := &gnmiproto.TypedValue{
		Value: &gnmiproto.TypedValue_IntVal{IntVal: 0},
	}
	v, ok := ExtractUint32Value(tv)
	if !ok {
		t.Fatal("expected ok=true for explicitly set zero IntVal")
	}
	if v != 0 {
		t.Fatalf("expected 0, got %d", v)
	}
}

func TestExtractUint32Value_FloatVal_Zero(t *testing.T) {
	// A TypedValue explicitly set to 0.0 float should return (0, true).
	tv := &gnmiproto.TypedValue{
		Value: &gnmiproto.TypedValue_FloatVal{FloatVal: 0.0},
	}
	v, ok := ExtractUint32Value(tv)
	if !ok {
		t.Fatal("expected ok=true for explicitly set zero FloatVal")
	}
	if v != 0 {
		t.Fatalf("expected 0, got %d", v)
	}
}

func TestExtractUint32Value_DoubleVal_Zero(t *testing.T) {
	// A TypedValue explicitly set to 0.0 double should return (0, true).
	tv := &gnmiproto.TypedValue{
		Value: &gnmiproto.TypedValue_DoubleVal{DoubleVal: 0.0},
	}
	v, ok := ExtractUint32Value(tv)
	if !ok {
		t.Fatal("expected ok=true for explicitly set zero DoubleVal")
	}
	if v != 0 {
		t.Fatalf("expected 0, got %d", v)
	}
}

func TestExtractUint32Value_Nil(t *testing.T) {
	v, ok := ExtractUint32Value(nil)
	if ok || v != 0 {
		t.Fatalf("expected (0, false), got (%d, %v)", v, ok)
	}
}

func TestExtractUint32Value_NilTypedValue(t *testing.T) {
	var tv *gnmiproto.TypedValue
	v, ok := ExtractUint32Value(tv)
	if ok || v != 0 {
		t.Fatalf("expected (0, false), got (%d, %v)", v, ok)
	}
}

func TestExtractUint32Value_StringValNotUint(t *testing.T) {
	// A TypedValue set to a string should not be extracted as uint32.
	tv := &gnmiproto.TypedValue{
		Value: &gnmiproto.TypedValue_StringVal{StringVal: "hello"},
	}
	_, ok := ExtractUint32Value(tv)
	if ok {
		t.Fatal("expected ok=false for StringVal")
	}
}

func TestExtractUint32Value_PlainTypes(t *testing.T) {
	// Test plain Go types including zero values.
	tests := []struct {
		name   string
		input  any
		want   uint32
		wantOk bool
	}{
		{"uint32 non-zero", uint32(10), 10, true},
		{"uint32 zero", uint32(0), 0, true},
		{"int non-zero", int(5), 5, true},
		{"int zero", int(0), 0, true},
		{"int64 non-zero", int64(99), 99, true},
		{"int64 zero", int64(0), 0, true},
		{"uint64 non-zero", uint64(7), 7, true},
		{"uint64 zero", uint64(0), 0, true},
		{"float64 non-zero", float64(3.14), 3, true},
		{"float64 zero", float64(0), 0, true},
		{"unsupported type", "string", 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := ExtractUint32Value(tt.input)
			if ok != tt.wantOk || got != tt.want {
				t.Errorf("ExtractUint32Value(%v) = (%d, %v), want (%d, %v)", tt.input, got, ok, tt.want, tt.wantOk)
			}
		})
	}
}

func TestExtractStrings(t *testing.T) {
	resp := &gnmiproto.GetResponse{
		Notification: []*gnmiproto.Notification{
			{
				Update: []*gnmiproto.Update{
					{
						Val: &gnmiproto.TypedValue{
							Value: &gnmiproto.TypedValue_JsonVal{JsonVal: []byte(`"10.6(2s)"`)},
						},
					},
				},
			},
		},
	}
	strs := extractStrings(resp)
	if len(strs) != 1 {
		t.Fatalf("expected 1 string, got %d", len(strs))
	}
	if strs[0] != "10.6(2s)" {
		t.Fatalf("expected '10.6(2s)', got %q", strs[0])
	}
}

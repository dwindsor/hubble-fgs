package agw

import (
	"strings"
	"testing"
)

type TestStruct struct {
	Name   string  `json:"name"`
	Age    int     `json:"age"`
	Active bool    `json:"active"`
	Score  float64 `json:"score"`
}

type TestStructNoTags struct {
	Name   string
	Age    int
	Active bool
}

type TestStructMixedTags struct {
	Name     string `json:"name"`
	Internal string // No JSON tag - should be skipped
	Age      int    `json:"age"`
}

type TestStructWithPointer struct {
	Name  string  `json:"name"`
	Value *string `json:"value"`
}

func TestFormatTable(t *testing.T) {
	tests := []struct {
		name        string
		input       interface{}
		wantHeaders []string
		wantRows    int
		wantErr     bool
	}{
		{
			name: "basic struct slice",
			input: []TestStruct{
				{Name: "Alice", Age: 30, Active: true, Score: 95.5},
				{Name: "Bob", Age: 25, Active: false, Score: 88.0},
			},
			wantHeaders: []string{"name", "age", "active", "score"},
			wantRows:    2,
			wantErr:     false,
		},
		{
			name: "struct without json tags returns error",
			input: []TestStructNoTags{
				{Name: "Test", Age: 10, Active: true},
			},
			wantHeaders: nil,
			wantRows:    0,
			wantErr:     true,
		},
		{
			name: "struct with mixed tags only shows tagged fields",
			input: []TestStructMixedTags{
				{Name: "Alice", Internal: "secret", Age: 30},
			},
			wantHeaders: []string{"name", "age"},
			wantRows:    1,
			wantErr:     false,
		},
		{
			name:        "empty slice",
			input:       []TestStruct{},
			wantHeaders: nil,
			wantRows:    0,
			wantErr:     false,
		},
		{
			name:        "single struct formats as key-value table",
			input:       TestStruct{Name: "Test", Age: 25, Active: true, Score: 99.5},
			wantHeaders: []string{"name", "age", "active", "score"},
			wantRows:    3, // 4 fields, but test subtracts 1 for header (struct format has no header)
			wantErr:     false,
		},
		{
			name:        "map formats as key-value table",
			input:       map[string]int{"alpha": 1, "beta": 2},
			wantHeaders: []string{"alpha", "beta"},
			wantRows:    1, // 2 entries, but test subtracts 1 for header (map format has no header)
			wantErr:     false,
		},
		{
			name:        "slice of non-structs",
			input:       []string{"a", "b"},
			wantHeaders: nil,
			wantRows:    0,
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := FormatTable(tt.input)

			if (err != nil) != tt.wantErr {
				t.Errorf("FormatTable() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			if tt.wantRows == 0 {
				if result != "" {
					t.Errorf("FormatTable() expected empty result for empty slice, got %q", result)
				}
				return
			}

			// Check headers are present
			for _, header := range tt.wantHeaders {
				if !strings.Contains(result, header) {
					t.Errorf("FormatTable() result missing header %q", header)
				}
			}

			// Count data rows (excluding header line and empty first line)
			lines := strings.Split(strings.TrimSpace(result), "\n")
			// First line is header, rest are data
			dataRows := len(lines) - 1
			if dataRows != tt.wantRows {
				t.Errorf("FormatTable() got %d data rows, want %d", dataRows, tt.wantRows)
			}
		})
	}
}

func TestFormatTableSkipsUntaggedFields(t *testing.T) {
	items := []TestStructMixedTags{
		{Name: "Alice", Internal: "secret", Age: 30},
	}

	result, err := FormatTable(items)
	if err != nil {
		t.Fatalf("FormatTable() unexpected error: %v", err)
	}

	// Should contain tagged fields
	if !strings.Contains(result, "Alice") {
		t.Error("FormatTable() should contain Alice")
	}
	if !strings.Contains(result, "30") {
		t.Error("FormatTable() should contain 30")
	}

	// Should NOT contain untagged field value
	if strings.Contains(result, "secret") {
		t.Error("FormatTable() should NOT contain untagged field value 'secret'")
	}

	// Should NOT contain "Internal" as a header
	if strings.Contains(result, "Internal") {
		t.Error("FormatTable() should NOT contain 'Internal' header")
	}
}

func TestFormatTableWithPointers(t *testing.T) {
	val := "test value"
	items := []TestStructWithPointer{
		{Name: "Item1", Value: &val},
		{Name: "Item2", Value: nil},
	}

	result, err := FormatTable(items)
	if err != nil {
		t.Fatalf("FormatTable() unexpected error: %v", err)
	}

	if !strings.Contains(result, "test value") {
		t.Error("FormatTable() should contain pointer value")
	}

	if !strings.Contains(result, "N/A") {
		t.Error("FormatTable() should contain N/A for nil pointer")
	}
}

func TestFormatTableWithPointerSlice(t *testing.T) {
	items := []*TestStruct{
		{Name: "Alice", Age: 30, Active: true, Score: 95.5},
		{Name: "Bob", Age: 25, Active: false, Score: 88.0},
	}

	result, err := FormatTable(items)
	if err != nil {
		t.Fatalf("FormatTable() unexpected error: %v", err)
	}

	if !strings.Contains(result, "Alice") {
		t.Error("FormatTable() should contain Alice")
	}

	if !strings.Contains(result, "Bob") {
		t.Error("FormatTable() should contain Bob")
	}
}

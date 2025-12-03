package agw

import (
	"bytes"
	"fmt"
	"reflect"
	"strings"
	"text/tabwriter"
)

// FormatTable generates a formatted table string from a slice of structs.
// It uses JSON tags as column headers. Fields without a JSON tag are skipped
// and will not appear in the table output.
//
// Parameters:
//   - items: a slice of structs (e.g., []MyStruct or interface{} containing a slice)
//
// Returns:
//   - A formatted table string with columns aligned using tabwriter
//   - An error if the input is not a slice of structs or has no fields with JSON tags
func FormatTable(items interface{}) (string, error) {
	v := reflect.ValueOf(items)

	// Handle pointer to slice
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}

	if v.Kind() != reflect.Slice {
		return "", fmt.Errorf("FormatTable requires a slice, got %s", v.Kind())
	}

	if v.Len() == 0 {
		return "", nil
	}

	// Get the element type
	elemType := v.Type().Elem()
	// Handle pointer to struct
	if elemType.Kind() == reflect.Ptr {
		elemType = elemType.Elem()
	}
	if elemType.Kind() != reflect.Struct {
		return "", fmt.Errorf("FormatTable requires a slice of structs, got slice of %s", elemType.Kind())
	}

	// Extract field indices that have JSON tags
	fieldIndices := getJSONFieldIndices(elemType)
	if len(fieldIndices) == 0 {
		return "", fmt.Errorf("no fields with JSON tags found in struct")
	}

	// Extract column headers from JSON tags
	headers := extractHeaders(elemType, fieldIndices)

	buf := new(bytes.Buffer)
	w := tabwriter.NewWriter(buf, 0, 0, 3, ' ', 0)

	// Write header row
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, strings.Join(headers, "\t"))

	// Write data rows
	for i := 0; i < v.Len(); i++ {
		elem := v.Index(i)
		// Handle pointer to struct
		if elem.Kind() == reflect.Ptr {
			if elem.IsNil() {
				continue
			}
			elem = elem.Elem()
		}

		row := extractRow(elem, fieldIndices)
		fmt.Fprintln(w, strings.Join(row, "\t"))
	}

	w.Flush()
	return buf.String(), nil
}

// getJSONFieldIndices returns the indices of fields that have JSON tags
func getJSONFieldIndices(t reflect.Type) []int {
	var indices []int
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)

		// Skip unexported fields
		if !field.IsExported() {
			continue
		}

		// Only include fields with JSON tags
		jsonTag := field.Tag.Get("json")
		if jsonTag == "" || jsonTag == "-" {
			continue
		}

		// Handle json tag options like `json:"name,omitempty"` - skip if name part is empty
		parts := strings.Split(jsonTag, ",")
		if parts[0] == "" {
			continue
		}

		indices = append(indices, i)
	}
	return indices
}

// extractHeaders extracts column headers from struct JSON tags for the given field indices
func extractHeaders(t reflect.Type, fieldIndices []int) []string {
	headers := make([]string, 0, len(fieldIndices))
	for _, idx := range fieldIndices {
		field := t.Field(idx)
		jsonTag := field.Tag.Get("json")
		parts := strings.Split(jsonTag, ",")
		headers = append(headers, parts[0])
	}
	return headers
}

// extractRow extracts values from a struct as strings for the given field indices
func extractRow(v reflect.Value, fieldIndices []int) []string {
	row := make([]string, 0, len(fieldIndices))
	for _, idx := range fieldIndices {
		fieldValue := v.Field(idx)
		row = append(row, formatValue(fieldValue))
	}
	return row
}

// formatValue converts a reflect.Value to its string representation
func formatValue(v reflect.Value) string {
	// Handle nil pointers
	if v.Kind() == reflect.Ptr {
		if v.IsNil() {
			return "N/A"
		}
		v = v.Elem()
	}

	// Handle interface types
	if v.Kind() == reflect.Interface {
		if v.IsNil() {
			return "N/A"
		}
		v = v.Elem()
	}

	switch v.Kind() {
	case reflect.String:
		s := v.String()
		if s == "" {
			return "N/A"
		}
		return s
	case reflect.Bool:
		return fmt.Sprintf("%t", v.Bool())
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return fmt.Sprintf("%d", v.Int())
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return fmt.Sprintf("%d", v.Uint())
	case reflect.Float32, reflect.Float64:
		return fmt.Sprintf("%g", v.Float())
	case reflect.Slice, reflect.Array:
		if v.Len() == 0 {
			return "N/A"
		}
		return fmt.Sprintf("%v", v.Interface())
	case reflect.Struct:
		// Check if the struct implements Stringer
		if stringer, ok := v.Interface().(fmt.Stringer); ok {
			return stringer.String()
		}
		return fmt.Sprintf("%v", v.Interface())
	default:
		return fmt.Sprintf("%v", v.Interface())
	}
}

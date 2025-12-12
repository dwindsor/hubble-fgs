package agw

import (
	"bytes"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"text/tabwriter"
)

// FormatTable generates a formatted table string from various data types.
// It supports:
//   - Slices of structs: Uses JSON tags as column headers
//   - Maps: Displays key-value pairs in a two-column table
//   - Structs: Displays field names and values in a two-column table
//
// Parameters:
//   - items: a slice of structs, map, or struct
//
// Returns:
//   - A formatted table string with columns aligned using tabwriter
//   - An error if the input type is not supported
func FormatTable(items interface{}) (string, error) {
	v := reflect.ValueOf(items)

	// Handle pointer
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}

	switch v.Kind() {
	case reflect.Slice:
		return formatSliceTable(v)
	case reflect.Map:
		return formatMapTable(v)
	case reflect.Struct:
		return formatStructTable(v)
	default:
		return "", fmt.Errorf("FormatTable requires a slice, map, or struct, got %s", v.Kind())
	}
}

// formatSliceTable formats a slice of structs as a table
func formatSliceTable(v reflect.Value) (string, error) {
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

// formatMapTable formats a map as a two-column key-value table
func formatMapTable(v reflect.Value) (string, error) {
	if v.Len() == 0 {
		return "", nil
	}

	buf := new(bytes.Buffer)
	w := tabwriter.NewWriter(buf, 0, 0, 3, ' ', 0)

	// Get and sort keys for consistent output
	keys := v.MapKeys()
	sortMapKeys(keys)

	// Write key-value pairs
	for _, key := range keys {
		val := v.MapIndex(key)
		keyStr := formatValue(key)
		valStr := formatValue(val)
		fmt.Fprintf(w, "  %s:\t%s\n", keyStr, valStr)
	}

	w.Flush()
	return buf.String(), nil
}

// formatStructTable formats a struct as a two-column field-value table
func formatStructTable(v reflect.Value) (string, error) {
	t := v.Type()

	buf := new(bytes.Buffer)
	w := tabwriter.NewWriter(buf, 0, 0, 3, ' ', 0)

	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)

		// Skip unexported fields
		if !field.IsExported() {
			continue
		}

		// Get display name from JSON tag or field name
		displayName := field.Name
		if jsonTag := field.Tag.Get("json"); jsonTag != "" && jsonTag != "-" {
			parts := strings.Split(jsonTag, ",")
			if parts[0] != "" {
				displayName = parts[0]
			}
		}

		fieldVal := v.Field(i)
		valStr := formatValue(fieldVal)

		fmt.Fprintf(w, "  %s:\t%s\n", displayName, valStr)
	}

	w.Flush()
	return buf.String(), nil
}

// FormatKeyValueTable formats a map or struct with a title header
func FormatKeyValueTable(title string, items interface{}) (string, error) {
	v := reflect.ValueOf(items)

	// Handle pointer
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}

	var content string
	var err error

	switch v.Kind() {
	case reflect.Map:
		content, err = formatMapTable(v)
	case reflect.Struct:
		content, err = formatStructTable(v)
	default:
		return "", fmt.Errorf("FormatKeyValueTable requires a map or struct, got %s", v.Kind())
	}

	if err != nil {
		return "", err
	}

	var b strings.Builder
	if title != "" {
		b.WriteString(fmt.Sprintf("─── %s ", title))
		// Pad to make consistent width
		padding := 65 - len(title) - 5
		if padding > 0 {
			b.WriteString(strings.Repeat("─", padding))
		}
		b.WriteString("\n")
	}
	b.WriteString(content)
	return b.String(), nil
}

// sortMapKeys sorts map keys for consistent output
func sortMapKeys(keys []reflect.Value) {
	if len(keys) == 0 {
		return
	}

	switch keys[0].Kind() {
	case reflect.String:
		sort.Slice(keys, func(i, j int) bool {
			return keys[i].String() < keys[j].String()
		})
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		sort.Slice(keys, func(i, j int) bool {
			return keys[i].Int() < keys[j].Int()
		})
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		sort.Slice(keys, func(i, j int) bool {
			return keys[i].Uint() < keys[j].Uint()
		})
	}
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

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
	"strings"
	"testing"

	"github.com/isovalent/ipa/application_model/v1alpha"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSanitizeUTF8AndMarshalJSON(t *testing.T) {
	// Create test data with invalid UTF-8
	invalidUTF8 := "\xff\xfe\xfd" // Invalid UTF-8 sequence

	model := &v1alpha.ApplicationModel{
		Host: &v1alpha.ApplicationHost{
			Processes: []*v1alpha.ApplicationProcessGroup{
				{
					Name:      "/bin/test" + invalidUTF8,       // Invalid UTF-8 in name
					Arguments: "arg1 " + invalidUTF8 + " arg2", // Invalid UTF-8 in arguments
				},
				{
					Name:      "/bin/valid",
					Arguments: "valid args", // Valid UTF-8
				},
			},
		},
		Namespaces: []*v1alpha.ApplicationNamespace{
			{
				Name: "test-namespace",
				Workloads: []*v1alpha.ApplicationWorkload{
					{
						Name: "workload" + invalidUTF8, // Invalid UTF-8 in workload name
						Processes: []*v1alpha.ApplicationProcessGroup{
							{
								Name:      "/app/binary",
								Arguments: "valid args",
							},
						},
					},
				},
			},
		},
	}

	// Test that regular JSON marshaling would fail or produce invalid output
	_, err := json.Marshal(model)
	if err == nil {
		// Even if marshaling succeeds, the JSON might contain invalid UTF-8
		t.Logf("Regular JSON marshaling succeeded, but may contain invalid UTF-8")
	}

	// Test our sanitizing function
	sanitizedJSON, err := SanitizeUTF8AndMarshalJSON(model)
	require.NoError(t, err, "SanitizeUTF8AndMarshalJSON should not fail")

	// Verify the result is valid JSON
	var result map[string]interface{}
	err = json.Unmarshal(sanitizedJSON, &result)
	require.NoError(t, err, "Sanitized JSON should be valid")

	// Verify invalid UTF-8 strings were replaced
	jsonString := string(sanitizedJSON)
	assert.Contains(t, jsonString, invalidUTF8Replacement, "JSON should contain replacement string")
	assert.NotContains(t, jsonString, invalidUTF8, "JSON should not contain original invalid UTF-8")

	// Count occurrences of replacement string
	count := strings.Count(jsonString, invalidUTF8Replacement)
	assert.Equal(t, 3, count, "Should have replaced 3 invalid UTF-8 strings")

	t.Logf("Sanitized JSON: %s", string(sanitizedJSON))
}

func TestSanitizeUTF8AndMarshalJSON_ValidUTF8(t *testing.T) {
	// Create test data with only valid UTF-8
	model := &v1alpha.ApplicationModel{
		Host: &v1alpha.ApplicationHost{
			Processes: []*v1alpha.ApplicationProcessGroup{
				{
					Name:      "/bin/test",
					Arguments: "arg1 arg2",
				},
			},
		},
	}

	// Test our sanitizing function with valid data
	sanitizedJSON, err := SanitizeUTF8AndMarshalJSON(model)
	require.NoError(t, err, "SanitizeUTF8AndMarshalJSON should not fail with valid UTF-8")

	// Verify the result is valid JSON
	var result map[string]interface{}
	err = json.Unmarshal(sanitizedJSON, &result)
	require.NoError(t, err, "Sanitized JSON should be valid")

	// Verify no replacement strings were added
	jsonString := string(sanitizedJSON)
	assert.NotContains(t, jsonString, invalidUTF8Replacement, "JSON should not contain replacement string for valid UTF-8")
}

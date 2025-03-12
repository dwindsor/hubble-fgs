//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package alerts

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/isovalent/hubble-fgs/pkg/option"
)

func TestEvaluateRules(t *testing.T) {
	t.Cleanup(func() {
		option.Config.AlertsExportDir = ""
	})
	a := newAlerter(t.Context())

	// Add two alert rules, no JSON export
	a.ruleManager.AddAlertRule(exampleAR)
	a.ruleManager.AddAlertRule(anotherAR)
	// Set export directory
	option.Config.AlertsExportDir = t.TempDir()
	// Add same two alert rules, but with JSON export enabled
	exampleCopy := exampleAR.DeepCopy()
	exampleCopy.ObjectMeta.Name = "curl2"
	a.ruleManager.AddAlertRule(exampleCopy)
	anotherCopy := anotherAR.DeepCopy()
	anotherCopy.ObjectMeta.Name = "shell2"
	a.ruleManager.AddAlertRule(anotherCopy)
	assert.Len(t, a.ruleManager.rules, 4)

	// Evaluate example event against rules - curls should match, shells not
	err := a.evaluateRules(t.Context(), exampleEvent)
	assert.NoError(t, err)

	// Check if alerts JSON files are correctly written
	expectedFiles := map[string]string{
		"curl2.log":  `{"event":{"process_exec":{"process":{"binary":"/usr/bin/curl","arguments":"ebpf.io"}},"time":"1970-01-01T00:00:00Z"},"rule":{"name":"curl2","severity":"CRITICAL","message":"Curl is curling.","tags":["network"]}}` + "\n",
		"shell2.log": "", // not matched
	}
	files, err := os.ReadDir(option.Config.AlertsExportDir)
	assert.NoError(t, err)
	found := make(map[string]bool)
	for _, f := range files {
		found[f.Name()] = true
	}
	for filename, expectedContent := range expectedFiles {
		assert.Contains(t, found, filename)
		filepath := filepath.Join(option.Config.AlertsExportDir, filename)
		content, err := os.ReadFile(filepath)
		assert.NoError(t, err)
		assert.Equal(t, expectedContent, normalizeJSON(string(content)))
	}
}

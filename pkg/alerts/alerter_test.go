// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package alerts

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/tetragon/api/v1/tetragon"

	"github.com/isovalent/hubble-fgs/pkg/option"
)

func TestEvaluateRules(t *testing.T) {
	t.Cleanup(func() {
		option.Config.AlertsExportDir = ""
	})
	a := newAlerter(t.Context(), NewRuleManager())

	// Add two alert rules, no JSON export
	a.ruleManager.AddAlertRule(exampleAR)
	a.ruleManager.AddAlertRule(anotherAR)
	// Set export directory
	option.Config.AlertsExportDir = t.TempDir()
	// Add same two alert rules, but with JSON export enabled
	exampleCopy := exampleAR.DeepCopy()
	exampleCopy.Name = "curl2"
	a.ruleManager.AddAlertRule(exampleCopy)
	anotherCopy := anotherAR.DeepCopy()
	anotherCopy.Name = "shell2"
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
		filepath := filepath.Join(option.Config.AlertsExportDir, filename)
		content, err := os.ReadFile(filepath)
		// NB: if the rule did not match, then file might not exist (indeed, the lumberjack
		// writer we use will not write a file)
		if len(expectedContent) == 0 {
			assert.Equal(t, 0, len(content))
		} else {
			assert.NoError(t, err)
			assert.Contains(t, found, filename)
			assert.Equal(t, expectedContent, normalizeJSON(string(content)))
		}
	}
}

var exampleYAML = `
apiVersion: cilium.io/v1alpha1
kind: AlertRule
metadata:
  name: curl
spec:
  expression: process_exec.process.binary.contains("curl")
  message: Curl is curling.
  severity: critical
  tags: [network]
`

var updatedYAML = `
apiVersion: cilium.io/v1alpha1
kind: AlertRule
metadata:
  name: curl
spec:
  expression: process_exec.process.binary == "/usr/bin/curl"
  message: Curl is curling in /usr/bin.
  severity: info
  tags: [http]
`

var anotherYAML = `
apiVersion: cilium.io/v1alpha1
kind: AlertRule
metadata:
  name: shell
spec:
  expression: process_exec.process.binary.contains("sh")
  message: Looks like shell.
  severity: warning
  tags: [shell]
`

func TestRPCAddAlertRuleFromYAML(t *testing.T) {
	a := newAlerter(t.Context(), NewRuleManager())

	expectedProtos := []*tetragon.AlertRule{
		{
			Meta: &tetragon.AlertRuleMeta{
				Name:     "curl",
				Severity: tetragon.AlertRuleMeta_CRITICAL,
				Message:  "Curl is curling.",
				Tags:     []string{"network"},
			},
		}, {
			Meta: &tetragon.AlertRuleMeta{
				Name:     "shell",
				Severity: tetragon.AlertRuleMeta_WARNING,
				Message:  "Looks like shell.",
				Tags:     []string{"shell"},
			},
		},
	}

	for i, yaml := range []string{exampleYAML, anotherYAML} {
		// Add a rule
		req := &tetragon.AddAlertRuleFromYAMLRequest{Yaml: yaml}
		resp, err := a.AddAlertRuleFromYAML(t.Context(), req)
		assert.NoError(t, err)
		assert.NotNil(t, resp)

		// Check the rule got added and the response is correct
		assert.Len(t, a.ruleManager.rules, i+1)
		assert.Equal(t, expectedProtos[i], resp.Rule)
	}
}

func TestRPCAddAlertRuleFromYAMLUpdate(t *testing.T) {
	a := newAlerter(t.Context(), NewRuleManager())

	// Add two rules
	a.ruleManager.AddAlertRule(exampleAR)
	a.ruleManager.AddAlertRule(anotherAR)

	// Update a rule
	req := &tetragon.AddAlertRuleFromYAMLRequest{Yaml: updatedYAML}
	resp, err := a.AddAlertRuleFromYAML(t.Context(), req)
	assert.NoError(t, err)
	assert.NotNil(t, resp)

	// Check the rule got updated and the response is correct
	assert.Len(t, a.ruleManager.rules, 2)
	assert.Equal(t, &tetragon.AlertRule{
		Meta: &tetragon.AlertRuleMeta{
			Name:     "curl",
			Severity: tetragon.AlertRuleMeta_INFO,
			Message:  "Curl is curling in /usr/bin.",
			Tags:     []string{"http"},
		},
	}, resp.Rule)
}

func TestRPCAddAlertRuleFromYAMLInvalid(t *testing.T) {
	a := newAlerter(t.Context(), NewRuleManager())

	for _, yaml := range []string{
		"not a valid yaml",
		"",
	} {
		req := &tetragon.AddAlertRuleFromYAMLRequest{Yaml: yaml}
		resp, err := a.AddAlertRuleFromYAML(t.Context(), req)
		assert.Error(t, err)
		assert.Nil(t, resp)
		assert.Len(t, a.ruleManager.rules, 0)
	}
}

func TestRPCDeleteAlertRule(t *testing.T) {
	a := newAlerter(t.Context(), NewRuleManager())

	// Add two rules
	a.ruleManager.AddAlertRule(exampleAR)
	a.ruleManager.AddAlertRule(anotherAR)

	// Delete a rule
	req := &tetragon.DeleteAlertRuleRequest{Name: "shell"}
	resp, err := a.DeleteAlertRule(t.Context(), req)
	assert.NoError(t, err)
	assert.NotNil(t, resp)

	// Check the rule got deleted
	assert.Len(t, a.ruleManager.rules, 1)
	_, exists := a.ruleManager.rules["shell"]
	assert.False(t, exists)
}

func TestRPCListAlertRules(t *testing.T) {
	a := newAlerter(t.Context(), NewRuleManager())

	// Add two rules
	a.ruleManager.AddAlertRule(exampleAR)
	a.ruleManager.AddAlertRule(anotherAR)

	// List rules
	req := &tetragon.ListAlertRulesRequest{}
	resp, err := a.ListAlertRules(t.Context(), req)
	assert.NoError(t, err)
	assert.NotNil(t, resp)

	// Check the response is correct
	assert.Len(t, resp.Rules, 2)
	assert.ElementsMatch(t, []*tetragon.AlertRule{
		{
			Meta: &tetragon.AlertRuleMeta{
				Name:     "curl",
				Severity: tetragon.AlertRuleMeta_CRITICAL,
				Message:  "Curl is curling.",
				Tags:     []string{"network"},
			},
		}, {
			Meta: &tetragon.AlertRuleMeta{
				Name:     "shell",
				Severity: tetragon.AlertRuleMeta_WARNING,
				Message:  "Looks like shell.",
				Tags:     []string{"shell"},
			},
		},
	}, resp.Rules)
}

func TestRPCGetAlertRule(t *testing.T) {
	a := newAlerter(t.Context(), NewRuleManager())

	// Add two rules
	a.ruleManager.AddAlertRule(exampleAR)
	a.ruleManager.AddAlertRule(anotherAR)

	// Get a rule
	req := &tetragon.GetAlertRuleRequest{Name: "shell"}
	resp, err := a.GetAlertRule(t.Context(), req)
	assert.NoError(t, err)
	assert.NotNil(t, resp)

	// Check the response is correct
	assert.Equal(t, &tetragon.GetAlertRuleResponse{
		Rule: &tetragon.AlertRule{
			Meta: &tetragon.AlertRuleMeta{
				Name:     "shell",
				Severity: tetragon.AlertRuleMeta_WARNING,
				Message:  "Looks like shell.",
				Tags:     []string{"shell"},
			},
		},
	}, resp)
}

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
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	eeOption "github.com/isovalent/hubble-fgs/pkg/option"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
)

var exampleAR = &v1alpha1.AlertRule{
	ObjectMeta: metav1.ObjectMeta{
		Name: "curl",
	},
	Spec: v1alpha1.AlertRuleSpec{
		Expression: "process_exec.process.binary.contains(\"curl\")",
		Message:    "Curl is curling.",
		Tags:       []string{"network"},
		Severity:   "critical",
	},
}

var updatedAR = &v1alpha1.AlertRule{
	ObjectMeta: metav1.ObjectMeta{
		Name: exampleAR.GetName(),
	},
	Spec: v1alpha1.AlertRuleSpec{
		Expression: "process_exec.process.binary == \"/usr/bin/curl\"",
		Message:    "Curl is curling in /usr/bin.",
		Tags:       []string{"http"},
		Severity:   "info",
		Export:     v1alpha1.AlertExport{Filename: "test.log"},
	},
}

var anotherAR = &v1alpha1.AlertRule{
	ObjectMeta: metav1.ObjectMeta{
		Name: "shell",
	},
	Spec: v1alpha1.AlertRuleSpec{
		Expression: "process_exec.process.binary.contains(\"sh\")",
		Message:    "Looks like shell.",
		Tags:       []string{"shell"},
		Severity:   "warning",
		Export:     v1alpha1.AlertExport{Filename: "test.log"},
	},
}

func TestAddAlertRule(t *testing.T) {
	rm := NewRuleManager()
	for i, ar := range []*v1alpha1.AlertRule{exampleAR, anotherAR} {
		// Add a rule
		err := rm.AddAlertRule(ar)
		assert.NoError(t, err)
		assert.Len(t, rm.rules, i+1)

		// Check the rule got added correctly
		rule, ok := rm.rules[ar.GetName()]
		assert.True(t, ok)
		assert.NotNil(t, rule)
		assert.NotNil(t, rule.cel)
		assert.Equal(t, ar.Spec.Message, rule.message)
		assert.Equal(t, ar.Spec.Tags, rule.tags)
		assert.Equal(t, ar.Spec.Severity, rule.severity)
	}
}

func TestUpdateAlertRule(t *testing.T) {
	// Set an alertsexportdir to trigger creation of encoders
	eeOption.Config.AlertsExportDir = os.TempDir()

	rm := NewRuleManager()
	// Add a rule
	rm.AddAlertRule(exampleAR)
	assert.Len(t, rm.rules, 1)
	// The rule has no Export.Filename; it uses default `GetName() + ".log"`.
	assert.NotNil(t, rm.encoders[exampleAR.GetName()+".log"])
	ogCEL := rm.rules[exampleAR.GetName()].cel

	// Update the rule
	err := rm.AddAlertRule(updatedAR)
	assert.NoError(t, err)
	assert.Len(t, rm.rules, 1) // replaced
	// The rule has Export.Filename
	assert.NotNil(t, rm.encoders[updatedAR.Spec.Export.Filename])

	// Check the rule got added correctly
	rule, ok := rm.rules[updatedAR.GetName()]
	assert.True(t, ok)
	assert.NotNil(t, rule)
	assert.NotEqual(t, ogCEL, rule.cel)
	assert.Equal(t, updatedAR.Spec.Message, rule.message)
	assert.Equal(t, updatedAR.Spec.Tags, rule.tags)
	assert.Equal(t, updatedAR.Spec.Severity, rule.severity)
}

func TestAddNil(t *testing.T) {
	rm := NewRuleManager()
	err := rm.AddAlertRule(nil)
	assert.NoError(t, err)
	assert.Len(t, rm.rules, 0)
}

func TestDeleteAlertRule(t *testing.T) {
	rm := NewRuleManager()
	// Add a rule
	rm.AddAlertRule(exampleAR)
	assert.Len(t, rm.rules, 1)

	// Delete the rule
	rm.DeleteAlertRule(exampleAR.GetName())
	assert.Len(t, rm.rules, 0)
}

func TestAddSameRule(t *testing.T) {
	oldVal := eeOption.Config.AlertsExportDir
	eeOption.Config.AlertsExportDir = t.TempDir()
	t.Cleanup(func() {
		eeOption.Config.AlertsExportDir = oldVal
	})

	ruleName := exampleAR.GetName()
	rm := NewRuleManager()
	err := rm.AddAlertRule(exampleAR)
	assert.NoError(t, err)
	err = rm.AddAlertRule(exampleAR)
	assert.NoError(t, err)
	assert.Len(t, rm.rules, 1)
	assert.Len(t, rm.encoders, 1)
	encoder := rm.rules[ruleName].jsonEncoder
	assert.Equal(t, int32(1), encoder.refCnt.Load())
	rm.DeleteAlertRule(ruleName)
	assert.Len(t, rm.rules, 0)
	assert.Len(t, rm.encoders, 0)
	assert.Equal(t, int32(0), encoder.refCnt.Load())
}

func TestAddFilenameRule(t *testing.T) {
	oldVal := eeOption.Config.AlertsExportDir
	eeOption.Config.AlertsExportDir = t.TempDir()
	t.Cleanup(func() {
		eeOption.Config.AlertsExportDir = oldVal
	})

	rm := NewRuleManager()

	ruleName := exampleAR.GetName()
	err := rm.addAlertRuleWithFilename(exampleAR, "pizza")
	assert.NoError(t, err)

	anotherRuleName := anotherAR.GetName()
	err = rm.addAlertRuleWithFilename(anotherAR, "burger")
	assert.NoError(t, err)

	assert.Len(t, rm.rules, 2)
	assert.Contains(t, rm.rules, ruleName)

	encoder1 := rm.rules[ruleName].jsonEncoder
	encoder2 := rm.rules[anotherRuleName].jsonEncoder
	assert.NotEqual(t, encoder1, encoder2)
	assert.Equal(t, int32(1), encoder1.refCnt.Load())
	assert.Equal(t, int32(1), encoder2.refCnt.Load())
	assert.Len(t, rm.rules, 2)
	assert.Len(t, rm.encoders, 2)

	rm.DeleteAlertRule(ruleName)
	assert.Len(t, rm.rules, 1)
	assert.Len(t, rm.encoders, 1)
	assert.Equal(t, int32(0), encoder1.refCnt.Load())
	assert.Equal(t, int32(1), encoder2.refCnt.Load())

	rm.DeleteAlertRule(anotherRuleName)
	assert.Len(t, rm.rules, 0)
	assert.Len(t, rm.encoders, 0)
	assert.Equal(t, int32(0), encoder1.refCnt.Load())
	assert.Equal(t, int32(0), encoder2.refCnt.Load())
}

func TestAddSameFilenameRule(t *testing.T) {
	oldVal := eeOption.Config.AlertsExportDir
	tmpDir := t.TempDir()
	eeOption.Config.AlertsExportDir = tmpDir
	t.Cleanup(func() {
		eeOption.Config.AlertsExportDir = oldVal
	})

	rm := NewRuleManager()

	// add one rule
	ruleName := exampleAR.GetName()
	err := rm.addAlertRuleWithFilename(exampleAR, "pizza")
	assert.NoError(t, err)

	// add a second rule, with the same filename
	anotherRuleName := anotherAR.GetName()
	err = rm.addAlertRuleWithFilename(anotherAR, "pizza")
	assert.NoError(t, err)

	// now we have two rules
	assert.Len(t, rm.rules, 2)
	assert.Contains(t, rm.rules, ruleName)
	assert.Contains(t, rm.rules, anotherRuleName)

	// but, because the files are the same we have 1 encoder with a reference count of 2
	encoder1 := rm.rules[ruleName].jsonEncoder
	encoder2 := rm.rules[anotherRuleName].jsonEncoder
	assert.Equal(t, encoder1, encoder2)
	assert.Equal(t, int32(2), encoder1.refCnt.Load())
	assert.Len(t, rm.encoders, 1)

	// write one
	err = encoder1.encode(eventToAlert(nil, exampleRule), nil)
	assert.NoError(t, err)

	// delete one rule, we are left with one rule and one encoder
	rm.DeleteAlertRule(ruleName)
	assert.Len(t, rm.rules, 1)
	assert.Len(t, rm.encoders, 1)
	assert.Equal(t, int32(1), encoder1.refCnt.Load())

	// write two
	err = encoder1.encode(eventToAlert(nil, exampleRule), nil)
	assert.NoError(t, err)

	// delete the other rule, no encoders and no rules remain
	rm.DeleteAlertRule(anotherRuleName)
	assert.Len(t, rm.rules, 0)
	assert.Len(t, rm.encoders, 0)
	assert.Equal(t, int32(0), encoder1.refCnt.Load())

	// write two, this should not appear because we have closed the file
	err = encoder1.encode(eventToAlert(nil, exampleRule), nil)
	assert.NoError(t, err)

	data, err := os.ReadFile(filepath.Join(tmpDir, "pizza"))
	assert.NoError(t, err)
	rule := `{"rule":{"name":"curl","severity":"CRITICAL","message":"Curl is curling.","tags":["network"]}}`
	expected := fmt.Sprintf("%s\n%s\n", rule, rule)
	assert.Equal(t, expected, normalizeJSON(string(data)))
}

func TestAddAlertRuleSameFilename(t *testing.T) {
	eeOption.Config.AlertsExportDir = t.TempDir()
	t.Cleanup(func() {
		eeOption.Config.AlertsExportDir = ""
	})

	rm := NewRuleManager()
	var rules []*rule
	for i, ar := range []*v1alpha1.AlertRule{updatedAR, anotherAR} {
		// Add a rule
		err := rm.AddAlertRule(ar)
		assert.NoError(t, err)
		assert.Len(t, rm.rules, i+1)

		// Check the rule got added correctly
		rule, ok := rm.rules[ar.GetName()]
		assert.True(t, ok)
		assert.NotNil(t, rule)
		assert.NotNil(t, rule.cel)
		assert.Equal(t, ar.Spec.Message, rule.message)
		assert.Equal(t, ar.Spec.Tags, rule.tags)
		assert.Equal(t, ar.Spec.Severity, rule.severity)
		rules = append(rules, rule)
	}

	wg := sync.WaitGroup{}
	for _, rule := range rules {
		wg.Go(func() {
			err := rule.jsonEncoder.encode(exampleAlert(), nil)
			assert.NoError(t, err)
		})
	}

	wg.Wait()

	// Check that the output file was created and contains correct data
	expectedFiles := map[string]string{
		"test.log": `{"event":{"process_exec":{"process":{"binary":"/usr/bin/curl","arguments":"ebpf.io"}},"time":"1970-01-01T00:00:00Z"},"rule":{"name":"curl","severity":"CRITICAL","message":"Curl is curling.","tags":["network"]}}
{"event":{"process_exec":{"process":{"binary":"/usr/bin/curl","arguments":"ebpf.io"}},"time":"1970-01-01T00:00:00Z"},"rule":{"name":"curl","severity":"CRITICAL","message":"Curl is curling.","tags":["network"]}}
`,
	}
	files, err := os.ReadDir(eeOption.Config.AlertsExportDir)
	assert.NoError(t, err)
	found := make(map[string]bool)
	for _, f := range files {
		found[f.Name()] = true
	}
	assert.Contains(t, found, "test.log")
	for filename, expectedContent := range expectedFiles {
		fpath := filepath.Join(eeOption.Config.AlertsExportDir, filename)
		content, err := os.ReadFile(fpath)
		assert.NoError(t, err)
		assert.Equal(t, expectedContent, normalizeJSON(string(content)))
	}
}

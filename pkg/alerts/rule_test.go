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
	"fmt"
	"os"
	"path/filepath"
	"testing"

	eeOption "github.com/isovalent/hubble-fgs/pkg/option"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/tetragon/api/v1/tetragon"
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
	},
}

func TestAddAlertRule(t *testing.T) {
	rm := newRuleManager()
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
	rm := newRuleManager()
	// Add a rule
	rm.AddAlertRule(exampleAR)
	assert.Len(t, rm.rules, 1)
	ogCEL := rm.rules[exampleAR.GetName()].cel

	// Update the rule
	err := rm.AddAlertRule(updatedAR)
	assert.NoError(t, err)
	assert.Len(t, rm.rules, 1) // replaced

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
	rm := newRuleManager()
	err := rm.AddAlertRule(nil)
	assert.NoError(t, err)
	assert.Len(t, rm.rules, 0)
}

func TestDeleteAlertRule(t *testing.T) {
	rm := newRuleManager()
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
	rm := newRuleManager()
	err := rm.AddAlertRule(exampleAR)
	assert.NoError(t, err)
	err = rm.AddAlertRule(exampleAR)
	assert.NoError(t, err)
	assert.Len(t, rm.rules, 1)
	assert.Len(t, rm.encoders, 1)
	encoder := rm.rules[ruleName].jsonEncoder
	assert.Equal(t, int32(1), encoder.refCnt)
	rm.DeleteAlertRule(ruleName)
	assert.Len(t, rm.rules, 0)
	assert.Len(t, rm.encoders, 0)
	assert.Equal(t, int32(0), encoder.refCnt)
}

func TestAddFilanameRule(t *testing.T) {
	oldVal := eeOption.Config.AlertsExportDir
	eeOption.Config.AlertsExportDir = t.TempDir()
	t.Cleanup(func() {
		eeOption.Config.AlertsExportDir = oldVal
	})

	rm := newRuleManager()

	ruleName := exampleAR.GetName()
	err := rm.AddAlertRuleWithFilename(exampleAR, "pizza")
	assert.NoError(t, err)

	anotherRuleName := anotherAR.GetName()
	err = rm.AddAlertRuleWithFilename(anotherAR, "burger")
	assert.NoError(t, err)

	assert.Len(t, rm.rules, 2)
	assert.Contains(t, rm.rules, ruleName)

	encoder1 := rm.rules[ruleName].jsonEncoder
	encoder2 := rm.rules[anotherRuleName].jsonEncoder
	assert.NotEqual(t, encoder1, encoder2)
	assert.Equal(t, int32(1), encoder1.refCnt)
	assert.Equal(t, int32(1), encoder2.refCnt)
	assert.Len(t, rm.rules, 2)
	assert.Len(t, rm.encoders, 2)

	rm.DeleteAlertRule(ruleName)
	assert.Len(t, rm.rules, 1)
	assert.Len(t, rm.encoders, 1)
	assert.Equal(t, int32(0), encoder1.refCnt)
	assert.Equal(t, int32(1), encoder2.refCnt)

	rm.DeleteAlertRule(anotherRuleName)
	assert.Len(t, rm.rules, 0)
	assert.Len(t, rm.encoders, 0)
	assert.Equal(t, int32(0), encoder1.refCnt)
	assert.Equal(t, int32(0), encoder2.refCnt)
}

func TestAddSameFilenameRule(t *testing.T) {
	oldVal := eeOption.Config.AlertsExportDir
	tmpDir := t.TempDir()
	eeOption.Config.AlertsExportDir = tmpDir
	t.Cleanup(func() {
		eeOption.Config.AlertsExportDir = oldVal
	})

	rm := newRuleManager()

	// add one rule
	ruleName := exampleAR.GetName()
	err := rm.AddAlertRuleWithFilename(exampleAR, "pizza")
	assert.NoError(t, err)

	// add a second rule, with the same filename
	anotherRuleName := anotherAR.GetName()
	err = rm.AddAlertRuleWithFilename(anotherAR, "pizza")
	assert.NoError(t, err)

	// now we have two rules
	assert.Len(t, rm.rules, 2)
	assert.Contains(t, rm.rules, ruleName)
	assert.Contains(t, rm.rules, anotherRuleName)

	// but, because the files are the same we have 1 encoder with a reference count of 2
	encoder1 := rm.rules[ruleName].jsonEncoder
	encoder2 := rm.rules[anotherRuleName].jsonEncoder
	assert.Equal(t, encoder1, encoder2)
	assert.Equal(t, int32(2), encoder1.refCnt)
	assert.Len(t, rm.encoders, 1)

	// write one
	err = encoder1.encode(&tetragon.Alert{Rule: exampleRule})
	assert.NoError(t, err)

	// delete one rule, we are left with one rule and one encoder
	rm.DeleteAlertRule(ruleName)
	assert.Len(t, rm.rules, 1)
	assert.Len(t, rm.encoders, 1)
	assert.Equal(t, int32(1), encoder1.refCnt)

	// write two
	err = encoder1.encode(&tetragon.Alert{Rule: exampleRule})
	assert.NoError(t, err)

	// delete the other rule, no encoders and no rules remain
	rm.DeleteAlertRule(anotherRuleName)
	assert.Len(t, rm.rules, 0)
	assert.Len(t, rm.encoders, 0)
	assert.Equal(t, int32(0), encoder1.refCnt)

	// write two, this should not appear because we have closed the file
	err = encoder1.encode(&tetragon.Alert{Rule: exampleRule})
	assert.NoError(t, err)

	data, err := os.ReadFile(filepath.Join(tmpDir, "pizza"))
	assert.NoError(t, err)
	rule := `{"rule":{"name":"curl","severity":"CRITICAL","message":"Curl is curling.","tags":["network"]}}`
	expected := fmt.Sprintf("%s\n%s\n", rule, rule)
	assert.Equal(t, expected, normalizeJSON(string(data)))
}

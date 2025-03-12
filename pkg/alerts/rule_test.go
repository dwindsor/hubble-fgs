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
	"testing"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

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

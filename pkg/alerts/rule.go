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
	"path/filepath"
	"sync"

	"github.com/google/cel-go/cel"

	"github.com/cilium/tetragon/pkg/filters"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/logger"

	"github.com/isovalent/hubble-fgs/pkg/metrics/alertmetrics"
	eeOption "github.com/isovalent/hubble-fgs/pkg/option"
)

var (
	cef = filters.NewCELExpressionFilter(logger.GetLogger())
)

type rule struct {
	cel         cel.Program
	name        string
	message     string
	tags        []string
	severity    string
	jsonEncoder *jsonEncoder
}

type RuleManager interface {
	AddAlertRule(ar *v1alpha1.AlertRule) error
	DeleteAlertRule(name string)

	// Add an alert rule that writes on a specific filename.
	//
	// NB(kkourt): The mandate code uses this function so that it can install two alert rules
	// with the same name. In the future, we might expose the ability to specify a filename in
	// the alert rule in the spec as well.
	//
	// WARNING: If the fname argument is ever provided by the user, we need to validate it
	// (e.g., using ValidateDNS1123Subdomain) before calling this function.
	AddAlertRuleWithFilename(ar *v1alpha1.AlertRule, fname string) error
}

type ruleManager struct {
	rules    map[string]*rule
	encoders map[string]*jsonEncoder
	mutex    sync.RWMutex
}

func NewRuleManager() RuleManager {
	return newRuleManager()
}

func newRuleManager() *ruleManager {
	return &ruleManager{
		rules:    make(map[string]*rule),
		encoders: make(map[string]*jsonEncoder),
	}
}

// Add an alert rule that writes on a specific filename.
// This is useful for the mandate code. If you want to call this function, ensure that fname is
// sanitized if it comes from the user (e.g., using ValidateDNS1123Subdomain)
func (r *ruleManager) AddAlertRuleWithFilename(ar *v1alpha1.AlertRule, fname string) error {
	if ar == nil {
		return nil
	}

	name := ar.GetName()
	celProgram, err := cef.CompileCEL(ar.Spec.Expression)
	if err != nil {
		// Track compilation errors in metrics
		alertmetrics.AlertRuleCompilationErrors.WithLabelValues(name).Inc()
		return err
	}

	var encoder *jsonEncoder
	var newEncoder bool
	// use an existing encoder if one exists
	r.mutex.Lock()
	encoder = r.encoders[fname]
	if encoder != nil {
		encoder.IncRef()
	}
	r.mutex.Unlock()

	// if no existing encoder exists, let's create a new one by openning a new file
	if eeOption.Config.AlertsExportDir != "" && encoder == nil {
		filename := filepath.Join(eeOption.Config.AlertsExportDir, fname)
		lw, err := newLogWriter(filename)
		if err != nil {
			return err
		}
		encoder = newJsonEncoder(lw, fname)
		newEncoder = true
	}

	severity := ar.Spec.Severity
	r.mutex.Lock()
	// if we are replacing a rule, decref its encoder and update metrics
	if oldRule, ok := r.rules[name]; ok {
		r.encoderDecref(oldRule)
		// If we're replacing a rule with different severity, update metrics
		if oldRule.severity != severity {
			// Decrement the old severity count
			r.updateRuleMetrics()
		}
	}
	r.rules[name] = &rule{
		cel:         celProgram,
		name:        ar.GetName(),
		message:     ar.Spec.Message,
		tags:        ar.Spec.Tags,
		severity:    severity,
		jsonEncoder: encoder,
	}
	if newEncoder {
		r.encoders[fname] = encoder
	}

	// Update metrics after adding new rule
	r.updateRuleMetrics()
	r.mutex.Unlock()
	return nil
}

func (r *ruleManager) AddAlertRule(ar *v1alpha1.AlertRule) error {
	if ar == nil {
		return nil
	}
	return r.AddAlertRuleWithFilename(ar, ar.GetName()+".log")
}

// updateRuleMetrics calculates and updates metrics for alerting rules by severity
// Note: This method assumes the caller holds r.mutex lock
func (r *ruleManager) updateRuleMetrics() {
	// Create a map to count rules by severity
	severityCounts := make(map[string]int)

	// Count rules by severity
	for _, rule := range r.rules {
		severityCounts[rule.severity]++
	}

	// Use Prometheus to track the counts
	for severity, count := range severityCounts {
		alertmetrics.UpdateAlertRuleCount(severity, float64(count))
	}
}

func (r *ruleManager) DeleteAlertRule(name string) {
	r.mutex.Lock()
	if rule, ok := r.rules[name]; ok {
		r.encoderDecref(rule)
		delete(r.rules, name)

		// Only delete evaluation and compilation error metrics
		// We preserve the AlertTriggered metric to maintain historical data
		// for the lifetime of the Tetragon agent
		alertmetrics.DeleteEvaluationErrorMetric(rule.name)
		alertmetrics.DeleteCompilationErrorMetric(rule.name)

		// Update metrics after deleting a rule
		r.updateRuleMetrics()
	}
	r.mutex.Unlock()
}

// encoderDecref decreases the reference counter of rules jsonEncoder, and removes it from
// r.encoders if the reference count is 0
func (r *ruleManager) encoderDecref(rule *rule) {
	je := rule.jsonEncoder
	if je == nil {
		return
	}
	cnt := je.DecRef()
	if cnt == int32(0) {
		delete(r.encoders, je.fname)
	}
}

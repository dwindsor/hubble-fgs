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
	"path/filepath"
	"sync"
	"time"

	"github.com/cilium/tetragon/pkg/filters"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/google/cel-go/cel"
	"golang.org/x/time/rate"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"

	"github.com/cilium/tetragon/api/v1/tetragon/codegen/helpers"

	"github.com/isovalent/hubble-fgs/pkg/metrics/alertmetrics"
	eeOption "github.com/isovalent/hubble-fgs/pkg/option"
)

var (
	cef = filters.NewCELExpressionFilter(logger.GetLogger())
)

type rule struct {
	cel         cel.Program
	eventNames  []string
	name        string
	message     string
	tags        []string
	severity    string
	riskScore   int32
	jsonEncoder *jsonEncoder
	labels      map[string]string
}

type RuleManager interface {
	AddAlertRule(ar *v1alpha1.AlertRule) error
	DeleteAlertRule(name string)
}

// AlertRuleManager is an exposed type without any exposed field.
// Callers can only interact through implemented interfaces.
type AlertRuleManager struct {
	rules    map[string]*rule
	encoders map[string]*jsonEncoder
	eventMap map[string]any
	mutex    sync.RWMutex
}

func NewRuleManager() *AlertRuleManager {
	return &AlertRuleManager{
		rules:    make(map[string]*rule),
		encoders: make(map[string]*jsonEncoder),
		// Create a single empty (all values are nil) process event map
		// this removes the need to do map allocations for every incoming event.
		eventMap: helpers.ProcessEventMapEmpty(),
	}
}

// Add an alert rule that writes on a specific filename.
// This is an internal helper method.
func (r *AlertRuleManager) addAlertRuleWithFilename(ar *v1alpha1.AlertRule, fname string) error {
	name := ar.GetName()
	celProgram, eventNames, err := cef.CompileCEL(ar.Spec.Expression)
	if err != nil {
		// Track compilation errors in metrics
		alertmetrics.AlertRuleCompilationErrors.WithLabelValues(name).Inc()
		return err
	}

	var encoder *jsonEncoder
	var newEncoder bool
	// use an existing encoder if one exists
	r.mutex.Lock()
	defer r.mutex.Unlock()
	encoder = r.encoders[fname]
	if encoder != nil {
		encoder.IncRef()
	}

	// if no existing encoder exists, let's create a new one by openning a new file
	if eeOption.Config.AlertsExportDir != "" && encoder == nil {
		filename := filepath.Join(eeOption.Config.AlertsExportDir, fname)
		lw, err := newLogWriter(filename)
		if err != nil {
			return err
		}
		var rateLimiter *rate.Limiter
		if ar.Spec.Export.RateLimit.MaxEvents != 0 && ar.Spec.Export.RateLimit.Window != "" {
			// No need to check for error here since the string is pre-validated, see crd declaration.
			dur, _ := time.ParseDuration(ar.Spec.Export.RateLimit.Window)
			rateLimiter = rate.NewLimiter(rate.Every(dur), int(ar.Spec.Export.RateLimit.MaxEvents))
		}
		encoder = newRateLimitedJsonEncoder(lw, fname, rateLimiter)
		newEncoder = true
	}

	severity := ar.Spec.Severity
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
		eventNames:  eventNames,
		name:        ar.GetName(),
		message:     ar.Spec.Message,
		tags:        ar.Spec.Tags,
		severity:    severity,
		riskScore:   int32(ar.Spec.RiskScore),
		jsonEncoder: encoder,
		labels:      ar.Labels,
	}
	if newEncoder {
		r.encoders[fname] = encoder
	}

	// Update metrics after adding new rule
	r.updateRuleMetrics()
	return nil
}

func (r *AlertRuleManager) AddAlertRule(ar *v1alpha1.AlertRule) error {
	if ar == nil {
		return nil
	}
	fname := ar.GetName() + ".log"
	if eeOption.Config.AlertsExportFilename != "" {
		// This input comes directly from the user.
		// Handle with **extra** care!
		fname = eeOption.Config.AlertsExportFilename
	}
	// Alert export.filename overrides global option
	if ar.Spec.Export.Filename != "" {
		// This input comes directly from the user.
		// Handle with **extra** care!
		fname = ar.Spec.Export.Filename
	}
	// OpenInRoot returns an error if any component of the name
	// references a location outside dir.
	if !filepath.IsLocal(fname) {
		return fmt.Errorf("invalid alerts exporting filename (non local): '%s'", fname)
	}
	return r.addAlertRuleWithFilename(ar, fname)
}

// updateRuleMetrics calculates and updates metrics for alerting rules by severity
// Note: This method assumes the caller holds r.mutex lock
func (r *AlertRuleManager) updateRuleMetrics() {
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

func (r *AlertRuleManager) DeleteAlertRule(name string) {
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

func (r *AlertRuleManager) ListAlertRules() []*v1alpha1.AlertRule {
	r.mutex.Lock()
	rules := make([]*v1alpha1.AlertRule, 0, len(r.rules))
	for _, r := range r.rules {
		rules = append(rules, &v1alpha1.AlertRule{
			ObjectMeta: metav1.ObjectMeta{
				Name:   r.name,
				Labels: r.labels,
			},
			Spec: v1alpha1.AlertRuleSpec{
				Severity:  r.severity,
				Message:   r.message,
				Tags:      r.tags,
				RiskScore: int(r.riskScore),
			},
		})
	}
	r.mutex.Unlock()
	return rules
}

// encoderDecref decreases the reference counter of rules jsonEncoder, and removes it from
// r.encoders if the reference count is 0
func (r *AlertRuleManager) encoderDecref(rule *rule) {
	je := rule.jsonEncoder
	if je == nil {
		return
	}
	cnt := je.DecRef()
	if cnt == int32(0) {
		delete(r.encoders, je.fname)
	}
}

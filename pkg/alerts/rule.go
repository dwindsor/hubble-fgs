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

	"cel.dev/cel-go/cel"
	"github.com/cilium/tetragon/pkg/filters"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/server/eventlog"
	"golang.org/x/time/rate"

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
	rateLimiter *encoderRateLimiter
	domain      string
}

type RuleManager interface {
	AddAlertRule(ar *v1alpha1.AlertRule) error
	DeleteAlertRule(name, domain string)
}

type collectionKey struct {
	domain string
	name   string
}

// AlertRuleManager is an exposed type without any exposed field.
// Callers can only interact through implemented interfaces.
type AlertRuleManager struct {
	rules    map[collectionKey]*rule
	encoders map[string]*jsonEncoder
	eventMap map[string]any
	mutex    sync.RWMutex

	// encoders params
	maxSize          int
	rotationInterval time.Duration
	compress         bool
	maxBackups       int
}

func NewRuleManager() *AlertRuleManager {
	return &AlertRuleManager{
		rules:    make(map[collectionKey]*rule),
		encoders: make(map[string]*jsonEncoder),
		// Create a single empty (all values are nil) process event map
		// this removes the need to do map allocations for every incoming event.
		eventMap:         helpers.ProcessEventMapEmpty(),
		maxSize:          option.Config.ExportFileMaxSizeMB,
		maxBackups:       option.Config.ExportFileMaxBackups,
		compress:         option.Config.ExportFileCompress,
		rotationInterval: option.Config.ExportFileRotationInterval,
	}
}

func (r *AlertRuleManager) SetLogParams(params eventlog.Params) error {
	logger.GetLogger().Info("Updating alert manager params", "params", params)

	// Use the lock since we are going to update encoder params
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if params.MaxSize != nil {
		r.maxSize = int(*params.MaxSize)
	}

	if params.MaxBackups != nil {
		r.maxBackups = int(*params.MaxBackups)
	}

	if params.RotationInterval != nil {
		r.rotationInterval = *params.RotationInterval
	}

	// Update existing encoders params
	for _, enc := range r.encoders {
		if lw, ok := enc.writer.(*logWriter); ok {
			lw.mu.Lock()
			if !lw.closed {
				lw.l.MaxBackups = r.maxBackups
				lw.l.MaxSize = r.maxSize
				if lw.rotateTimer != nil {
					lw.rotateTimer.Stop()
				}
				lw.rotateTimer = time.AfterFunc(
					r.rotationInterval,
					lw.rotate,
				)
			}
			lw.mu.Unlock()
		}
	}

	return nil

}

// Add an alert rule that writes on a specific filename.
// This is an internal helper method.
func (r *AlertRuleManager) addAlertRuleWithFilename(ar *v1alpha1.AlertRule, fname string) error {
	name := ar.GetName()
	key := collectionKey{ar.Domain, name}
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
		lw, err := newLogWriter(filename, r.maxSize, r.maxBackups, r.compress, r.rotationInterval)
		if err != nil {
			return err
		}
		encoder = newJsonEncoder(lw, fname)
		newEncoder = true
	}

	var rateLimiter *encoderRateLimiter
	if encoder != nil {
		if ar.Spec.Export.RateLimit.MaxEvents != 0 && ar.Spec.Export.RateLimit.Window != "" {
			// No need to check for error here since the string is pre-validated, see crd declaration.
			dur, _ := time.ParseDuration(ar.Spec.Export.RateLimit.Window)
			rateLimiter = &encoderRateLimiter{
				Limiter:     rate.NewLimiter(rate.Every(dur), int(ar.Spec.Export.RateLimit.MaxEvents)),
				rateLimited: false,
			}
		}
	}

	severity := ar.Spec.Severity
	// if we are replacing a rule, decref its encoder and update metrics
	if oldRule, ok := r.rules[key]; ok {
		r.encoderDecref(oldRule)
		// If we're replacing a rule with different severity, update metrics
		if oldRule.severity != severity {
			// Decrement the old severity count
			r.updateRuleMetrics()
		}
	}

	r.rules[key] = &rule{
		cel:         celProgram,
		eventNames:  eventNames,
		name:        ar.GetName(),
		message:     ar.Spec.Message,
		tags:        ar.Spec.Tags,
		severity:    severity,
		riskScore:   int32(ar.Spec.RiskScore),
		jsonEncoder: encoder,
		labels:      ar.Labels,
		rateLimiter: rateLimiter,
		domain:      ar.Domain,
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

func (r *AlertRuleManager) DeleteAlertRule(name, domain string) {
	key := collectionKey{domain, name}
	r.mutex.Lock()
	if rule, ok := r.rules[key]; ok {
		r.encoderDecref(rule)
		delete(r.rules, key)

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
			Name:   r.name,
			Labels: r.labels,
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

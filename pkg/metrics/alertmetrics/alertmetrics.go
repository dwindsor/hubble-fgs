// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package alertmetrics

import (
	"io"

	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/prometheus/client_golang/prometheus"
)

// AlertRule metrics
var (
	// AlertsExportedBytesTotal counts the number of bytes exported for alert events
	AlertsExportedBytesTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace:   consts.MetricsNamespace,
			Name:        "alert_rules_exported_bytes_total",
			Help:        "Number of bytes exported for alert events. Reset on Tetragon restart.",
			ConstLabels: nil,
		},
	)

	// AlertsTriggeredTotal counts the number of alerts triggered per rule and severity
	AlertsTriggeredTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace:   consts.MetricsNamespace,
			Name:        "alert_rules_triggered_total",
			Help:        "Number of alerts triggered per rule name and severity. Reset on Tetragon restart.",
			ConstLabels: nil,
		},
		[]string{"rule", "severity"},
	)

	// AlertsBySeverityTotal counts the number of alerts triggered by severity level
	AlertsBySeverityTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace:   consts.MetricsNamespace,
			Name:        "alert_rules_by_severity_total",
			Help:        "Number of alerts triggered by severity level. Reset on Tetragon restart.",
			ConstLabels: nil,
		},
		[]string{"severity"},
	)

	// AlertRulesTotal counts the number of alert rules loaded
	AlertRulesTotal = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace:   consts.MetricsNamespace,
			Name:        "alert_rules_total",
			Help:        "Number of alert rules currently present on the system. Updated whenever an alert rule is added or removed.",
			ConstLabels: nil,
		},
		[]string{"severity"},
	)

	// AlertRuleEvaluationErrors counts evaluation errors to spot invalid CEL expressions
	AlertRuleEvaluationErrors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace:   consts.MetricsNamespace,
			Name:        "alert_rules_evaluation_errors_total",
			Help:        "Number of errors during alert rule evaluation. Deleted if the respective alert rule is not applied anymore.",
			ConstLabels: nil,
		},
		[]string{"rule"},
	)

	// AlertRuleCompilationErrors counts errors when compiling CEL expressions in alert rules
	AlertRuleCompilationErrors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace:   consts.MetricsNamespace,
			Name:        "alert_rules_compilation_errors_total",
			Help:        "Number of errors when compiling CEL expressions in alert rules. Deleted if the respective alert rule is not applied anymore.",
			ConstLabels: nil,
		},
		[]string{"rule"},
	)

	// AlertsEvaluatedTotal counts the number of alerts evaluated per rule
	AlertsEvaluatedTotal = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace:   consts.MetricsNamespace,
			Name:        "alert_rules_evaluated_num_total",
			Help:        "Number of alerts evaluated per rule. Reset on Tetragon restart.",
			ConstLabels: nil,
		},
		[]string{"rule"},
	)

	// AlertsEvaluatedTimeTotal counts the total number of usec in alerts evaluated per rule
	AlertsEvaluatedTimeTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace:   consts.MetricsNamespace,
			Name:        "alert_rules_evaluated_usec_total",
			Help:        "Total amount of usec of alerts evaluated per rule. Reset on Tetragon restart.",
			ConstLabels: nil,
		},
		[]string{"rule"},
	)

	// AlertRuleRateLimitActive will be 1 for rules that are currently rate limited, 0 otherwise
	AlertRuleRateLimitActive = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace:   consts.MetricsNamespace,
			Name:        "alert_rules_rate_limit_active",
			Help:        "Whether alert rule is being rate limited. Reset on Tetragon restart.",
			ConstLabels: nil,
		},
		[]string{"rule"},
	)

	// AlertRuleRateLimitDropsTotal counts the total number of dropped events because of rate limiting
	AlertRuleRateLimitDropsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace:   consts.MetricsNamespace,
			Name:        "alert_rules_rate_limit_drops_total",
			Help:        "Number of alerts dropped events because of rate limiting. Reset on Tetragon restart.",
			ConstLabels: nil,
		},
		[]string{"rule"},
	)

	// AlertRuleRateLimitWindowUsage will be set to the number of remaining events in active window for rate limiting
	AlertRuleRateLimitWindowUsage = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace:   consts.MetricsNamespace,
			Name:        "alert_rules_rate_limit_window_usage",
			Help:        "Window usage for rate limited alerts (ratio between 0 and 1). Reset on Tetragon restart.",
			ConstLabels: nil,
		},
		[]string{"rule"},
	)

	// AlertsExportedTotal counts the number exported alert events
	AlertsExportedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace:   consts.MetricsNamespace,
			Name:        "alert_rules_events_exported_total",
			Help:        "Number of events exported. Reset on Tetragon restart.",
			ConstLabels: nil,
		},
		[]string{"rule"},
	)
)

// UpdateAlertRuleCount updates the gauge of currently loaded alert rules
func UpdateAlertRuleCount(severity string, count float64) {
	AlertRulesTotal.WithLabelValues(severity).Set(count)
}

// DeleteEvaluationErrorMetric removes the AlertRuleEvaluationErrors time series for the rule.
func DeleteEvaluationErrorMetric(rule string) {
	AlertRuleEvaluationErrors.DeleteLabelValues(rule)
}

// DeleteCompilationErrorMetric removes the AlertRuleCompilationErrors time series for the rule.
func DeleteCompilationErrorMetric(rule string) {
	AlertRuleCompilationErrors.DeleteLabelValues(rule)
}

// RecordAlertMatch increments all relevant metrics when an alert rule matches an event
// It increments both AlertsTriggeredTotal (by rule and severity) and AlertsBySeverityTotal (by severity only)
func RecordAlertMatch(rule, severity string) {
	// Increment alert counters by rule and severity
	AlertsTriggeredTotal.WithLabelValues(rule, severity).Inc()

	// Also track by severity only
	AlertsBySeverityTotal.WithLabelValues(severity).Inc()
}

func RecordAlertTime(rule string, duration float64) {
	AlertsEvaluatedTotal.WithLabelValues(rule).Inc()
	AlertsEvaluatedTimeTotal.WithLabelValues(rule).Add(duration)
}

// InitMetrics registers all alert metrics with Prometheus
func InitMetrics(registry *prometheus.Registry) {
	registry.MustRegister(AlertsExportedBytesTotal)
	registry.MustRegister(AlertsTriggeredTotal)
	registry.MustRegister(AlertsBySeverityTotal)
	registry.MustRegister(AlertRulesTotal)
	registry.MustRegister(AlertRuleEvaluationErrors)
	registry.MustRegister(AlertRuleCompilationErrors)
	registry.MustRegister(AlertsEvaluatedTotal)
	registry.MustRegister(AlertsEvaluatedTimeTotal)
	registry.MustRegister(AlertRuleRateLimitActive)
	registry.MustRegister(AlertRuleRateLimitDropsTotal)
	registry.MustRegister(AlertRuleRateLimitWindowUsage)
	registry.MustRegister(AlertsExportedTotal)
}

// InitMetricsForDocs registers metrics and adds example entries for documentation
func InitMetricsForDocs(registry *prometheus.Registry) {
	InitMetrics(registry)

	// Add example metrics for documentation
	AlertsExportedBytesTotal.Add(0)
	AlertsTriggeredTotal.WithLabelValues("example-alert-rule", "critical").Add(0)
	AlertsBySeverityTotal.WithLabelValues("critical").Add(0)
	AlertRulesTotal.WithLabelValues("critical").Set(0)
	AlertRuleEvaluationErrors.WithLabelValues("example-alert-rule").Add(0)
	AlertRuleCompilationErrors.WithLabelValues("example-alert-rule").Add(0)
	AlertsEvaluatedTotal.WithLabelValues("example-alert-rule").Add(0)
	AlertsEvaluatedTimeTotal.WithLabelValues("example-alert-rule").Add(0)
	AlertRuleRateLimitActive.WithLabelValues("example-alert-rule").Add(0)
	AlertRuleRateLimitDropsTotal.WithLabelValues("example-alert-rule").Add(0)
	AlertRuleRateLimitWindowUsage.WithLabelValues("example-alert-rule").Add(0)
	AlertsExportedTotal.WithLabelValues("example-alert-rule").Add(0)
}

// byteCounterWriter wraps an io.WriteCloser and tracks the number of bytes written
type byteCounterWriter struct {
	io.WriteCloser
	bytesWritten prometheus.Counter
}

// Write satisfies the io.Writer interface and tracks bytes written
func (w *byteCounterWriter) Write(p []byte) (int, error) {
	n, err := w.WriteCloser.Write(p)
	w.bytesWritten.Add(float64(n))
	return n, err
}

// NewAlertExportedBytesCounterWriter creates a new wrapped writer that increments the
// AlertsExportedBytesTotal counter when bytes are written
func NewAlertExportedBytesCounterWriter(w io.WriteCloser) io.WriteCloser {
	return &byteCounterWriter{
		WriteCloser:  w,
		bytesWritten: AlertsExportedBytesTotal,
	}
}

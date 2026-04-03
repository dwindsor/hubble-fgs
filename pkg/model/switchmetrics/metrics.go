// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

//go:build linux
// +build linux

package switchmetrics

import (
	"bufio"
	"math"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// AGWMetrics holds all AGW-related metrics
type AGWMetrics struct {
	// Gauges for current state values
	k8sPolicyCount   prometheus.Gauge
	dpuRuleCount     prometheus.Gauge
	memoryUsageGauge prometheus.Gauge
	cpuUsageGauge    prometheus.Gauge

	// Counters for error tracking (always increasing)
	insertErrorCount prometheus.Counter
	updateErrorCount prometheus.Counter
	deleteErrorCount prometheus.Counter
}

// CurrentMetrics represents the current state of all metrics
type CurrentMetrics struct {
	TotalPhysicalMemoryKBUsage float64 `json:"total_physical_memory_kb_usage"`
	CPUUsagePercent            float64 `json:"cpu_usage_percent"`
	PolicyK8sIDs               int64   `json:"policy_k8s_ids"`
	PolicyDPURules             int64   `json:"policy_dpu_rules"`
	PolicyDPUInsertErrors      int64   `json:"policy_dpu_insert_errors"`
	PolicyDPUDeleteErrors      int64   `json:"policy_dpu_delete_errors"`
	PolicyDPUUpdateErrors      int64   `json:"policy_dpu_update_errors"`
}

// NewAGWMetrics creates a new metrics collector
func NewAGWMetrics() *AGWMetrics {
	m := &AGWMetrics{
		// Create Prometheus Gauges
		k8sPolicyCount: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "agw_policy_count",
			Help: "Number of Kubernetes policies",
		}),
		dpuRuleCount: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "agw_dpu_rules_count",
			Help: "Number of DPU rules",
		}),
		memoryUsageGauge: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "agw_memory_usage_kb",
			Help: "Memory usage in KB",
		}),
		cpuUsageGauge: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "agw_cpu_usage_percent",
			Help: "CPU usage percentage",
		}),

		// Create Prometheus Counters
		insertErrorCount: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "agw_dpu_insert_errors_total",
			Help: "Total number of DPU insert errors",
		}),
		updateErrorCount: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "agw_dpu_update_errors_total",
			Help: "Total number of DPU update errors",
		}),
		deleteErrorCount: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "agw_dpu_delete_errors_total",
			Help: "Total number of DPU delete errors",
		}),
	}

	// Register all metrics with the default registry
	prometheus.MustRegister(
		m.k8sPolicyCount,
		m.dpuRuleCount,
		m.memoryUsageGauge,
		m.cpuUsageGauge,
		m.insertErrorCount,
		m.updateErrorCount,
		m.deleteErrorCount,
	)

	return m
}

// Error metrics
func (m *AGWMetrics) RecordDPUInsertError() {
	m.insertErrorCount.Inc()
	logger.GetLogger().Debug("recorded DPU insert error", "new_count", m.GetInsertErrorCount())
}

func (m *AGWMetrics) RecordDPUDeleteError() {
	m.deleteErrorCount.Inc()
	logger.GetLogger().Debug("recorded DPU delete error", "new_count", m.GetDeleteErrorCount())
}

func (m *AGWMetrics) RecordDPUUpdateError() {
	m.updateErrorCount.Inc()
	logger.GetLogger().Debug("recorded DPU update error", "new_count", m.GetUpdateErrorCount())
}

// Policy count updates
func (m *AGWMetrics) SetK8sPolicyCount(count int64) {
	m.k8sPolicyCount.Set(float64(count))
}

// DPU rule count updates
func (m *AGWMetrics) SetDPURuleCount(count int64) {
	m.dpuRuleCount.Set(float64(count))
}

// Memory and CPU updates
func (m *AGWMetrics) UpdateSystemMetrics() {
	memUsage := m.getProcessMemoryUsage()
	cpuUsage := m.getCurrentCPUUsage()

	m.memoryUsageGauge.Set(memUsage)
	m.cpuUsageGauge.Set(cpuUsage)
}

// GetInsertErrorCount returns the current value of insert error counter
func (m *AGWMetrics) GetInsertErrorCount() float64 {
	metric := &dto.Metric{}
	m.insertErrorCount.Write(metric)
	return metric.GetCounter().GetValue()
}

// GetUpdateErrorCount returns the current value of update error counter
func (m *AGWMetrics) GetUpdateErrorCount() float64 {
	metric := &dto.Metric{}
	m.updateErrorCount.Write(metric)
	return metric.GetCounter().GetValue()
}

// GetDeleteErrorCount returns the current value of delete error counter
func (m *AGWMetrics) GetDeleteErrorCount() float64 {
	metric := &dto.Metric{}
	m.deleteErrorCount.Write(metric)
	return metric.GetCounter().GetValue()
}

// GetK8sPolicyCount returns the current number of Kubernetes policies
func (m *AGWMetrics) GetK8sPolicyCount() float64 {
	metric := &dto.Metric{}
	m.k8sPolicyCount.Write(metric)
	return metric.GetGauge().GetValue()
}

// GetDPURuleCount returns the current number of DPU rules
func (m *AGWMetrics) GetDPURuleCount() float64 {
	metric := &dto.Metric{}
	m.dpuRuleCount.Write(metric)
	return metric.GetGauge().GetValue()
}

// getProcessMemoryUsage retrieves the current process's resident set size (RSS) in kilobytes
// by parsing the VmRSS field from /proc/self/status. RSS represents the amount of physical
// memory currently used by the process, excluding swapped memory.
func (m *AGWMetrics) getProcessMemoryUsage() float64 {
	// Read from /proc/self/status for RSS (Resident Set Size)
	file, err := os.Open("/proc/self/status")
	if err != nil {
		return 0.0
	}
	defer file.Close()

	// Report VmRSS (physical memory usage) instead of VmSize (virtual memory size)
	// Check agw process in cat /proc/$(pgrep agw)/status | grep VmRSS
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "VmRSS:") {
			fields := strings.Fields(line)
			logger.GetLogger().Debug("Found VmRSS line", "fields", fields)
			if len(fields) >= 2 {
				if memoryKB, err := strconv.ParseInt(fields[1], 10, 64); err == nil {
					return float64(memoryKB)
				}
			}
		}
	}
	logger.GetLogger().Warn("VmRSS not found in /proc/self/status")
	return 0.0
}

// safeFloatToInt64 converts float64 to int64 safely, handling NaN and Inf values
func safeFloatToInt64(f float64) int64 {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return 0
	}
	return int64(f)
}

// GetCurrentMetrics returns current metric values
func (m *AGWMetrics) GetCurrentMetrics(policyK8sCount int64, totalDPURules int64) *CurrentMetrics {
	// Update gauges with current values
	m.SetK8sPolicyCount(policyK8sCount)
	m.SetDPURuleCount(totalDPURules)
	m.UpdateSystemMetrics()

	return &CurrentMetrics{
		TotalPhysicalMemoryKBUsage: m.getProcessMemoryUsage(),
		CPUUsagePercent:            m.getCurrentCPUUsage(),
		PolicyK8sIDs:               policyK8sCount,
		PolicyDPURules:             totalDPURules,
		PolicyDPUInsertErrors:      safeFloatToInt64(m.GetInsertErrorCount()),
		PolicyDPUDeleteErrors:      safeFloatToInt64(m.GetDeleteErrorCount()),
		PolicyDPUUpdateErrors:      safeFloatToInt64(m.GetUpdateErrorCount()),
	}
}

// getCurrentCPUUsage returns the current CPU usage percentage for the Go process.
func (m *AGWMetrics) getCurrentCPUUsage() float64 {
	var rtm runtime.MemStats
	runtime.ReadMemStats(&rtm)

	// Use GC CPU fraction for process-specific CPU usage
	// This represents actual CPU time used by this process
	return rtm.GCCPUFraction * 100
}

// GetMetricsRegistry returns a gatherer for all metrics
func (m *AGWMetrics) GetMetricsRegistry() prometheus.Gatherer {
	return prometheus.DefaultGatherer
}

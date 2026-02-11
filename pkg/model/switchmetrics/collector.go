// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

// This file implements a metrics collector for switch metrics,
// to stream metrics to external systems

package switchmetrics

import (
	"context"
	"sync"

	"github.com/cilium/tetragon/pkg/logger"

	"github.com/isovalent/hubble-fgs/pkg/model/switchpolicy"
)

// MetricsCollector manages metrics collection lifecycle
type MetricsCollector struct {
	agwMetrics    *AGWMetrics
	policyHandler switchpolicy.PolicyHandler
	pusher        *PrometheusPusher
	mu            sync.RWMutex
}

// Singleton instance of MetricsCollector
var (
	instance *MetricsCollector
	once     sync.Once
)

// GetInstance returns the singleton instance of MetricsCollector
func GetInstance(_ context.Context) *MetricsCollector {
	once.Do(func() {
		instance = &MetricsCollector{
			agwMetrics: NewAGWMetrics(),
		}
	})
	return instance
}

func (mc *MetricsCollector) SetPolicyHandler(policyHandler switchpolicy.PolicyHandler) {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	mc.policyHandler = policyHandler
	logger.GetLogger().Info("policy handler set for metrics collector")
}

// GetAGWMetrics returns the underlying metrics object for updates
func (mc *MetricsCollector) GetAGWMetrics() switchpolicy.AGWMetricsInterface {
	return mc.agwMetrics
}

// GetCurrentMetrics returns the current metrics values,
// including real-time policy and rule counts if available
func (mc *MetricsCollector) GetCurrentMetrics() *CurrentMetrics {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	if mc.policyHandler != nil {
		// Calculate real-time policies and rules count
		policyMap := mc.policyHandler.ListPolicies()
		policyCount := int64(len(policyMap))
		ruleCount := int64(0)
		for _, rules := range policyMap {
			ruleCount += int64(len(rules))
		}
		return mc.agwMetrics.GetCurrentMetrics(policyCount, ruleCount)
	}

	// Fallback to send only process-level metrics, if no policy handler
	return mc.agwMetrics.GetCurrentMetrics(0, 0)
}

// StartPrometheusPusher initializes and starts the Prometheus pusher
func (mc *MetricsCollector) StartPrometheusPusher(ctx context.Context, config *PrometheusPushConfig) error {
	// Validate configuration before taking the lock.
	if config == nil || config.ControllerURL == "" {
		logger.GetLogger().Info("Prometheus pusher not configured, skipping")
		return nil
	}

	mc.mu.Lock()
	if mc.pusher != nil {
		// A pusher is already running; do not start another one.
		logger.GetLogger().Info("Prometheus pusher already running")
		mc.mu.Unlock()
		return nil
	}

	logger.GetLogger().Info("starting Prometheus pusher", "endpoint", config.ControllerURL)
	pusher := NewPrometheusPusher(ctx, mc, config)
	mc.pusher = pusher
	mc.mu.Unlock()

	// Start pusher outside the lock to avoid blocking other methods.
	if err := pusher.Start(); err != nil {
		// On start error, clear the pusher so that a retry is possible.
		mc.mu.Lock()
		if mc.pusher == pusher {
			mc.pusher = nil
		}
		mc.mu.Unlock()
		return err
	}
	// Wait for context cancellation to stop the pusher.
	<-ctx.Done()

	// Stop the pusher when context is cancelled, without holding the lock.
	stopErr := pusher.Stop()

	// Clear the pusher reference to allow subsequent starts.
	mc.mu.Lock()
	if mc.pusher == pusher {
		mc.pusher = nil
	}
	mc.mu.Unlock()

	return stopErr
}

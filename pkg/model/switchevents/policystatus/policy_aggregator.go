// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

// Package policystatus provides policy-level aggregation for SmartSwitch network policy events.
//
// Multi-Rule (one or more) Policy Aggregation:
// PolicyAggregator collects rule events from multiple FWA agents and aggregates them at the
// policy level (multiple rules per policy) before sending batched results to timescape.
//
// Key features:
// - Policy-level aggregation: Waits for ALL rules in a policy to receive responses from ALL expected agents
// - Batching: Groups up to `DefaultMaxBatchSize` completed policies per batch to reduce HTTP requests
// - Timeout handling: Sends partial results if agents don't respond within `DefaultAggregationTimeout` seconds
// - Cleanup: Automatically removes stale entries older than `CleanupCutoffAge` time
// - Metrics: Tracks partial policy sends due to timeouts
//
// Flow: Rule events → Policy aggregation → Batch formation → Enqueue to timescape queue

package policystatus

import (
	"context"
	"regexp"
	"sync"
	"time"

	"github.com/cilium/tetragon/pkg/logger"

	l3l4networkpolicyv1alpha "github.com/isovalent/ipa/l3l4networkpolicy/v1alpha"
)

const (
	// DefaultAggregationTimeout is the default timeout for policy aggregation.
	// Controls how long to wait for all FWA agents to report before completing aggregation.
	DefaultAggregationTimeout = 15 * time.Second

	// CleanupInterval is the interval to check for cleaning up old entries
	CleanupInterval = 2 * time.Minute
	// Delete entries older than 3 minutes to prevent memory leaks in pendingPolicies.
	CleanupCutoffAge = 3 * time.Minute

	// Default ExpectedAgentCount is 0 (number of DPUs)
	DefaultExpectedAgentCount = 0

	// Policy-level aggregation constants
	DefaultMaxBatchSize = 2                // Maximum policies per batch
	DefaultBatchTimeout = 30 * time.Second // Force send batch after timeout
)

var ruleNameSuffixRegex = regexp.MustCompile(`/\d+$`)

// PolicyAggregationResult represents the aggregated result for an entire policy
type PolicyAggregationResult struct {
	PolicyName string // PolicyName is already in format "kind/namespace/name"
	Version    string
	// normalizedRuleName -> rule result
	RuleResults   map[string]*RuleAggregationResult
	FirstSeen     time.Time
	LastUpdated   time.Time
	IsComplete    bool
	ExpectedCount int
}

// RuleAggregationResult represents the aggregated result for a rule within a policy
type RuleAggregationResult struct {
	RuleName      string
	PolicyName    string
	AgentResults  map[string]*AgentRuleResult // agentUID -> result
	ExpectedCount int                         // Number of expected FWA agents
}

// AgentRuleResult represents the result from a single agent
type AgentRuleResult struct {
	AgentUID     string
	IsSuccess    bool
	Error        l3l4networkpolicyv1alpha.PolicyRuleError
	ErrorMessage string
	ReceivedAt   time.Time
}

// PolicyAggregator handles aggregation of policy rule events from multiple FWA agents
// Aggregates at policy level (multiple rules per policy) with batching support
type PolicyAggregator struct {
	mu                     sync.RWMutex
	pendingPolicies        map[string]*PolicyAggregationResult // PolicyName -> policy result
	pendingBatch           []*PolicyAggregationResult          // Up to 3 policies
	expectedAgentCount     int                                 // Expected number of FWA agents (2 or 4)
	aggregationTimeout     time.Duration                       // Timeout for waiting for all agents
	cleanupInterval        time.Duration                       // Interval for cleaning up old entries
	maxBatchSize           int                                 // Max policies per batch
	batchCallback          func([]*PolicyAggregationResult)    // Callback when policy batch is ready
	partialPolicySendCount int64                               // Count of partial policy sends due to timeouts
	stopCh                 chan struct{}
	running                bool
	wg                     sync.WaitGroup // Wait for cleanup goroutine to finish
}

// NewPolicyAggregator creates a new policy aggregator
func NewPolicyAggregator(expectedAgentCount int, aggregationTimeout time.Duration, maxBatchSize int) *PolicyAggregator {
	if maxBatchSize <= 0 {
		maxBatchSize = DefaultMaxBatchSize
	}

	if aggregationTimeout <= 0 {
		aggregationTimeout = DefaultAggregationTimeout
	}

	return &PolicyAggregator{
		pendingPolicies:    make(map[string]*PolicyAggregationResult),
		pendingBatch:       make([]*PolicyAggregationResult, 0, maxBatchSize),
		expectedAgentCount: expectedAgentCount,
		aggregationTimeout: aggregationTimeout,
		cleanupInterval:    CleanupInterval,
		maxBatchSize:       maxBatchSize,
		stopCh:             make(chan struct{}),
		running:            false,
	}
}

// Start begins the policy aggregation process
func (pa *PolicyAggregator) Start(ctx context.Context) {
	pa.mu.Lock()
	if pa.running {
		pa.mu.Unlock()
		return
	}
	pa.running = true
	pa.mu.Unlock()

	// Start cleanup goroutine
	pa.wg.Add(1)
	go func() {
		defer pa.wg.Done()
		pa.cleanupLoop(ctx)
	}()

	logger.GetLogger().Info("policy aggregator started",
		"expectedAgentCount", pa.expectedAgentCount,
		"aggregationTimeout", pa.aggregationTimeout,
		"maxBatchSize", pa.maxBatchSize)
}

// Stop stops the policy aggregation process
func (pa *PolicyAggregator) Stop() {
	pa.mu.Lock()
	if !pa.running {
		pa.mu.Unlock()
		return
	}
	pa.running = false

	// Send any pending batch before stopping
	if len(pa.pendingBatch) > 0 {
		pa.sendBatch()
	}

	pa.mu.Unlock()

	close(pa.stopCh)
	// Wait for cleanup goroutine to finish
	pa.wg.Wait()
	logger.GetLogger().Info("policy aggregator stopped")
}

// SetBatchCallback sets the callback function for policy batch completion
func (pa *PolicyAggregator) SetBatchCallback(callback func([]*PolicyAggregationResult)) {
	pa.mu.Lock()
	defer pa.mu.Unlock()
	pa.batchCallback = callback
}

// normalizeRuleName removes the /integer suffix from rule names for comparison
func (pa *PolicyAggregator) normalizeRuleName(ruleName string) string {
	// Remove /integer pattern from the end of rule name
	// Example: "rule-name/123" -> "rule-name"
	normalized := ruleNameSuffixRegex.ReplaceAllString(ruleName, "")

	logger.GetLogger().Debug("normalized rule name",
		"original", ruleName,
		"normalized", normalized)

	return normalized
}

// ProcessRuleEvent processes a policy rule event and adds it to policy-level aggregation
func (pa *PolicyAggregator) ProcessRuleEvent(agentUID string, ruleEvent *l3l4networkpolicyv1alpha.PolicyRuleEvent) {
	policyName := ruleEvent.PolicyName // Already "kind/namespace/name"
	normalizedRuleName := pa.normalizeRuleName(ruleEvent.RuleName)
	now := time.Now()

	pa.mu.Lock()
	defer pa.mu.Unlock()

	// Get or create policy aggregation result using PolicyName directly
	policyResult, exists := pa.pendingPolicies[policyName]
	if !exists {
		policyResult = &PolicyAggregationResult{
			PolicyName:    policyName,
			Version:       ruleEvent.K8SResourceVersion,
			RuleResults:   make(map[string]*RuleAggregationResult),
			FirstSeen:     now,
			LastUpdated:   now,
			IsComplete:    false,
			ExpectedCount: pa.expectedAgentCount,
		}
		pa.pendingPolicies[policyName] = policyResult
		go pa.handlePolicyTimeout(policyName, now)
	}

	// Get or create rule result within policy
	ruleResult, ruleExists := policyResult.RuleResults[normalizedRuleName]
	if !ruleExists {
		ruleResult = &RuleAggregationResult{
			RuleName:      normalizedRuleName,
			PolicyName:    policyName,
			AgentResults:  make(map[string]*AgentRuleResult),
			ExpectedCount: pa.expectedAgentCount,
		}
		policyResult.RuleResults[normalizedRuleName] = ruleResult
	}

	// Add agent result to rule
	ruleResult.AgentResults[agentUID] = &AgentRuleResult{
		AgentUID:     agentUID,
		IsSuccess:    ruleEvent.IsSuccess,
		Error:        ruleEvent.Error,
		ErrorMessage: ruleEvent.ErrorMessage,
		ReceivedAt:   now,
	}

	// Update policy last updated time
	policyResult.LastUpdated = now

	logger.GetLogger().Debug("processed rule event for policy",
		"policyName", policyName,
		"ruleName", normalizedRuleName,
		"agentUID", agentUID,
		"isSuccess", ruleEvent.IsSuccess,
		"ruleAgentCount", len(ruleResult.AgentResults),
		"policyRuleCount", len(policyResult.RuleResults))
}

// isPolicyComplete checks if all rules in a policy have results from all expected agents
func (pa *PolicyAggregator) isPolicyComplete(policy *PolicyAggregationResult) bool {
	// Policy is complete when ALL rules have results from ALL expected agents
	if len(policy.RuleResults) == 0 {
		return false
	}

	for _, ruleResult := range policy.RuleResults {
		if len(ruleResult.AgentResults) < pa.expectedAgentCount {
			return false
		}
	}
	return len(policy.RuleResults) > 0 // At least one rule must exist
}

// completePolicyAggregation marks a policy as complete and adds to batch
func (pa *PolicyAggregator) completePolicyAggregation(policyName string, policy *PolicyAggregationResult) {
	if policy.IsComplete {
		return
	}

	policy.IsComplete = true

	logger.GetLogger().Debug("policy aggregation complete",
		"policyName", policyName,
		"ruleCount", len(policy.RuleResults),
		"duration", time.Since(policy.FirstSeen))

	// Add to batch
	pa.pendingBatch = append(pa.pendingBatch, policy)

	// Check if batch should be sent
	if len(pa.pendingBatch) >= pa.maxBatchSize || pa.shouldFlushBatch() {
		logger.GetLogger().Debug("policy batch ready to send",
			"batchSize", len(pa.pendingBatch))
		pa.sendBatch()
	}

	// Remove from pending policies
	logger.GetLogger().Debug("removing completed policy from pending",
		"policyName", policyName)
	delete(pa.pendingPolicies, policyName)
}

// sendBatch sends the current batch of policies
func (pa *PolicyAggregator) sendBatch() {
	if len(pa.pendingBatch) == 0 {
		return
	}

	batch := make([]*PolicyAggregationResult, len(pa.pendingBatch))
	copy(batch, pa.pendingBatch)

	pa.pendingBatch = pa.pendingBatch[:0] // Clear batch

	logger.GetLogger().Debug("sending policy batch",
		"batchSize", len(batch))

	if pa.batchCallback != nil {
		go pa.batchCallback(batch)
	}
}

// shouldFlushBatch determines if batch should be flushed due to timeout
func (pa *PolicyAggregator) shouldFlushBatch() bool {
	if len(pa.pendingBatch) == 0 {
		return false
	}

	// Flush if oldest policy in batch has been waiting too long
	oldestPolicy := pa.pendingBatch[0]
	return time.Since(oldestPolicy.FirstSeen) > DefaultBatchTimeout
}

// handlePolicyTimeout handles timeout for policy aggregation.
// adds metric for partial sends
func (pa *PolicyAggregator) handlePolicyTimeout(policyName string, startTime time.Time) {
	timeout := pa.aggregationTimeout

	select {
	case <-pa.stopCh:
		return
	case <-time.After(timeout):
		pa.mu.Lock()
		policy, exists := pa.pendingPolicies[policyName]
		if exists && !policy.IsComplete {
			// Increment partial send counter
			pa.partialPolicySendCount++

			// Calculate what was missing
			timeTaken := time.Since(startTime)
			incompleteRules := pa.countIncompleteRules(policy)

			// Determine if policy is actually complete or partial
			if incompleteRules == 0 {
				// Policy is complete but timed out (timeout-only completion design)
				logger.GetLogger().Debug("policy aggregation - sending complete results",
					"policyName", policyName,
					"timeout", timeout,
					"timeTaken", timeTaken,
					"totalRules", len(policy.RuleResults),
					"completionSendCount", pa.partialPolicySendCount,
					"reason", "timeout_reached_complete")
			} else {
				// Policy is actually incomplete due to missing agent responses
				logger.GetLogger().Warn("policy aggregation - sending partial results",
					"policyName", policyName,
					"timeout", timeout,
					"timeTaken", timeTaken,
					"totalRules", len(policy.RuleResults),
					"incompleteRules", incompleteRules,
					"partialSendCount", pa.partialPolicySendCount,
					"reason", "timeout_reached_incomplete")
			}

			// Complete aggregation with whatever is available
			pa.completePolicyAggregation(policyName, policy)
		}
		pa.mu.Unlock()
	}
}

// countIncompleteRules counts how many rules don't have all expected agent responses
func (pa *PolicyAggregator) countIncompleteRules(policy *PolicyAggregationResult) int {
	incompleteCount := 0
	for _, ruleResult := range policy.RuleResults {
		if len(ruleResult.AgentResults) < pa.expectedAgentCount {
			incompleteCount++
		}
	}
	return incompleteCount
}

// GetPartialPolicySendCount returns the current count of partial policy sends
func (pa *PolicyAggregator) GetPartialPolicySendCount() int64 {
	pa.mu.RLock()
	defer pa.mu.RUnlock()
	return pa.partialPolicySendCount
}

// cleanupLoop periodically cleans up old entries
func (pa *PolicyAggregator) cleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(pa.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			pa.cleanup()
		case <-ctx.Done():
			logger.GetLogger().Info("policy aggregator cleanup loop exiting due to context done")
			return
		case <-pa.stopCh:
			return
		}
	}
}

// cleanup removes old completed or stale entries
func (pa *PolicyAggregator) cleanup() {
	pa.mu.Lock()
	defer pa.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-CleanupCutoffAge) // Remove entries older than 3 minutes

	// Cleanup policies
	var policiesToDelete []string
	for policyName, policy := range pa.pendingPolicies {
		if policy.LastUpdated.Before(cutoff) {
			policiesToDelete = append(policiesToDelete, policyName)
		}
	}

	for _, policyName := range policiesToDelete {
		logger.GetLogger().Debug("cleaning up old policy aggregation entry",
			"policyName", policyName,
			"lastUpdated", pa.pendingPolicies[policyName].LastUpdated,
			"cutoffAge", CleanupCutoffAge)
		delete(pa.pendingPolicies, policyName)
	}

	if len(policiesToDelete) > 0 {
		logger.GetLogger().Debug("cleaned up old policy aggregation entries",
			"policiesCount", len(policiesToDelete),
			"cleanupInterval", pa.cleanupInterval,
			"cutoffAge", CleanupCutoffAge)
	}
}

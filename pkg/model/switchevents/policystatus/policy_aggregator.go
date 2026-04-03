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
// policy level (multiple rules per policy) before storing completed results for periodic bulk reporting.
//
// Key features:
// - Policy-level aggregation: Waits for ALL rules in a policy to receive responses from ALL expected agents
// - Store-based completion: Completed policies are stored for periodic bulk reporting instead of immediate callbacks
// - Cleanup-based timeout: Stale incomplete policies are completed with timeout status during periodic cleanup
// - Cleanup: Automatically removes stale entries older than `CleanupCutoffAge` time
// - Metrics: Tracks partial policy sends due to timeouts
//
// Flow: Rule events → Policy aggregation → Store completed policies → Periodic bulk reporting

package policystatus

import (
	"context"
	"fmt"
	"regexp"
	"sync"
	"time"

	"github.com/cilium/tetragon/pkg/logger"

	l3l4networkpolicyv1alpha "github.com/isovalent/ipa/l3l4networkpolicy/v1alpha"
)

const (
	DefaultPolicyStatusReportingInterval = 15 * time.Minute

	// DefaultCleanupCutoffAge is the default cutoff age for cleaning up stale policies.
	// Policies older than this will be completed with timeout status.
	DefaultCleanupCutoffAge = DefaultPolicyStatusReportingInterval + (30 * time.Second)

	// Default ExpectedAgentCount is 0 (number of DPUs)
	DefaultExpectedAgentCount = 0
)

var (
	ruleNameSuffixRegex = regexp.MustCompile(`/\d+$`)
)

// PolicyAggregationResult represents the aggregated result for an entire policy
type PolicyAggregationResult struct {
	PolicyName    string // PolicyName is already in format "kind/namespace/name"
	Version       string
	PolicyGroupId string // PolicyGroupId extracted from metadata annotations
	Policy        string // Policy name
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
// Aggregates at policy level (multiple rules per policy) and stores completed policies
// in PolicyStatusStore for periodic bulk reporting instead of immediate callbacks
type PolicyAggregator struct {
	mu                     sync.RWMutex
	pendingPolicies        map[string]*PolicyAggregationResult // PolicyName -> policy result
	expectedAgentCount     int                                 // Expected number of FWA agents (2 or 4)
	cleanupCutoffAge       time.Duration                       // Age at which policies are completed with timeout status
	policyStatusStore      PolicyStatusStore                   // Store for completed policies
	partialPolicySendCount int64                               // Count of partial policy sends due to timeouts
	expectedRuleCounts     map[string]int                      // PolicyName -> expected rule count
	policiesToDelete       map[string]bool                     // PolicyName -> true (policies marked for deletion)
	running                bool
}

// NewPolicyAggregator creates a new policy aggregator with policy status store
// reportingInterval is used to calculate cleanup timing (cutoff = reportingInterval + 1min, interval = reportingInterval/2)
func NewPolicyAggregator(expectedAgentCount int, reportingInterval time.Duration, policyStatusStore PolicyStatusStore) *PolicyAggregator {
	var cleanupCutoffAge time.Duration

	if reportingInterval <= 0 {
		cleanupCutoffAge = DefaultCleanupCutoffAge
	} else {
		// Cleanup cutoff = reporting interval + 1 minute
		cleanupCutoffAge = reportingInterval + time.Minute
	}

	if policyStatusStore == nil {
		policyStatusStore = NewInMemoryPolicyStatusStore()
	}

	return &PolicyAggregator{
		pendingPolicies:    make(map[string]*PolicyAggregationResult),
		expectedAgentCount: expectedAgentCount,
		cleanupCutoffAge:   cleanupCutoffAge,
		policyStatusStore:  policyStatusStore,
		expectedRuleCounts: make(map[string]int),
		policiesToDelete:   make(map[string]bool),
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

	logger.GetLogger().Info("policy aggregator started",
		"expectedAgentCount", pa.expectedAgentCount,
		"cleanupCutoffAge", pa.cleanupCutoffAge,
		"storeType", "PolicyStatusStore")
}

// Stop stops the policy aggregation process
func (pa *PolicyAggregator) Stop() {
	pa.mu.Lock()
	if !pa.running {
		pa.mu.Unlock()
		return
	}
	pa.running = false
	pa.mu.Unlock()

	logger.GetLogger().Info("policy aggregator stopped")
}

// GetPolicyStatusStore returns the policy status store
func (pa *PolicyAggregator) GetPolicyStatusStore() PolicyStatusStore {
	pa.mu.RLock()
	defer pa.mu.RUnlock()
	return pa.policyStatusStore
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

// SetExpectedRuleCount sets the expected number of rules for a policy
func (pa *PolicyAggregator) SetExpectedRuleCount(policyName string, expectedRuleCount int) {
	pa.mu.Lock()
	defer pa.mu.Unlock()

	pa.expectedRuleCounts[policyName] = expectedRuleCount

	logger.GetLogger().Info("set expected rule count for policy",
		"policyName", policyName,
		"expectedRuleCount", expectedRuleCount)
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
			PolicyGroupId: "", // Will be set by watcher
			Policy:        extractPolicyNameFromPath(policyName),
			RuleResults:   make(map[string]*RuleAggregationResult),
			FirstSeen:     now,
			LastUpdated:   now,
			IsComplete:    false,
			ExpectedCount: pa.expectedAgentCount,
		}
		pa.pendingPolicies[policyName] = policyResult
		// Note: Cleanup handles stale policies with timeout based on reporting interval
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

	// Check if policy is now complete after this rule result
	if pa.isPolicyComplete(policyResult) {
		pa.completePolicyAggregation(policyName, policyResult)
	}

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
	// Policy is complete when ALL expected rules have results from ALL expected agents
	if len(policy.RuleResults) == 0 {
		return false
	}

	// Check if we have expected rule count for this policy
	if expectedRuleCount, exists := pa.expectedRuleCounts[policy.PolicyName]; exists {
		// We know the expected number of rules - check if we have them all
		if len(policy.RuleResults) < expectedRuleCount {
			logger.GetLogger().Info("policy incomplete - missing rules",
				"policyName", policy.PolicyName,
				"actualRules", len(policy.RuleResults),
				"expectedRules", expectedRuleCount)
			return false
		}
	}

	// Check that each rule has responses from all expected agents
	for _, ruleResult := range policy.RuleResults {
		if len(ruleResult.AgentResults) < pa.expectedAgentCount {
			logger.GetLogger().Warn("policy incomplete - missing agent responses",
				"policyName", policy.PolicyName,
				"ruleName", ruleResult.RuleName,
				"actualAgents", len(ruleResult.AgentResults),
				"expectedAgents", pa.expectedAgentCount)
			return false
		}
	}
	// All checks passed - policy is complete
	return true
}

// completePolicyAggregation marks a policy as complete and adds to store
// ProcessRuleEvent() will call this when they detect a policy is complete
func (pa *PolicyAggregator) completePolicyAggregation(policyName string, policy *PolicyAggregationResult) {
	if policy.IsComplete {
		return
	}

	pa.completePolicy(policyName, policy, false) // false = with mutex locking

	// Remove from pending policies (only for the main completion path)
	logger.GetLogger().Info("removing completed policy from pending",
		"policyName", policyName)
	delete(pa.pendingPolicies, policyName)
}

// completePolicyAggregationUnlocked is like completePolicyAggregation but assumes mutex is already held
// cleanup() will call this when it detects a policy is stale and needs to be completed with timeout status
func (pa *PolicyAggregator) completePolicyAggregationUnlocked(policyName string, policy *PolicyAggregationResult) {
	if policy.IsComplete {
		return
	}

	pa.completePolicy(policyName, policy, true) // true = unlocked (mutex already held)

	// Note: Don't delete from pendingPolicies here - cleanup() will handle that
}

// completePolicy contains the shared logic for both completion methods
func (pa *PolicyAggregator) completePolicy(policyName string, policy *PolicyAggregationResult, unlocked bool) {
	policy.IsComplete = true

	logger.GetLogger().Debug("policy aggregation complete",
		"policyName", policyName,
		"ruleCount", len(policy.RuleResults),
		"duration", time.Since(policy.FirstSeen))

	// Check if policy is marked for deletion and is successful
	// Policy is successful if complete and no rule failures
	policyIsSuccess := policy.IsComplete
	for _, ruleResult := range policy.RuleResults {
		for _, agentResult := range ruleResult.AgentResults {
			if !agentResult.IsSuccess {
				policyIsSuccess = false
				break
			}
		}
		if !policyIsSuccess {
			break
		}
	}
	shouldDelete := pa.policiesToDelete[policyName] && policyIsSuccess

	logSuffix := ""
	if unlocked {
		logSuffix = " (cleanup))"
	}

	if shouldDelete {
		logger.GetLogger().Info("policy marked for deletion and completed successfully - not storing (no status reporting needed for successful deletion)"+logSuffix,
			"policyName", policyName)
		// Clean up deletion tracking since deletion is considered successful
		delete(pa.policiesToDelete, policyName)
		// Don't store - successful deletions don't need status reporting
	} else {
		// Store completed policy for bulk reporting (includes deletion failures)
		pa.policyStatusStore.Store(policy)

		if unlocked {
			logger.GetLogger().Debug("stored completed policy for bulk reporting"+logSuffix,
				"policyName", policyName,
				"storeCount", pa.policyStatusStore.GetCount())
		} else {
			logger.GetLogger().Info("stored completed policy for bulk reporting",
				"policyName", policyName,
				"storeCount", pa.policyStatusStore.GetCount(),
				"deleted", shouldDelete)
		}
	}
}

// addTimeoutResponses adds timeout agent responses for missing agents in incomplete rules
func (pa *PolicyAggregator) addTimeoutResponses(policy *PolicyAggregationResult) {
	for _, ruleResult := range policy.RuleResults {
		// Add timeout responses for missing agents
		missingAgentCount := pa.expectedAgentCount - len(ruleResult.AgentResults)
		if missingAgentCount > 0 {
			logger.GetLogger().Info("adding timeout responses for missing agents",
				"policyName", policy.PolicyName,
				"ruleName", ruleResult.RuleName,
				"missingAgents", missingAgentCount,
				"existingAgents", len(ruleResult.AgentResults))

			// Generate timeout agent responses for missing agents
			agentIndex := 0
			for len(ruleResult.AgentResults) < pa.expectedAgentCount {
				timeoutAgentUID := fmt.Sprintf("timeout-agent-%d", agentIndex)
				// Avoid duplicate if agent ID already exists
				if _, exists := ruleResult.AgentResults[timeoutAgentUID]; exists {
					agentIndex++
					continue
				}

				ruleResult.AgentResults[timeoutAgentUID] = &AgentRuleResult{
					AgentUID:     timeoutAgentUID,
					IsSuccess:    false,
					Error:        l3l4networkpolicyv1alpha.PolicyRuleError_POLICY_RULE_ERROR_TIMEOUT,
					ErrorMessage: "TIMEOUT_AGENT_RESPONSES",
					ReceivedAt:   time.Now(),
				}
				agentIndex++
			}
		}
	}
}

// StoreValidationError stores a policy with validation error
func (pa *PolicyAggregator) StoreValidationError(policyName, errorMsg string) {
	pa.policyStatusStore.UpdateValidationError(policyName, errorMsg)
	logger.GetLogger().Debug("stored policy validation error",
		"policyName", policyName,
		"error", errorMsg)
}

// GetStoreStats returns statistics about the policy status store
func (pa *PolicyAggregator) GetStoreStats() (int, int) {
	pa.mu.RLock()
	defer pa.mu.RUnlock()
	return len(pa.pendingPolicies), pa.policyStatusStore.GetCount()
}

// cleanup removes old completed or stale entries, reporting incomplete ones as timeout
func (pa *PolicyAggregator) cleanup() {
	pa.mu.Lock()
	defer pa.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-pa.cleanupCutoffAge) // Remove entries older than reporting interval + 1 minute

	// Cleanup policies - complete stale ones with timeout before deleting
	var policiesToDelete []string
	for policyName, policy := range pa.pendingPolicies {
		if policy.LastUpdated.Before(cutoff) {
			// Mark incomplete policies as timeout before cleanup
			if !policy.IsComplete {
				logger.GetLogger().Warn("policy aggregation timeout - completing with partial results",
					"policyName", policyName,
					"timeSinceLastUpdate", now.Sub(policy.LastUpdated),
					"totalRules", len(policy.RuleResults),
					"cutoffAge", pa.cleanupCutoffAge,
				)

				// Add timeout responses for missing agents in incomplete rules
				pa.addTimeoutResponses(policy)

				// Complete aggregation with timeout responses (this will store it)
				pa.completePolicyAggregationUnlocked(policyName, policy)
			}
			policiesToDelete = append(policiesToDelete, policyName)
		}
	}

	for _, policyName := range policiesToDelete {
		logger.GetLogger().Info("cleaning up old policy aggregation entry",
			"policyName", policyName,
			"lastUpdated", pa.pendingPolicies[policyName].LastUpdated,
			"cutoffAge", pa.cleanupCutoffAge)
		delete(pa.pendingPolicies, policyName)
	}

	if len(policiesToDelete) > 0 {
		logger.GetLogger().Info("cleaned up old policy aggregation entries",
			"policiesCount", len(policiesToDelete),
			"cutoffAge", pa.cleanupCutoffAge)
	}
}

// SetPolicyGroupId sets the PolicyGroupId for a specific policy
func (pa *PolicyAggregator) SetPolicyGroupId(policyName string, policyGroupId string) {
	pa.mu.Lock()
	defer pa.mu.Unlock()

	if policyResult, exists := pa.pendingPolicies[policyName]; exists {
		policyResult.PolicyGroupId = policyGroupId
		logger.GetLogger().Info("timescape: set PolicyGroupId for policy",
			"policyName", policyName,
			"policyGroupId", policyGroupId)
	}
}

// MarkPolicyForDeletion marks a policy to be deleted from the store after completion
func (pa *PolicyAggregator) MarkPolicyForDeletion(policyName string) {
	pa.mu.Lock()
	defer pa.mu.Unlock()

	pa.policiesToDelete[policyName] = true
	logger.GetLogger().Info("marked policy for deletion after completion",
		"policyName", policyName)
}

// SetExpectedAgentCount sets the expected number of FWA agents
func (pa *PolicyAggregator) SetExpectedAgentCount(count int) {
	pa.mu.Lock()
	defer pa.mu.Unlock()
	pa.expectedAgentCount = count
	logger.GetLogger().Debug("updated expected agent count in aggregator", "count", count)
}

// GetExpectedAgentCount gets the expected number of FWA agents
func (pa *PolicyAggregator) GetExpectedAgentCount() int {
	pa.mu.RLock()
	defer pa.mu.RUnlock()
	return pa.expectedAgentCount
}

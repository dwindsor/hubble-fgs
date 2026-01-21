// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package policystatus

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	l3l4networkpolicyv1alpha "github.com/isovalent/ipa/l3l4networkpolicy/v1alpha"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewPolicyAggregator(t *testing.T) {
	expectedAgentCount := 2
	timeout := 30 * time.Second

	pa := NewPolicyAggregator(expectedAgentCount, timeout)

	assert.NotNil(t, pa)
	assert.Equal(t, expectedAgentCount, pa.expectedAgentCount)
	assert.Equal(t, timeout, pa.aggregationTimeout)
	assert.Equal(t, DefaultMaxBatchSize, pa.maxBatchSize)
	assert.Equal(t, CleanupInterval, pa.cleanupInterval)
	assert.False(t, pa.running)
	assert.NotNil(t, pa.pendingPolicies)
	assert.NotNil(t, pa.pendingBatch)
	assert.NotNil(t, pa.stopCh)
}

func TestPolicyAggregator_StartStop(t *testing.T) {
	pa := NewPolicyAggregator(2, 30*time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Test start
	pa.Start(ctx)
	assert.True(t, pa.running)

	// Test start when already running
	pa.Start(ctx)
	assert.True(t, pa.running)

	// Test stop
	pa.Stop()
	assert.False(t, pa.running)

	// Test stop when already stopped
	pa.Stop()
	assert.False(t, pa.running)
}

func TestPolicyAggregator_SetBatchCallback(t *testing.T) {
	pa := NewPolicyAggregator(2, 30*time.Second)
	called := false

	callback := func([]*PolicyAggregationResult) {
		called = true
	}

	pa.SetBatchCallback(callback)
	assert.NotNil(t, pa.batchCallback)

	// Trigger callback
	pa.batchCallback([]*PolicyAggregationResult{})
	assert.True(t, called)
}

func TestPolicyAggregator_normalizeRuleName(t *testing.T) {
	pa := NewPolicyAggregator(2, 30*time.Second)

	tests := []struct {
		input    string
		expected string
	}{
		{"rule-name/123", "rule-name"},
		{"rule-name", "rule-name"},
		{"complex-rule-name/456", "complex-rule-name"},
		{"rule/with/slashes/789", "rule/with/slashes"},
		{"", ""},
	}

	for _, tt := range tests {
		result := pa.normalizeRuleName(tt.input)
		assert.Equal(t, tt.expected, result)
	}
}

func TestPolicyAggregator_ProcessRuleEvent(t *testing.T) {
	shortTimeout := 100 * time.Millisecond
	pa := NewPolicyAggregator(2, shortTimeout)

	// Create test rule event
	ruleEvent := &l3l4networkpolicyv1alpha.PolicyRuleEvent{
		PolicyName:         "NetworkPolicy/default/test-policy",
		RuleName:           "rule-1/123",
		K8SResourceVersion: "v1.0.0",
		IsSuccess:          true,
		Error:              l3l4networkpolicyv1alpha.PolicyRuleError_POLICY_RULE_ERROR_UNSPECIFIED,
		ErrorMessage:       "",
	}

	// Process first agent result
	pa.ProcessRuleEvent("agent-1", ruleEvent)

	pa.mu.RLock()
	assert.Len(t, pa.pendingPolicies, 1)
	policy := pa.pendingPolicies["NetworkPolicy/default/test-policy"]
	require.NotNil(t, policy)
	assert.Equal(t, "NetworkPolicy/default/test-policy", policy.PolicyName)
	assert.Equal(t, "v1.0.0", policy.Version)
	assert.False(t, policy.IsComplete)
	assert.Len(t, policy.RuleResults, 1)

	ruleResult := policy.RuleResults["rule-1"]
	require.NotNil(t, ruleResult)
	assert.Equal(t, "rule-1", ruleResult.RuleName)
	assert.Len(t, ruleResult.AgentResults, 1)
	pa.mu.RUnlock()

	// Process second agent result to complete policy
	pa.ProcessRuleEvent("agent-2", ruleEvent)

	// With timeout-only completion, policy should still be pending
	pa.mu.RLock()
	assert.Len(t, pa.pendingPolicies, 1, "Policy should still exist (timeout-only completion)")
	policy = pa.pendingPolicies["NetworkPolicy/default/test-policy"]
	require.NotNil(t, policy, "Policy should still exist")

	// Verify policy has responses from both agents
	ruleResult = policy.RuleResults["rule-1"]
	assert.Len(t, ruleResult.AgentResults, 2, "Rule should have responses from both agents")
	assert.Contains(t, ruleResult.AgentResults, "agent-1")
	assert.Contains(t, ruleResult.AgentResults, "agent-2")
	pa.mu.RUnlock()

	// Wait for timeout to complete the policy
	time.Sleep(shortTimeout + 50*time.Millisecond)

	pa.mu.RLock()
	assert.Len(t, pa.pendingPolicies, 0) // Should be removed after completion
	pa.mu.RUnlock()
}

func TestPolicyAggregator_isPolicyComplete(t *testing.T) {
	pa := NewPolicyAggregator(2, 30*time.Second)

	// Create policy with incomplete rules
	policy := &PolicyAggregationResult{
		RuleResults: map[string]*RuleAggregationResult{
			"rule-1": {
				AgentResults: map[string]*AgentRuleResult{
					"agent-1": {},
				},
			},
		},
	}

	assert.False(t, pa.isPolicyComplete(policy))

	// Add second agent result to complete the rule
	policy.RuleResults["rule-1"].AgentResults["agent-2"] = &AgentRuleResult{}
	assert.True(t, pa.isPolicyComplete(policy))

	// Test empty policy
	emptyPolicy := &PolicyAggregationResult{
		RuleResults: map[string]*RuleAggregationResult{},
	}
	assert.False(t, pa.isPolicyComplete(emptyPolicy))
}

func TestPolicyAggregator_BatchingBehavior(t *testing.T) {
	shortTimeout := 100 * time.Millisecond
	pa := NewPolicyAggregator(1, shortTimeout) // Single agent for quick completion

	var batchedResults []*PolicyAggregationResult
	var mu sync.Mutex

	pa.SetBatchCallback(func(batch []*PolicyAggregationResult) {
		mu.Lock()
		batchedResults = append(batchedResults, batch...)
		mu.Unlock()
	})

	// Process events for multiple policies
	for i := 0; i < 3; i++ {
		ruleEvent := &l3l4networkpolicyv1alpha.PolicyRuleEvent{
			PolicyName:         fmt.Sprintf("NetworkPolicy/default/test-policy-%d", i),
			RuleName:           "rule-1",
			K8SResourceVersion: "v1.0.0",
			IsSuccess:          true,
		}
		pa.ProcessRuleEvent("agent-1", ruleEvent)
	}

	// Wait for batch processing
	time.Sleep(shortTimeout + 50*time.Millisecond)

	pa.mu.Lock()
	pendingBatchCount := len(pa.pendingBatch)
	if pendingBatchCount > 0 {
		pa.sendBatch() // Force send remaining policies
	}
	pa.mu.Unlock()

	// Wait a bit more for the callback to process
	time.Sleep(10 * time.Millisecond)

	mu.Lock()
	// All 3 policies should be batched now (via timeout completion)
	assert.Len(t, batchedResults, 3, "All 3 policies should be completed via timeout")

	// Verify each policy has the expected structure
	for _, result := range batchedResults {
		assert.Len(t, result.RuleResults, 1, "Each policy should have 1 rule")
		rule := result.RuleResults["rule-1"]
		assert.Len(t, rule.AgentResults, 1, "Each rule should have 1 agent response")
		assert.Contains(t, rule.AgentResults, "agent-1")
	}
	mu.Unlock()
}

func TestPolicyAggregator_TimeoutHandling(t *testing.T) {
	shortTimeout := 100 * time.Millisecond
	pa := NewPolicyAggregator(2, shortTimeout)

	var batchedResults []*PolicyAggregationResult
	var mu sync.Mutex

	pa.SetBatchCallback(func(batch []*PolicyAggregationResult) {
		mu.Lock()
		batchedResults = append(batchedResults, batch...)
		mu.Unlock()
	})

	// Process two policies to trigger batch send (since DefaultMaxBatchSize = 2)
	for i := 0; i < 2; i++ {
		ruleEvent := &l3l4networkpolicyv1alpha.PolicyRuleEvent{
			PolicyName:         fmt.Sprintf("NetworkPolicy/default/timeout-policy-%d", i),
			RuleName:           "rule-1",
			K8SResourceVersion: "v1.0.0",
			IsSuccess:          true,
		}
		pa.ProcessRuleEvent("agent-1", ruleEvent) // Only agent-1, missing agent-2
	}

	// Wait for timeout
	time.Sleep(shortTimeout + 50*time.Millisecond)

	// Check that partial send count increased
	assert.Equal(t, pa.GetPartialPolicySendCount(), int64(2))

	mu.Lock()
	assert.Len(t, batchedResults, 2) // Policies should be sent despite incomplete
	// Verify both policies are partial
	for _, result := range batchedResults {
		assert.Equal(t, 1, len(result.RuleResults)) // Each has 1 rule
		rule := result.RuleResults["rule-1"]
		assert.Equal(t, 1, len(rule.AgentResults))          // Each rule has 1 agent response (missing 1)
		assert.Contains(t, rule.AgentResults, "agent-1")    // Has agent-1
		assert.NotContains(t, rule.AgentResults, "agent-2") // Missing agent-2
	}
	mu.Unlock()
}

func TestPolicyAggregator_Cleanup(t *testing.T) {
	pa := NewPolicyAggregator(2, 30*time.Second)

	// Create old policy entry
	oldTime := time.Now().Add(-5 * time.Minute) // Older than CleanupCutoffAge
	pa.pendingPolicies["old-policy"] = &PolicyAggregationResult{
		PolicyName:  "old-policy",
		LastUpdated: oldTime,
	}

	// Create recent policy entry
	recentTime := time.Now()
	pa.pendingPolicies["recent-policy"] = &PolicyAggregationResult{
		PolicyName:  "recent-policy",
		LastUpdated: recentTime,
	}

	assert.Len(t, pa.pendingPolicies, 2)

	// Run cleanup
	pa.cleanup()

	// Old policy should be removed, recent should remain
	assert.Len(t, pa.pendingPolicies, 1)
	_, exists := pa.pendingPolicies["recent-policy"]
	assert.True(t, exists)
}

func TestPolicyAggregator_shouldFlushBatch(t *testing.T) {
	pa := NewPolicyAggregator(2, 30*time.Second)

	// Empty batch should not flush
	assert.False(t, pa.shouldFlushBatch())

	// Recent policy should not flush
	recentPolicy := &PolicyAggregationResult{
		FirstSeen: time.Now(),
	}
	pa.pendingBatch = append(pa.pendingBatch, recentPolicy)
	assert.False(t, pa.shouldFlushBatch())

	// Old policy should flush
	oldPolicy := &PolicyAggregationResult{
		FirstSeen: time.Now().Add(-DefaultBatchTimeout - time.Minute),
	}
	pa.pendingBatch[0] = oldPolicy
	assert.True(t, pa.shouldFlushBatch())
}

func TestPolicyAggregator_countIncompleteRules(t *testing.T) {
	pa := NewPolicyAggregator(2, 30*time.Second)

	policy := &PolicyAggregationResult{
		RuleResults: map[string]*RuleAggregationResult{
			"complete-rule": {
				AgentResults: map[string]*AgentRuleResult{
					"agent-1": {},
					"agent-2": {},
				},
			},
			"incomplete-rule": {
				AgentResults: map[string]*AgentRuleResult{
					"agent-1": {},
				},
			},
		},
	}

	count := pa.countIncompleteRules(policy)
	assert.Equal(t, 1, count)
}

func TestPolicyAggregator_CleanupLoop(t *testing.T) {
	// Use shorter cleanup interval and cutoff for testing
	pa := NewPolicyAggregator(2, 30*time.Second)
	pa.cleanupInterval = 20 * time.Millisecond // Short cleanup interval

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pa.Start(ctx)
	defer pa.Stop()

	// Add old entry that's definitely older than CleanupCutoffAge (3 minutes)
	oldTime := time.Now().Add(-CleanupCutoffAge - time.Minute) // 4 minutes ago
	pa.mu.Lock()
	pa.pendingPolicies["old-policy"] = &PolicyAggregationResult{
		PolicyName:  "old-policy",
		LastUpdated: oldTime,
	}

	// Add recent entry that should NOT be cleaned up
	recentTime := time.Now()
	pa.pendingPolicies["recent-policy"] = &PolicyAggregationResult{
		PolicyName:  "recent-policy",
		LastUpdated: recentTime,
	}

	initialCount := len(pa.pendingPolicies)
	pa.mu.Unlock()

	assert.Equal(t, 2, initialCount)

	// Wait for cleanup to run (multiple cycles to be sure)
	time.Sleep(100 * time.Millisecond)

	pa.mu.RLock()
	finalCount := len(pa.pendingPolicies)
	_, oldExists := pa.pendingPolicies["old-policy"]
	_, recentExists := pa.pendingPolicies["recent-policy"]
	pa.mu.RUnlock()

	// Old policy should be cleaned up, recent should remain
	assert.Equal(t, 1, finalCount, "Should have 1 policy remaining after cleanup")
	assert.False(t, oldExists, "Old policy should be cleaned up")
	assert.True(t, recentExists, "Recent policy should remain")
}

func TestPolicyAggregator_MultipleRulesPerPolicy(t *testing.T) {
	shortTimeout := 300 * time.Millisecond
	pa := NewPolicyAggregator(2, shortTimeout)
	pa.maxBatchSize = 1 // Force immediate batch send

	var batchedResults []*PolicyAggregationResult
	var mu sync.Mutex

	// Set up callback to capture completed policies
	pa.SetBatchCallback(func(batch []*PolicyAggregationResult) {
		mu.Lock()
		batchedResults = append(batchedResults, batch...)
		mu.Unlock()
	})

	// Create events for multiple rules in same policy
	policyName := "NetworkPolicy/default/multi-rule-policy"

	rule1Event := &l3l4networkpolicyv1alpha.PolicyRuleEvent{
		PolicyName:         policyName,
		RuleName:           "rule-1",
		K8SResourceVersion: "v1.0.0",
		IsSuccess:          true,
	}

	rule2Event := &l3l4networkpolicyv1alpha.PolicyRuleEvent{
		PolicyName:         policyName,
		RuleName:           "rule-2",
		K8SResourceVersion: "v1.0.0",
		IsSuccess:          true,
	}

	// Process rule 1 from first agent only (incomplete)
	pa.ProcessRuleEvent("agent-1", rule1Event)

	// Policy should exist and be incomplete
	pa.mu.RLock()
	policy, exists := pa.pendingPolicies[policyName]
	pa.mu.RUnlock()

	assert.True(t, exists)
	if policy != nil {
		assert.False(t, policy.IsComplete)
		assert.Len(t, policy.RuleResults, 1)
	}

	// Add rule 2 from first agent (still incomplete policy)
	pa.ProcessRuleEvent("agent-1", rule2Event)

	// Policy should still exist with 2 rules, both incomplete
	pa.mu.RLock()
	policy, exists = pa.pendingPolicies[policyName]
	pa.mu.RUnlock()

	assert.True(t, exists)
	if policy != nil {
		assert.False(t, policy.IsComplete)
		assert.Len(t, policy.RuleResults, 2)
	}

	// Complete rule 1 with second agent
	pa.ProcessRuleEvent("agent-2", rule1Event)

	// Policy should still be incomplete (rule-2 missing agent-2)
	pa.mu.RLock()
	policy, exists = pa.pendingPolicies[policyName]
	pa.mu.RUnlock()

	assert.True(t, exists)
	if policy != nil {
		assert.False(t, policy.IsComplete)
	}

	// Complete rule 2 with second agent - this should complete the policy
	pa.ProcessRuleEvent("agent-2", rule2Event)

	// Wait a bit for batch processing
	time.Sleep(shortTimeout + 50*time.Millisecond)

	// Now policy should be completed and removed from pending
	pa.mu.RLock()
	_, exists = pa.pendingPolicies[policyName]
	pa.mu.RUnlock()

	assert.False(t, exists, "Policy should be completed and removed from pending")

	// Check that policy was batched
	mu.Lock()
	assert.Len(t, batchedResults, 1, "Policy should be in batched results")
	if len(batchedResults) > 0 {
		completedPolicy := batchedResults[0]
		assert.Equal(t, policyName, completedPolicy.PolicyName)
		assert.Len(t, completedPolicy.RuleResults, 2, "Policy should have 2 rules")

		// Verify both rules have responses from both agents
		for ruleName, ruleResult := range completedPolicy.RuleResults {
			assert.Len(t, ruleResult.AgentResults, 2, "Rule %s should have 2 agent responses", ruleName)
			assert.Contains(t, ruleResult.AgentResults, "agent-1")
			assert.Contains(t, ruleResult.AgentResults, "agent-2")
		}
	}
	mu.Unlock()
}

/*
Setup: 3 agents expected, timeout-only completion
Rule-1 circular sending:
agent-1 → rule-1 (1/3 agents)
agent-2 → rule-1 (2/3 agents)
agent-3 → rule-1 (3/3 agents, rule-1 complete)
Rule-2 circular sending:
agent-1 → rule-2 (1/3 agents for rule-2)
agent-2 → rule-2 (2/3 agents for rule-2)
agent-3 → rule-2 (3/3 agents for rule-2, both rules complete)
Timeout completion: Policy completes via timeout with all rules having all agent responses
Verification: Both rules have responses from all 3 agents
*/
func TestPolicyAggregator_MultipleRulesCircularAgents(t *testing.T) {
	shortTimeout := 300 * time.Millisecond
	pa := NewPolicyAggregator(3, shortTimeout) // 3 agents expected
	pa.maxBatchSize = 1                        // Force immediate batch send

	var batchedResults []*PolicyAggregationResult
	var mu sync.Mutex

	// Set up callback to capture completed policies
	pa.SetBatchCallback(func(batch []*PolicyAggregationResult) {
		mu.Lock()
		batchedResults = append(batchedResults, batch...)
		mu.Unlock()
	})

	// Create events for multiple rules in same policy
	policyName := "NetworkPolicy/default/circular-rule-policy"

	rule1Event := &l3l4networkpolicyv1alpha.PolicyRuleEvent{
		PolicyName:         policyName,
		RuleName:           "rule-1",
		K8SResourceVersion: "v1.0.0",
		IsSuccess:          true,
	}

	rule2Event := &l3l4networkpolicyv1alpha.PolicyRuleEvent{
		PolicyName:         policyName,
		RuleName:           "rule-2",
		K8SResourceVersion: "v1.0.0",
		IsSuccess:          true,
	}

	agents := []string{"agent-1", "agent-2", "agent-3"}

	// Send rule-1 to all agents in circular manner
	for _, agent := range agents {
		pa.ProcessRuleEvent(agent, rule1Event)

		// Verify policy exists and track progress
		pa.mu.RLock()
		policy, exists := pa.pendingPolicies[policyName]
		pa.mu.RUnlock()

		assert.True(t, exists, "Policy should exist after processing rule-1 from %s", agent)
		if policy != nil {
			assert.False(t, policy.IsComplete, "Policy should not be complete yet")
			assert.Len(t, policy.RuleResults, 1, "Policy should have 1 rule")

			rule1Result := policy.RuleResults["rule-1"]
			assert.NotNil(t, rule1Result, "Rule-1 should exist")

			// Check agent responses received so far
			for i, agentID := range agents {
				if i <= getAgentIndex(agents, agent) {
					assert.Contains(t, rule1Result.AgentResults, agentID,
						"Rule-1 should have response from %s", agentID)
				}
			}
		}
	}

	// At this point, rule-1 should have responses from all 3 agents, but policy not complete
	// because we're using timeout-only completion
	pa.mu.RLock()
	policy, exists := pa.pendingPolicies[policyName]
	pa.mu.RUnlock()

	assert.True(t, exists, "Policy should still exist after rule-1 completion")
	if policy != nil {
		rule1Result := policy.RuleResults["rule-1"]
		assert.Len(t, rule1Result.AgentResults, 3, "Rule-1 should have responses from all 3 agents")
		assert.Contains(t, rule1Result.AgentResults, "agent-1")
		assert.Contains(t, rule1Result.AgentResults, "agent-2")
		assert.Contains(t, rule1Result.AgentResults, "agent-3")
	}

	// Send rule-2 to all agents in circular manner
	for _, agent := range agents {
		pa.ProcessRuleEvent(agent, rule2Event)

		// Verify policy progress
		pa.mu.RLock()
		policy, exists := pa.pendingPolicies[policyName]
		pa.mu.RUnlock()

		assert.True(t, exists, "Policy should exist after processing rule-2 from %s", agent)
		if policy != nil {
			assert.False(t, policy.IsComplete, "Policy should not be complete yet (timeout-only)")
			assert.Len(t, policy.RuleResults, 2, "Policy should have 2 rules")

			// Verify rule-1 is still complete
			rule1Result := policy.RuleResults["rule-1"]
			assert.Len(t, rule1Result.AgentResults, 3, "Rule-1 should still have all 3 agent responses")

			// Verify rule-2 progress
			rule2Result := policy.RuleResults["rule-2"]
			assert.NotNil(t, rule2Result, "Rule-2 should exist")

			// Check agent responses received so far for rule-2
			for i, agentID := range agents {
				if i <= getAgentIndex(agents, agent) {
					assert.Contains(t, rule2Result.AgentResults, agentID,
						"Rule-2 should have response from %s", agentID)
				}
			}
		}
	}

	// Final verification - both rules should have all agent responses
	pa.mu.RLock()
	policy, exists = pa.pendingPolicies[policyName]
	pa.mu.RUnlock()

	assert.True(t, exists, "Policy should still exist (waiting for timeout)")
	if policy != nil {
		assert.Len(t, policy.RuleResults, 2, "Policy should have 2 rules")

		// Both rules should have responses from all 3 agents
		for _, ruleName := range []string{"rule-1", "rule-2"} {
			ruleResult := policy.RuleResults[ruleName]
			assert.NotNil(t, ruleResult, "Rule %s should exist", ruleName)
			assert.Len(t, ruleResult.AgentResults, 3, "Rule %s should have 3 agent responses", ruleName)
			assert.Contains(t, ruleResult.AgentResults, "agent-1")
			assert.Contains(t, ruleResult.AgentResults, "agent-2")
			assert.Contains(t, ruleResult.AgentResults, "agent-3")
		}
	}

	// Wait for timeout to complete the policy
	time.Sleep(shortTimeout + 50*time.Millisecond)

	// Policy should now be completed via timeout and removed from pending
	pa.mu.RLock()
	_, exists = pa.pendingPolicies[policyName]
	pa.mu.RUnlock()

	assert.False(t, exists, "Policy should be completed and removed from pending")

	// Check that policy was batched with complete results
	mu.Lock()
	assert.Len(t, batchedResults, 1, "Policy should be in batched results")
	if len(batchedResults) > 0 {
		completedPolicy := batchedResults[0]
		assert.Equal(t, policyName, completedPolicy.PolicyName)
		assert.Len(t, completedPolicy.RuleResults, 2, "Policy should have 2 rules")

		// Verify both rules have responses from all 3 agents in final result
		for ruleName, ruleResult := range completedPolicy.RuleResults {
			assert.Len(t, ruleResult.AgentResults, 3, "Rule %s should have 3 agent responses", ruleName)
			assert.Contains(t, ruleResult.AgentResults, "agent-1")
			assert.Contains(t, ruleResult.AgentResults, "agent-2")
			assert.Contains(t, ruleResult.AgentResults, "agent-3")

			// Verify each agent result
			for _, agent := range agents {
				agentResult := ruleResult.AgentResults[agent]
				assert.NotNil(t, agentResult, "Agent %s result should exist for rule %s", agent, ruleName)
				assert.True(t, agentResult.IsSuccess, "Agent %s should report success for rule %s", agent, ruleName)
				assert.Equal(t, agent, agentResult.AgentUID)
			}
		}
	}
	mu.Unlock()

	// Verify no partial sends (since all agents responded)
	assert.Equal(t, int64(1), pa.GetPartialPolicySendCount(), "Should have 1 timeout completion (but complete)")
}

// Helper function to get agent index in the slice
func getAgentIndex(agents []string, agent string) int {
	for i, a := range agents {
		if a == agent {
			return i
		}
	}
	return -1
}

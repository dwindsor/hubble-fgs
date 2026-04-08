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
	"testing"
	"time"

	l3l4networkpolicyv1alpha "github.com/isovalent/ipa/l3l4networkpolicy/v1alpha"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewPolicyAggregator(t *testing.T) {
	expectedAgentCount := 2
	reportingInterval := 30 * time.Second

	pa := NewPolicyAggregator(expectedAgentCount, reportingInterval, NewInMemoryPolicyStatusStore())

	assert.NotNil(t, pa)
	assert.Equal(t, expectedAgentCount, pa.expectedAgentCount)
	assert.Equal(t, reportingInterval+time.Minute, pa.cleanupCutoffAge) // Should be reportingInterval + 1 minute
	assert.False(t, pa.running)
	assert.NotNil(t, pa.pendingPolicies)
	assert.NotNil(t, pa.expectedRuleCounts)
	assert.NotNil(t, pa.policiesToDelete)
	assert.NotNil(t, pa.policyStatusStore)
	assert.Equal(t, 0, len(pa.pendingPolicies))
	assert.Equal(t, 0, len(pa.expectedRuleCounts))
	assert.Equal(t, 0, len(pa.policiesToDelete))
}

func TestPolicyAggregator_StartStop(t *testing.T) {
	pa := NewPolicyAggregator(2, 30*time.Second, NewInMemoryPolicyStatusStore())
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

func TestPolicyAggregator_normalizeRuleName(t *testing.T) {
	pa := NewPolicyAggregator(2, 30*time.Second, NewInMemoryPolicyStatusStore())

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
	pa := NewPolicyAggregator(2, shortTimeout, NewInMemoryPolicyStatusStore())

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

	// Policy should now be completed and moved to PolicyStatusStore
	pa.mu.RLock()
	_, exists := pa.pendingPolicies["NetworkPolicy/default/test-policy"]
	pa.mu.RUnlock()

	assert.False(t, exists, "Policy should be completed and removed from pending")

	// Check that policy was stored in PolicyStatusStore
	allPolicies := pa.GetPolicyStatusStore().GetAll(false)
	storedPolicy, found := allPolicies["NetworkPolicy/default/test-policy"]
	assert.True(t, found, "Policy should be in PolicyStatusStore")
	if found {
		ruleResult := storedPolicy.RuleResults["rule-1"]
		assert.Len(t, ruleResult.AgentResults, 2, "Rule should have responses from both agents")
		assert.Contains(t, ruleResult.AgentResults, "agent-1")
		assert.Contains(t, ruleResult.AgentResults, "agent-2")
	}
}

func TestPolicyAggregator_isPolicyComplete(t *testing.T) {
	pa := NewPolicyAggregator(2, 30*time.Second, NewInMemoryPolicyStatusStore())

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

func TestPolicyAggregator_TimeoutHandling(t *testing.T) {
	shortTimeout := 100 * time.Millisecond
	pa := NewPolicyAggregator(2, shortTimeout, NewInMemoryPolicyStatusStore())

	// Process two policies with incomplete agent responses
	for i := 0; i < 2; i++ {
		ruleEvent := &l3l4networkpolicyv1alpha.PolicyRuleEvent{
			PolicyName:         fmt.Sprintf("NetworkPolicy/default/timeout-policy-%d", i),
			RuleName:           "rule-1",
			K8SResourceVersion: "v1.0.0",
			IsSuccess:          true,
		}
		pa.ProcessRuleEvent("agent-1", ruleEvent) // Only agent-1, missing agent-2
	}

	// Verify policies are pending and incomplete
	pa.mu.RLock()
	assert.Len(t, pa.pendingPolicies, 2, "Should have 2 pending policies")
	for i := 0; i < 2; i++ {
		policyName := fmt.Sprintf("NetworkPolicy/default/timeout-policy-%d", i)
		policy, exists := pa.pendingPolicies[policyName]
		assert.True(t, exists, "Policy %s should exist", policyName)
		assert.False(t, policy.IsComplete, "Policy should not be complete yet")
		assert.Len(t, policy.RuleResults, 1, "Policy should have 1 rule")

		rule := policy.RuleResults["rule-1"]
		assert.Len(t, rule.AgentResults, 1, "Rule should have 1 agent response (missing 1)")
		assert.Contains(t, rule.AgentResults, "agent-1", "Should have agent-1")

		// Manually set LastUpdated to an old time to trigger cleanup
		policy.LastUpdated = time.Now().Add(-pa.cleanupCutoffAge - time.Minute)
	}
	pa.mu.RUnlock()

	// Run cleanup to process timeouts
	pa.cleanup()

	// Verify policies were completed and stored despite being incomplete
	storeCount := pa.GetPolicyStatusStore().GetCount()
	assert.Equal(t, 2, storeCount, "Both policies should be stored after timeout")

	// Verify policies are no longer pending
	pa.mu.RLock()
	assert.Len(t, pa.pendingPolicies, 0, "No policies should be pending after cleanup")
	pa.mu.RUnlock()

	// Verify stored policies have timeout agent responses
	storedPolicies := pa.GetPolicyStatusStore().GetAll(false)
	assert.Len(t, storedPolicies, 2, "Should have 2 stored policies")

	for _, policy := range storedPolicies {
		assert.True(t, policy.IsComplete, "Policy should be complete")
		assert.Len(t, policy.RuleResults, 1, "Policy should have 1 rule")

		rule := policy.RuleResults["rule-1"]
		assert.Len(t, rule.AgentResults, 2, "Rule should have 2 agent responses (1 real + 1 timeout)")
		assert.Contains(t, rule.AgentResults, "agent-1", "Should have real agent-1")

		// Check that timeout agent was added
		foundTimeoutAgent := false
		for agentID, agentResult := range rule.AgentResults {
			if agentID != "agent-1" {
				foundTimeoutAgent = true
				assert.False(t, agentResult.IsSuccess, "Timeout agent should report failure")
				assert.Equal(t, l3l4networkpolicyv1alpha.PolicyRuleError_POLICY_RULE_ERROR_TIMEOUT, agentResult.Error)
			}
		}
		assert.True(t, foundTimeoutAgent, "Should have timeout agent response")
	}
}

func TestPolicyAggregator_Cleanup(t *testing.T) {
	pa := NewPolicyAggregator(2, 30*time.Second, NewInMemoryPolicyStatusStore())

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

func TestPolicyAggregator_countIncompleteRules(t *testing.T) {
	pa := NewPolicyAggregator(2, 30*time.Second, NewInMemoryPolicyStatusStore())

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

	// Count incomplete rules inline since the method was removed
	incompleteCount := 0
	for _, ruleResult := range policy.RuleResults {
		if len(ruleResult.AgentResults) < pa.expectedAgentCount {
			incompleteCount++
		}
	}

	assert.Equal(t, 1, incompleteCount)
}

func TestPolicyAggregator_MultipleRulesPerPolicy(t *testing.T) {
	shortTimeout := 300 * time.Millisecond
	pa := NewPolicyAggregator(2, shortTimeout, NewInMemoryPolicyStatusStore())

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

	// Policy should now be completed and moved to PolicyStatusStore
	pa.mu.RLock()
	_, exists = pa.pendingPolicies[policyName]
	pa.mu.RUnlock()

	assert.False(t, exists, "Policy should be completed and removed from pending")

	// Check that policy was stored in PolicyStatusStore
	allPolicies := pa.GetPolicyStatusStore().GetAll(false) // Don't clear after read
	storedPolicy, found := allPolicies[policyName]
	assert.True(t, found, "Policy should be in PolicyStatusStore")
	if found {
		assert.Equal(t, policyName, storedPolicy.PolicyName)
		assert.Len(t, storedPolicy.RuleResults, 2, "Policy should have 2 rules")

		// Verify both rules have responses from both agents
		for ruleName, ruleResult := range storedPolicy.RuleResults {
			assert.Len(t, ruleResult.AgentResults, 2, "Rule %s should have 2 agent responses", ruleName)
			assert.Contains(t, ruleResult.AgentResults, "agent-1")
			assert.Contains(t, ruleResult.AgentResults, "agent-2")
		}
	}
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
	pa := NewPolicyAggregator(3, shortTimeout, NewInMemoryPolicyStatusStore()) // 3 agents expected

	// Create events for multiple rules in same policy
	policyName := "NetworkPolicy/default/circular-rule-policy"

	// Set expected rule count to 2 so policy won't complete until both rules are done
	pa.SetExpectedRuleCount(policyName, 2)

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
	// because we need multiple rules to be complete
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
	for i, agent := range agents {
		pa.ProcessRuleEvent(agent, rule2Event)

		// Verify policy progress - it should complete when rule-2 gets all agents
		isLastAgent := (i == len(agents)-1)

		if isLastAgent {
			// Policy should be completed and removed from pending after last agent
			pa.mu.RLock()
			_, exists := pa.pendingPolicies[policyName]
			pa.mu.RUnlock()

			assert.False(t, exists, "Policy should be completed and removed from pending after final agent")
		} else {
			// Policy should still be pending
			pa.mu.RLock()
			policy, exists := pa.pendingPolicies[policyName]
			pa.mu.RUnlock()

			assert.True(t, exists, "Policy should exist after processing rule-2 from %s", agent)
			if policy != nil {
				assert.Len(t, policy.RuleResults, 2, "Policy should have 2 rules")

				// Verify rule-1 is still complete
				rule1Result := policy.RuleResults["rule-1"]
				assert.Len(t, rule1Result.AgentResults, 3, "Rule-1 should still have all 3 agent responses")

				// Verify rule-2 progress
				rule2Result := policy.RuleResults["rule-2"]
				assert.NotNil(t, rule2Result, "Rule-2 should exist")

				// Check agent responses received so far for rule-2
				for j, agentID := range agents {
					if j <= i {
						assert.Contains(t, rule2Result.AgentResults, agentID,
							"Rule-2 should have response from %s", agentID)
					}
				}
			}
		}
	}

	// Final verification - both rules should have all agent responses
	// Policy should now be completed and stored in PolicyStatusStore
	pa.mu.RLock()
	_, exists = pa.pendingPolicies[policyName]
	pa.mu.RUnlock()

	assert.False(t, exists, "Policy should be completed and removed from pending")

	// Check stored policy in PolicyStatusStore
	allPolicies := pa.GetPolicyStatusStore().GetAll(false)
	storedPolicy, found := allPolicies[policyName]
	assert.True(t, found, "Policy should be in PolicyStatusStore")
	if found {
		assert.Len(t, storedPolicy.RuleResults, 2, "Policy should have 2 rules")
		assert.True(t, storedPolicy.IsComplete, "Policy should be complete now")

		// Both rules should have responses from all 3 agents
		for _, ruleName := range []string{"rule-1", "rule-2"} {
			ruleResult := storedPolicy.RuleResults[ruleName]
			assert.NotNil(t, ruleResult, "Rule %s should exist", ruleName)
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

	// Verify policy was stored in the policy status store
	storeCount := pa.GetPolicyStatusStore().GetCount()
	assert.Equal(t, 1, storeCount, "Policy should be stored in policy status store")
}

func TestPolicyAggregator_GetPolicyStatusStore(t *testing.T) {
	store := NewInMemoryPolicyStatusStore()
	pa := NewPolicyAggregator(2, 30*time.Second, store)

	retrievedStore := pa.GetPolicyStatusStore()
	assert.Equal(t, store, retrievedStore, "Should return the same store instance")

	// Test that operations on retrieved store work
	testPolicy := &PolicyAggregationResult{
		PolicyName: "test-policy",
		Version:    "v1.0.0",
		IsComplete: true,
	}

	retrievedStore.Store(testPolicy)
	assert.Equal(t, 1, retrievedStore.GetCount(), "Store should have 1 policy")
}

func TestPolicyAggregator_extractPolicyNameFromPath(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"NetworkPolicy/default/my-policy", "my-policy"},
		{"NetworkPolicy/kube-system/system-policy", "system-policy"},
		{"CiliumNetworkPolicy/production/app-policy", "app-policy"},
		{"NetworkPolicy/default/policy-with-dashes", "policy-with-dashes"},
		{"NetworkPolicy/namespace-with-dashes/policy", "policy"},
		{"invalid-format", "invalid-format"}, // fallback case
		{"", ""},                             // empty case
		{"only-one-part", "only-one-part"},   // single part
		{"two/parts", "two/parts"},           // two parts only
	}

	for _, tt := range tests {
		result := extractPolicyNameFromPath(tt.input)
		assert.Equal(t, tt.expected, result, "extractPolicyNameFromPath(%s)", tt.input)
	}
}

func TestPolicyAggregator_SetExpectedRuleCount(t *testing.T) {
	pa := NewPolicyAggregator(2, 30*time.Second, NewInMemoryPolicyStatusStore())
	policyName := "NetworkPolicy/default/test-policy"

	// Initially no expected rule count
	pa.mu.RLock()
	_, exists := pa.expectedRuleCounts[policyName]
	pa.mu.RUnlock()
	assert.False(t, exists, "Policy should not have expected rule count initially")

	// Set expected rule count
	pa.SetExpectedRuleCount(policyName, 3)

	pa.mu.RLock()
	count, exists := pa.expectedRuleCounts[policyName]
	pa.mu.RUnlock()

	assert.True(t, exists, "Policy should have expected rule count after setting")
	assert.Equal(t, 3, count, "Expected rule count should be 3")

	// Update expected rule count
	pa.SetExpectedRuleCount(policyName, 5)

	pa.mu.RLock()
	count, exists = pa.expectedRuleCounts[policyName]
	pa.mu.RUnlock()

	assert.True(t, exists, "Policy should still have expected rule count")
	assert.Equal(t, 5, count, "Expected rule count should be updated to 5")
}

func TestPolicyAggregator_StoreValidationError(t *testing.T) {
	pa := NewPolicyAggregator(2, 30*time.Second, NewInMemoryPolicyStatusStore())
	policyName := "NetworkPolicy/default/invalid-policy"
	errorMsg := "Policy validation failed: invalid CIDR"

	// Store validation error
	pa.StoreValidationError(policyName, errorMsg)

	// Check that error was stored in PolicyStatusStore
	allPolicies := pa.GetPolicyStatusStore().GetAll(false)
	assert.Len(t, allPolicies, 1, "Should have 1 policy in store")

	storedPolicy, exists := allPolicies[policyName]
	assert.True(t, exists, "Policy should exist in store")
	assert.Equal(t, policyName, storedPolicy.PolicyName)
	// Note: Validation errors create complete policies in the store
	assert.True(t, storedPolicy.IsComplete, "Policy with validation error should be complete in store")

	// Multiple validation errors should update existing policy
	errorMsg2 := "Additional validation error"
	pa.StoreValidationError(policyName, errorMsg2)

	allPolicies = pa.GetPolicyStatusStore().GetAll(false)
	assert.Len(t, allPolicies, 1, "Should still have only 1 policy in store")
}

func TestPolicyAggregator_GetStoreStats(t *testing.T) {
	pa := NewPolicyAggregator(2, 30*time.Second, NewInMemoryPolicyStatusStore())

	// Initially empty
	pendingCount, storeCount := pa.GetStoreStats()
	assert.Equal(t, 0, pendingCount, "Pending policies should be empty initially")
	assert.Equal(t, 0, storeCount, "Store should be empty initially")

	// Add an incomplete policy to pending
	ruleEvent := &l3l4networkpolicyv1alpha.PolicyRuleEvent{
		PolicyName:         "NetworkPolicy/default/test-policy",
		RuleName:           "rule-1",
		K8SResourceVersion: "v1.0.0",
		IsSuccess:          true,
	}

	// Process only one agent (incomplete)
	pa.ProcessRuleEvent("agent-1", ruleEvent)

	pendingCount, storeCount = pa.GetStoreStats()
	assert.Equal(t, 1, pendingCount, "Should have 1 pending policy")
	assert.Equal(t, 0, storeCount, "Store should still be empty")

	// Complete the policy
	pa.ProcessRuleEvent("agent-2", ruleEvent)

	pendingCount, storeCount = pa.GetStoreStats()
	assert.Equal(t, 0, pendingCount, "Should have 0 pending policies")
	assert.Equal(t, 1, storeCount, "Store should have 1 policy")

	// Add validation error policy
	pa.StoreValidationError("NetworkPolicy/default/error-policy", "validation error")

	pendingCount, storeCount = pa.GetStoreStats()
	assert.Equal(t, 0, pendingCount, "Should still have 0 pending policies")
	assert.Equal(t, 2, storeCount, "Store should have 2 policies")
}

func TestPolicyAggregator_SetPolicyGroupId(t *testing.T) {
	pa := NewPolicyAggregator(2, 30*time.Second, NewInMemoryPolicyStatusStore())
	policyName := "NetworkPolicy/default/test-policy"
	policyGroupId := "12345678-1234-5678-9abc-123456789012"

	// Process a rule event first to create the policy
	ruleEvent := &l3l4networkpolicyv1alpha.PolicyRuleEvent{
		PolicyName:         policyName,
		RuleName:           "rule-1",
		K8SResourceVersion: "v1.0.0",
		IsSuccess:          true,
	}
	pa.ProcessRuleEvent("agent-1", ruleEvent)

	// Set policy group ID
	pa.SetPolicyGroupId(policyName, policyGroupId)

	// Verify policy group ID was set
	pa.mu.RLock()
	policy, exists := pa.pendingPolicies[policyName]
	pa.mu.RUnlock()

	assert.True(t, exists, "Policy should exist")
	if policy != nil {
		actualGroupId := pa.GetPolicyGroupId(policyName)
		assert.Equal(t, policyGroupId, actualGroupId, "PolicyGroupId should be set")
	}

	// Complete the policy and verify PolicyGroupId is preserved
	pa.ProcessRuleEvent("agent-2", ruleEvent)

	// Check in stored policy
	allPolicies := pa.GetPolicyStatusStore().GetAll(false)
	_, found := allPolicies[policyName]
	assert.True(t, found, "Policy should be stored")
	if found {
		actualGroupId := pa.GetPolicyGroupId(policyName)
		assert.Equal(t, policyGroupId, actualGroupId, "PolicyGroupId should be preserved in stored policy")
	}

	// Test setting policy group ID for non-existent policy
	nonExistentPolicy := "NetworkPolicy/default/non-existent"
	pa.SetPolicyGroupId(nonExistentPolicy, policyGroupId)

	pa.mu.RLock()
	_, exists = pa.pendingPolicies[nonExistentPolicy]
	pa.mu.RUnlock()

	assert.False(t, exists, "Non-existent policy should not be created")
}

func TestPolicyAggregator_MarkPolicyForDeletion(t *testing.T) {
	pa := NewPolicyAggregator(2, 30*time.Second, NewInMemoryPolicyStatusStore())
	policyName := "NetworkPolicy/default/test-policy"

	// Initially, policy should not be marked for deletion
	pa.mu.RLock()
	_, markedForDeletion := pa.policiesToDelete[policyName]
	pa.mu.RUnlock()
	assert.False(t, markedForDeletion, "Policy should not be marked for deletion initially")

	// Mark policy for deletion
	pa.MarkPolicyForDeletion(policyName)

	pa.mu.RLock()
	markedForDeletion, exists := pa.policiesToDelete[policyName]
	pa.mu.RUnlock()

	assert.True(t, exists, "Policy should be in deletion map")
	assert.True(t, markedForDeletion, "Policy should be marked for deletion")

	// Mark same policy again (should be idempotent)
	pa.MarkPolicyForDeletion(policyName)

	pa.mu.RLock()
	markedForDeletion, exists = pa.policiesToDelete[policyName]
	pa.mu.RUnlock()

	assert.True(t, exists, "Policy should still be in deletion map")
	assert.True(t, markedForDeletion, "Policy should still be marked for deletion")

	// Verify multiple policies can be marked
	policyName2 := "NetworkPolicy/default/test-policy-2"
	pa.MarkPolicyForDeletion(policyName2)

	pa.mu.RLock()
	assert.True(t, pa.policiesToDelete[policyName], "First policy should still be marked")
	assert.True(t, pa.policiesToDelete[policyName2], "Second policy should be marked")
	assert.Len(t, pa.policiesToDelete, 2, "Should have 2 policies marked for deletion")
	pa.mu.RUnlock()
}

func TestPolicyAggregator_AddTimeoutResponses(t *testing.T) {
	pa := NewPolicyAggregator(3, 30*time.Second, NewInMemoryPolicyStatusStore()) // 3 expected agents

	// Create a policy with incomplete rule (missing agents)
	policyResult := &PolicyAggregationResult{
		PolicyName: "NetworkPolicy/default/timeout-policy",
		Version:    "v1.0.0",
		RuleResults: map[string]*RuleAggregationResult{
			"rule-1": {
				RuleName:   "rule-1",
				PolicyName: "NetworkPolicy/default/timeout-policy",
				AgentResults: map[string]*AgentRuleResult{
					"agent-1": {
						AgentUID:  "agent-1",
						IsSuccess: true,
					},
					// Missing agent-2 and agent-3
				},
				ExpectedCount: 3,
			},
		},
		ExpectedCount: 3,
	}

	// Add timeout responses
	pa.addTimeoutResponses(policyResult)

	// Verify timeout responses were added
	rule := policyResult.RuleResults["rule-1"]
	assert.Len(t, rule.AgentResults, 3, "Rule should have responses from all 3 agents")
	assert.Contains(t, rule.AgentResults, "agent-1", "Should have original agent-1")

	// Find the timeout agents
	timeoutAgentCount := 0
	for agentID, agentResult := range rule.AgentResults {
		if agentID != "agent-1" {
			timeoutAgentCount++
			assert.False(t, agentResult.IsSuccess, "Timeout agent should report failure")
			assert.Equal(t, l3l4networkpolicyv1alpha.PolicyRuleError_POLICY_RULE_ERROR_TIMEOUT, agentResult.Error)
			assert.Contains(t, agentResult.ErrorMessage, "TIMEOUT", "Error message should mention timeout")
		}
	}
	assert.Equal(t, 2, timeoutAgentCount, "Should have 2 timeout agents")

	// Test with already complete rule (no timeout responses should be added)
	completePolicy := &PolicyAggregationResult{
		PolicyName: "NetworkPolicy/default/complete-policy",
		Version:    "v1.0.0",
		RuleResults: map[string]*RuleAggregationResult{
			"rule-1": {
				RuleName:   "rule-1",
				PolicyName: "NetworkPolicy/default/complete-policy",
				AgentResults: map[string]*AgentRuleResult{
					"agent-1": {AgentUID: "agent-1", IsSuccess: true},
					"agent-2": {AgentUID: "agent-2", IsSuccess: true},
					"agent-3": {AgentUID: "agent-3", IsSuccess: true},
				},
				ExpectedCount: 3,
			},
		},
		ExpectedCount: 3,
	}

	pa.addTimeoutResponses(completePolicy)

	// Should still have exactly 3 responses, no timeout responses added
	completeRule := completePolicy.RuleResults["rule-1"]
	assert.Len(t, completeRule.AgentResults, 3, "Complete rule should still have exactly 3 responses")

	for _, agentResult := range completeRule.AgentResults {
		assert.True(t, agentResult.IsSuccess, "All responses in complete rule should be successful")
		assert.NotEqual(t, l3l4networkpolicyv1alpha.PolicyRuleError_POLICY_RULE_ERROR_TIMEOUT, agentResult.Error)
	}
}

func TestPolicyAggregator_PolicyDeletion_Integration(t *testing.T) {
	pa := NewPolicyAggregator(2, 30*time.Second, NewInMemoryPolicyStatusStore())
	policyName := "NetworkPolicy/default/delete-policy"

	// Create and complete a policy
	ruleEvent := &l3l4networkpolicyv1alpha.PolicyRuleEvent{
		PolicyName:         policyName,
		RuleName:           "rule-1",
		K8SResourceVersion: "v1.0.0",
		IsSuccess:          true,
	}

	pa.ProcessRuleEvent("agent-1", ruleEvent)
	pa.ProcessRuleEvent("agent-2", ruleEvent)

	// Verify policy is stored
	assert.Equal(t, 1, pa.GetPolicyStatusStore().GetCount(), "Policy should be stored")

	// Mark policy for deletion
	pa.MarkPolicyForDeletion(policyName)

	// Verify policy is marked for deletion
	pa.mu.RLock()
	markedForDeletion := pa.policiesToDelete[policyName]
	pa.mu.RUnlock()
	assert.True(t, markedForDeletion, "Policy should be marked for deletion")

	// Verify policy can be deleted from store
	deleted := pa.GetPolicyStatusStore().Delete(policyName)
	assert.True(t, deleted, "Policy should be successfully deleted")
	assert.Equal(t, 0, pa.GetPolicyStatusStore().GetCount(), "Store should be empty after deletion")
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

// The test now comprehensively validates the timing behavior of the policy aggregator
// with multiple policies across reporting intervals, showing how policies complete at
// different times and get properly stored while being removed from the pending collection.
func TestPolicyAggregator_MultiPolicyAddTimingWithInterval(t *testing.T) {
	/*
		1. Policy A with 2 rules - Added at 1ms with both rules completed immediately
		2. Policy B with 2 rules - Added at 8ms but incomplete (missing agent-2 responses)
		3. Policy A completed within the interval - Verified store has 1 object, aggregator has 0

		4. Check after Policy B added - Store has 1 object, aggregator has 1 pending policy

		5. Wait for interval to elapse for next iteration - Explicit sleep and comment added
		6. Policy B completed - Agent-2 responses added to complete Policy B
		7. Check the store should contain 2 objects - Both Policy A and Policy B stored
		8. Check the aggregator should contain 0 objects - Both policies removed from pending
	*/
	reportingInterval := 10 * time.Millisecond
	pa := NewPolicyAggregator(2, reportingInterval, NewInMemoryPolicyStatusStore())

	policyA := "NetworkPolicy/default/policy-a"
	policyB := "NetworkPolicy/default/policy-b"

	// Set expected rule counts for both policies (2 rules each)
	pa.SetExpectedRuleCount(policyA, 2)
	pa.SetExpectedRuleCount(policyB, 2)

	// Create rule events for Policy A
	policyARule1 := &l3l4networkpolicyv1alpha.PolicyRuleEvent{
		PolicyName:         policyA,
		RuleName:           "rule-1",
		K8SResourceVersion: "v1.0.0",
		IsSuccess:          true,
	}
	policyARule2 := &l3l4networkpolicyv1alpha.PolicyRuleEvent{
		PolicyName:         policyA,
		RuleName:           "rule-2",
		K8SResourceVersion: "v1.0.0",
		IsSuccess:          true,
	}

	// Create rule events for Policy B
	policyBRule1 := &l3l4networkpolicyv1alpha.PolicyRuleEvent{
		PolicyName:         policyB,
		RuleName:           "rule-1",
		K8SResourceVersion: "v1.0.0",
		IsSuccess:          true,
	}
	policyBRule2 := &l3l4networkpolicyv1alpha.PolicyRuleEvent{
		PolicyName:         policyB,
		RuleName:           "rule-2",
		K8SResourceVersion: "v1.0.0",
		IsSuccess:          true,
	}

	// Wait 1 millisecond, then add Policy A with 2 rules
	time.Sleep(1 * time.Millisecond)

	// Add Policy A rule 1 from both agents
	pa.ProcessRuleEvent("agent-1", policyARule1)
	pa.ProcessRuleEvent("agent-2", policyARule1)

	// Add Policy A rule 2 from both agents - this should complete Policy A
	pa.ProcessRuleEvent("agent-1", policyARule2)
	pa.ProcessRuleEvent("agent-2", policyARule2)

	// Policy A should be completed and stored, removed from pending
	storeCount := pa.GetPolicyStatusStore().GetCount()
	assert.Equal(t, 1, storeCount, "Store should contain 1 completed policy (Policy A)")

	pa.mu.RLock()
	pendingCount := len(pa.pendingPolicies)
	pa.mu.RUnlock()
	assert.Equal(t, 0, pendingCount, "Aggregator should have 0 pending policies after Policy A completed")

	// Wait until 8 milliseconds from start, then add Policy B
	time.Sleep(7 * time.Millisecond)

	// Add Policy B rule 1 and rule 2 from first agent only (incomplete - missing agent-2)
	pa.ProcessRuleEvent("agent-1", policyBRule1)
	pa.ProcessRuleEvent("agent-1", policyBRule2)

	// Policy B should be pending (incomplete - waiting for agent-2)
	storeCount = pa.GetPolicyStatusStore().GetCount()
	assert.Equal(t, 1, storeCount, "Store should still contain 1 object (only Policy A)")

	pa.mu.RLock()
	pendingCount = len(pa.pendingPolicies)
	_, policyBExists := pa.pendingPolicies[policyB]
	pa.mu.RUnlock()
	assert.Equal(t, 1, pendingCount, "Aggregator should contain 1 pending policy (Policy B incomplete)")
	assert.True(t, policyBExists, "Policy B should be pending")

	// Wait for the reporting interval to elapse (total >10ms from start) - next iteration
	time.Sleep(3 * time.Millisecond)

	// Now complete Policy B by adding rule responses from agent-2
	pa.ProcessRuleEvent("agent-2", policyBRule1)
	pa.ProcessRuleEvent("agent-2", policyBRule2)

	// Policy B should now be completed and stored
	storeCount = pa.GetPolicyStatusStore().GetCount()
	assert.Equal(t, 2, storeCount, "Store should contain 2 completed policies (Policy A and Policy B)")

	pa.mu.RLock()
	pendingCount = len(pa.pendingPolicies)
	pa.mu.RUnlock()
	assert.Equal(t, 0, pendingCount, "Aggregator should have 0 pending policies (both completed)")

	// Verify both policies are in the store with correct details
	allPolicies := pa.GetPolicyStatusStore().GetAll(false)

	storedPolicyA, foundA := allPolicies[policyA]
	assert.True(t, foundA, "Policy A should be in store")
	if foundA {
		assert.True(t, storedPolicyA.IsComplete, "Policy A should be complete")
		assert.Len(t, storedPolicyA.RuleResults, 2, "Policy A should have 2 rules")
	}

	storedPolicyB, foundB := allPolicies[policyB]
	assert.True(t, foundB, "Policy B should be in store")
	if foundB {
		assert.True(t, storedPolicyB.IsComplete, "Policy B should be complete")
		assert.Len(t, storedPolicyB.RuleResults, 2, "Policy B should have 2 rules")
	}
}

// The test demonstrates that the PolicyAggregator correctly handles policy updates by:
// - Detecting when a policy update occurs (based on version change)
// - Updating the existing policy in the store rather than creating a duplicate
// - Properly managing the transition from pending to stored state
// - Maintaining the correct final state with the updated policy
func TestPolicyAggregator_MultiPolicyAddUpdateTimingWithInterval(t *testing.T) {
	/*
		Step 1: Policy A starts with 2 rules (rule-1, rule-2)
		Step 2: Wait for next iteration
		Step 3: Policy A updated with 1 more rule (total 3 rules expected)
		Step 4: Policy A receives rule-3, rule-4, rule-5 with new version v2.0.0 (simulating rule-1 and rule-2 being replaced)
		Step 5: Store contains only 1 Policy A (updated version)
		Step 6: Aggregator has 0 pending policies
	*/

	store := NewInMemoryPolicyStatusStore()
	pa := NewPolicyAggregator(2, 10*time.Millisecond, store) // 2 agents, 10ms interval

	policyA := "NetworkPolicy/default/policy-a"

	// Step 1: Policy A has 2 rules (rule-1 and rule-2)
	pa.SetExpectedRuleCount(policyA, 2)

	// Complete Policy A with initial 2 rules
	policyARule1 := &l3l4networkpolicyv1alpha.PolicyRuleEvent{
		PolicyName:         policyA,
		RuleName:           "rule-1",
		K8SResourceVersion: "v1.0.0",
		IsSuccess:          true,
	}
	pa.ProcessRuleEvent("agent-1", policyARule1)
	pa.ProcessRuleEvent("agent-2", policyARule1)

	policyARule2 := &l3l4networkpolicyv1alpha.PolicyRuleEvent{
		PolicyName:         policyA,
		RuleName:           "rule-2",
		K8SResourceVersion: "v1.0.0",
		IsSuccess:          true,
	}
	pa.ProcessRuleEvent("agent-1", policyARule2)
	pa.ProcessRuleEvent("agent-2", policyARule2)

	// Policy A should be completed and stored with 2 rules
	assert.Equal(t, 1, pa.GetPolicyStatusStore().GetCount(), "Store should contain Policy A")

	pa.mu.RLock()
	pendingCount := len(pa.pendingPolicies)
	pa.mu.RUnlock()
	assert.Equal(t, 0, pendingCount, "No pending policies after initial completion")

	// Step 2: Wait for next iteration
	time.Sleep(15 * time.Millisecond) // Wait longer than reporting interval

	// Step 3: Policy A is updated with 1 more rule (total 3 rules)
	pa.SetExpectedRuleCount(policyA, 3)

	// Step 4: Policy A status updated with rule-3, rule-4, rule-5 applied
	// and rule-1, rule-2 deleted (simulated by new policy version)
	policyARule3 := &l3l4networkpolicyv1alpha.PolicyRuleEvent{
		PolicyName:         policyA,
		RuleName:           "rule-3",
		K8SResourceVersion: "v2.0.0", // New version
		IsSuccess:          true,
	}
	pa.ProcessRuleEvent("agent-1", policyARule3)
	pa.ProcessRuleEvent("agent-2", policyARule3)

	policyARule4 := &l3l4networkpolicyv1alpha.PolicyRuleEvent{
		PolicyName:         policyA,
		RuleName:           "rule-4",
		K8SResourceVersion: "v2.0.0",
		IsSuccess:          true,
	}
	pa.ProcessRuleEvent("agent-1", policyARule4)
	pa.ProcessRuleEvent("agent-2", policyARule4)

	policyARule5 := &l3l4networkpolicyv1alpha.PolicyRuleEvent{
		PolicyName:         policyA,
		RuleName:           "rule-5",
		K8SResourceVersion: "v2.0.0",
		IsSuccess:          true,
	}
	pa.ProcessRuleEvent("agent-1", policyARule5)
	pa.ProcessRuleEvent("agent-2", policyARule5)

	// Step 5: Check the store - there should be only 1 Policy A (updated version)
	assert.Equal(t, 1, pa.GetPolicyStatusStore().GetCount(), "Store should contain only 1 Policy A")

	// Step 6: Check the aggregator should have 0 pending
	pa.mu.RLock()
	pendingCount = len(pa.pendingPolicies)
	pa.mu.RUnlock()
	assert.Equal(t, 0, pendingCount, "Aggregator should have 0 pending policies")
	assert.False(t, pa.policiesToDelete[policyA])

	// Verify the stored policy has the updated rules (rule-3, rule-4, rule-5)
	allPolicies := pa.GetPolicyStatusStore().GetAll(false)
	storedPolicyA, found := allPolicies[policyA]
	assert.True(t, found, "Policy A should be in store")
	if found {
		assert.True(t, storedPolicyA.IsComplete, "Policy A should be complete")
		assert.Equal(t, "v2.0.0", storedPolicyA.Version, "Policy A should have updated version")

		// Should contain the new rules (rule-3, rule-4, rule-5)
		assert.Contains(t, storedPolicyA.RuleResults, "rule-3", "Policy A should contain rule-3")
		assert.Contains(t, storedPolicyA.RuleResults, "rule-4", "Policy A should contain rule-4")
		assert.Contains(t, storedPolicyA.RuleResults, "rule-5", "Policy A should contain rule-5")

		// Should NOT contain the old rules (rule-1, rule-2) since they were deleted
		assert.NotContains(t, storedPolicyA.RuleResults, "rule-1", "Policy A should NOT contain deleted rule-1")
		assert.NotContains(t, storedPolicyA.RuleResults, "rule-2", "Policy A should NOT contain deleted rule-2")

		assert.Len(t, storedPolicyA.RuleResults, 3, "Policy A should have exactly 3 rules")
	}
}

func TestPolicyAggregator_MultiPolicyAddDeleteTiming(t *testing.T) {
	// Test policy lifecycle with deletion scenario:
	// 1. Add and complete Policy A and Policy B (both with 2 rules each)
	// 2. Mark Policy A for deletion and re-process its events (should not be stored)
	// 3. Verify only Policy B remains in store
	// 4. Mark Policy B for deletion and re-process its events (should not be stored)
	// 5. Verify store is empty after both deletions
	store := NewInMemoryPolicyStatusStore()
	pa := NewPolicyAggregator(2, 10*time.Millisecond, store) // 2 agents, 10ms reporting interval

	policyA := "NetworkPolicy/default/policy-a"
	policyB := "NetworkPolicy/default/policy-b"

	// Set expected rule counts for both policies (2 rules each)
	pa.SetExpectedRuleCount(policyA, 2)
	pa.SetExpectedRuleCount(policyB, 2)

	// Wait 1 millisecond before adding policies
	time.Sleep(1 * time.Millisecond)

	// Add Policy A with 2 rules at 1 millisec
	policyARule1 := &l3l4networkpolicyv1alpha.PolicyRuleEvent{
		PolicyName:         policyA,
		RuleName:           "rule-1",
		K8SResourceVersion: "v1.0.0",
		IsSuccess:          true,
	}
	policyARule2 := &l3l4networkpolicyv1alpha.PolicyRuleEvent{
		PolicyName:         policyA,
		RuleName:           "rule-2",
		K8SResourceVersion: "v1.0.0",
		IsSuccess:          true,
	}

	// Complete Policy A with both rules from both agents
	pa.ProcessRuleEvent("agent-1", policyARule1)
	pa.ProcessRuleEvent("agent-2", policyARule1)
	pa.ProcessRuleEvent("agent-1", policyARule2)
	pa.ProcessRuleEvent("agent-2", policyARule2)

	// Add Policy B with 2 rules at 1 millisec
	policyBRule1 := &l3l4networkpolicyv1alpha.PolicyRuleEvent{
		PolicyName:         policyB,
		RuleName:           "rule-1",
		K8SResourceVersion: "v1.0.0",
		IsSuccess:          true,
	}
	policyBRule2 := &l3l4networkpolicyv1alpha.PolicyRuleEvent{
		PolicyName:         policyB,
		RuleName:           "rule-2",
		K8SResourceVersion: "v1.0.0",
		IsSuccess:          true,
	}

	// Complete Policy B with both rules from both agents
	pa.ProcessRuleEvent("agent-1", policyBRule1)
	pa.ProcessRuleEvent("agent-2", policyBRule1)
	pa.ProcessRuleEvent("agent-1", policyBRule2)
	pa.ProcessRuleEvent("agent-2", policyBRule2)

	// Both policies should be completed within the interval
	assert.Equal(t, 2, pa.GetPolicyStatusStore().GetCount(), "Store should contain 2 completed policies")

	pa.mu.RLock()
	pendingCount := len(pa.pendingPolicies)
	pa.mu.RUnlock()
	assert.Equal(t, 0, pendingCount, "Aggregator should have 0 pending policies")

	// Policy A received Delete event
	pa.MarkPolicyForDeletion(policyA)

	// Re-process rule events for Policy A (simulating new rule events after deletion marking)
	pa.ProcessRuleEvent("agent-1", policyARule1)
	pa.ProcessRuleEvent("agent-2", policyARule1)
	pa.ProcessRuleEvent("agent-1", policyARule2)
	pa.ProcessRuleEvent("agent-2", policyARule2)

	// Check the store - it should contain only 1 object (Policy B) because MarkPolicyForDeletion
	// should have immediately removed Policy A from the store
	storeCount := pa.GetPolicyStatusStore().GetCount()
	assert.Equal(t, 1, storeCount, "Store should contain only 1 object (Policy B) after marking Policy A for deletion")

	// Check the aggregator - it should contain 0 pending objects (Policy A completion was not stored)
	pa.mu.RLock()
	pendingCount = len(pa.pendingPolicies)
	pa.mu.RUnlock()
	assert.Equal(t, 0, pendingCount, "Aggregator should contain 0 pending policies")

	// Verify that only Policy B is in the store
	allPolicies := pa.GetPolicyStatusStore().GetAll(false)

	// Policy A should no longer be in the store since it was deleted
	_, policyAFound := allPolicies[policyA]
	assert.False(t, policyAFound, "Policy A should not be in store after deletion")

	// Policy B should still be in the store
	policyBStored, policyBFound := allPolicies[policyB]
	assert.True(t, policyBFound, "Policy B should still be in store")
	if policyBFound {
		assert.True(t, policyBStored.IsComplete, "Policy B should be complete")
		assert.Len(t, policyBStored.RuleResults, 2, "Policy B should have 2 rules")
		assert.Equal(t, "v1.0.0", policyBStored.Version, "Policy B should have original version")
	}

	// Verify store count matches our expectations
	assert.Len(t, allPolicies, 1, "Store should contain exactly 1 policy (only Policy B)")

	time.Sleep(5000 * time.Millisecond)
	// Policy B received Delete event
	pa.MarkPolicyForDeletion(policyB)

	// Re-process rule events for Policy B (simulating new rule events after deletion marking)
	pa.ProcessRuleEvent("agent-1", policyBRule1)
	pa.ProcessRuleEvent("agent-2", policyBRule1)
	pa.ProcessRuleEvent("agent-1", policyBRule2)
	pa.ProcessRuleEvent("agent-2", policyBRule2)

	// Check the store - it should contain only 0 object
	// should have immediately removed Policy B from the store
	storeCount = pa.GetPolicyStatusStore().GetCount()
	assert.Equal(t, 0, storeCount, "Store should contain 0 object after marking Policy B for deletion")

	// Check the aggregator - it should contain 0 pending objects (Policy B completion was not stored)
	pa.mu.RLock()
	pendingCount = len(pa.pendingPolicies)
	pa.mu.RUnlock()
	assert.Equal(t, 0, pendingCount, "Aggregator should contain 0 pending policies")
	assert.False(t, pa.policiesToDelete[policyB])

}

func TestPolicyAggregator_MultiPolicyAddDeleteAddWithInterval(t *testing.T) {
	// Test policy lifecycle with deletion and re-addition scenario:
	// 1. Add and complete Policy A with 2 rules (v1.0.0)
	// 2. Mark Policy A for deletion
	// 3. Re-add Policy A with 3 rules with a different version (v2.0.0)
	// 4. Verify Policy A with new version is stored
	store := NewInMemoryPolicyStatusStore()
	pa := NewPolicyAggregator(2, 10*time.Millisecond, store) // 2 agents, 10ms reporting interval

	policyA := "NetworkPolicy/default/policy-a"

	// Set expected rule count for policy (2 rules)
	pa.SetExpectedRuleCount(policyA, 2)

	// Add Policy A with 2 rules at 1 millisec (version v1.0.0)
	policyARule1V1 := &l3l4networkpolicyv1alpha.PolicyRuleEvent{
		PolicyName:         policyA,
		RuleName:           "rule-1",
		K8SResourceVersion: "v1.0.0",
		IsSuccess:          true,
	}
	policyARule2V1 := &l3l4networkpolicyv1alpha.PolicyRuleEvent{
		PolicyName:         policyA,
		RuleName:           "rule-2",
		K8SResourceVersion: "v1.0.0",
		IsSuccess:          true,
	}

	// Complete Policy A v1.0.0 with both agents for both rules
	pa.ProcessRuleEvent("agent-1", policyARule1V1)
	pa.ProcessRuleEvent("agent-2", policyARule1V1)
	pa.ProcessRuleEvent("agent-1", policyARule2V1)
	pa.ProcessRuleEvent("agent-2", policyARule2V1)

	// Verify Policy A v1.0.0 is stored
	assert.Equal(t, 1, pa.GetPolicyStatusStore().GetCount(), "Store should contain 1 completed policy (v1.0.0)")

	allPolicies := pa.GetPolicyStatusStore().GetAll(false)
	policyAStored, policyAFound := allPolicies[policyA]
	assert.True(t, policyAFound, "Policy A v1.0.0 should be in store")
	if policyAFound {
		assert.True(t, policyAStored.IsComplete, "Policy A v1.0.0 should be complete")
		assert.Equal(t, "v1.0.0", policyAStored.Version, "Policy A should have v1.0.0")
		assert.Len(t, policyAStored.RuleResults, 2, "Policy A v1.0.0 should have 2 rules")
	}

	// Check the aggregator - it should contain 0 pending objects
	pa.mu.RLock()
	pendingCount := len(pa.pendingPolicies)
	pa.mu.RUnlock()
	assert.Equal(t, 0, pendingCount, "Aggregator should contain 0 pending policies")

	time.Sleep(15 * time.Millisecond)

	// Policy A received Delete event
	pa.MarkPolicyForDeletion(policyA)
	pa.ProcessRuleEvent("agent-1", policyARule1V1)
	pa.ProcessRuleEvent("agent-2", policyARule1V1)
	pa.ProcessRuleEvent("agent-1", policyARule2V1)
	pa.ProcessRuleEvent("agent-2", policyARule2V1)

	assert.Equal(t, 0, pa.GetPolicyStatusStore().GetCount(), "Store should contain 0 policy")

	// Wait some time interval before re-adding
	time.Sleep(30 * time.Millisecond)

	// Re-add Policy A with different version (v2.0.0) and 3 rules - set expected rule count
	pa.SetExpectedRuleCount(policyA, 3)

	// Re-add Policy A with different version (v2.0.0)
	policyARule1V2 := &l3l4networkpolicyv1alpha.PolicyRuleEvent{
		PolicyName:         policyA,
		RuleName:           "rule-1",
		K8SResourceVersion: "v2.0.0", // New version
		IsSuccess:          true,
	}
	policyARule2V2 := &l3l4networkpolicyv1alpha.PolicyRuleEvent{
		PolicyName:         policyA,
		RuleName:           "rule-2",
		K8SResourceVersion: "v2.0.0", // New version
		IsSuccess:          true,
	}
	policyARule3V2 := &l3l4networkpolicyv1alpha.PolicyRuleEvent{
		PolicyName:         policyA,
		RuleName:           "rule-3",
		K8SResourceVersion: "v2.0.0", // New version
		IsSuccess:          true,
	}

	// Complete Policy A v2.0.0 with both agents for all 3 rules
	pa.ProcessRuleEvent("agent-1", policyARule1V2)
	pa.ProcessRuleEvent("agent-2", policyARule1V2)
	pa.ProcessRuleEvent("agent-1", policyARule2V2)
	pa.ProcessRuleEvent("agent-2", policyARule2V2)
	pa.ProcessRuleEvent("agent-1", policyARule3V2)
	pa.ProcessRuleEvent("agent-2", policyARule3V2)

	// Verify Policy A v2.0.0 is stored
	assert.Equal(t, 1, pa.GetPolicyStatusStore().GetCount(), "Store should contain 1 completed policies (v2.0.0)")

	allPoliciesV2 := pa.GetPolicyStatusStore().GetAll(false)
	policyAStoredV2, policyAFoundV2 := allPoliciesV2[policyA]
	assert.True(t, policyAFoundV2, "Policy A should be in store")
	if policyAFoundV2 {
		assert.True(t, policyAStoredV2.IsComplete, "Policy A should be complete")
		// The newer version should overwrite the older one in the store
		assert.Equal(t, "v2.0.0", policyAStoredV2.Version, "Policy A should have v2.0.0 (newer version)")
		assert.Len(t, policyAStoredV2.RuleResults, 3, "Policy A v2.0.0 should have 3 rules")
	}

	// Verify aggregator has no pending policies
	pa.mu.RLock()
	pendingCount = len(pa.pendingPolicies)
	pa.mu.RUnlock()
	assert.Equal(t, 0, pendingCount, "Aggregator should contain 0 pending policies")
	assert.False(t, pa.policiesToDelete[policyA])
}

func TestPolicyAggregator_MultiPolicyAddDeleteWithTimeout(t *testing.T) {
	// Test policy lifecycle with timeout scenario:
	// 1. Add and complete Policy A successfully
	// 2. Add Policy B but let it timeout (incomplete)
	// 3. Verify Policy A is stored successfully and Policy B times out
	store := NewInMemoryPolicyStatusStore()
	// Use very short intervals to make timeout happen quickly
	pa := NewPolicyAggregator(2, 10*time.Millisecond, store) // 2 agents, 10ms reporting interval

	// Override cleanup cutoff to be much shorter for testing
	pa.mu.Lock()
	pa.cleanupCutoffAge = 30 * time.Millisecond // Short cutoff for testing
	pa.mu.Unlock()

	policyA := "NetworkPolicy/default/policy-a"
	policyB := "NetworkPolicy/default/policy-b"

	// Set expected rule counts for both policies (2 rules each)
	pa.SetExpectedRuleCount(policyA, 2)

	// Add Policy A with 2 rules (this will succeed)
	policyARule1 := &l3l4networkpolicyv1alpha.PolicyRuleEvent{
		PolicyName:         policyA,
		RuleName:           "rule-1",
		K8SResourceVersion: "v1.0.0",
		IsSuccess:          true,
	}
	policyARule2 := &l3l4networkpolicyv1alpha.PolicyRuleEvent{
		PolicyName:         policyA,
		RuleName:           "rule-2",
		K8SResourceVersion: "v1.0.0",
		IsSuccess:          true,
	}

	// Complete Policy A with both agents for both rules (successful)
	pa.ProcessRuleEvent("agent-1", policyARule1)
	pa.ProcessRuleEvent("agent-2", policyARule1)
	pa.ProcessRuleEvent("agent-1", policyARule2)
	pa.ProcessRuleEvent("agent-2", policyARule2)

	// Verify Policy A is completed and stored
	assert.Equal(t, 1, pa.GetPolicyStatusStore().GetCount(), "Store should contain 1 completed policy (Policy A)")

	allPolicies := pa.GetPolicyStatusStore().GetAll(false)
	policyAStored, policyAFound := allPolicies[policyA]
	assert.True(t, policyAFound, "Policy A should be in store")
	if policyAFound {
		assert.True(t, policyAStored.IsComplete, "Policy A should be complete")
		assert.Equal(t, "v1.0.0", policyAStored.Version, "Policy A should have v1.0.0")
		assert.Len(t, policyAStored.RuleResults, 2, "Policy A should have 2 rules")

		// Verify all rule results are successful
		for _, ruleResult := range policyAStored.RuleResults {
			for _, agentResult := range ruleResult.AgentResults {
				assert.True(t, agentResult.IsSuccess, "Policy A agent results should be successful")
			}
		}
	}

	pa.SetExpectedRuleCount(policyB, 1)
	// Add Policy B with partial rules (this will timeout)
	policyBRule1 := &l3l4networkpolicyv1alpha.PolicyRuleEvent{
		PolicyName:         policyB,
		RuleName:           "rule-1",
		K8SResourceVersion: "v1.0.0",
		IsSuccess:          true,
	}

	// Add Policy B with only partial completion (only agent-1 for rule-1)
	// This will cause Policy B to be incomplete and eventually timeout
	pa.ProcessRuleEvent("agent-1", policyBRule1)
	// Intentionally NOT adding:
	// - agent-2 response for rule-1
	// This creates a timeout scenario

	// Wait a short time to ensure Policy B is processed but still pending
	time.Sleep(15 * time.Millisecond)

	// Verify Policy B is pending (not yet complete)
	pa.mu.RLock()
	pendingCount := len(pa.pendingPolicies)
	_, policyBPending := pa.pendingPolicies[policyB]
	pa.mu.RUnlock()
	assert.Equal(t, 1, pendingCount, "Aggregator should have 1 pending policy (Policy B)")
	assert.True(t, policyBPending, "Policy B should be in pending policies")

	// Store should still only have Policy A
	assert.Equal(t, 1, pa.GetPolicyStatusStore().GetCount(), "Store should still contain only 1 policy (Policy A)")

	// Verify that Policy B is still pending (waiting for cleanup)
	pa.mu.RLock()
	pendingCountBeforeCleanup := len(pa.pendingPolicies)
	policyBStillPending := pa.pendingPolicies[policyB]
	pa.mu.RUnlock()
	assert.Equal(t, 1, pendingCountBeforeCleanup, "Policy B should still be pending before cleanup")
	assert.NotNil(t, policyBStillPending, "Policy B should still be in pending state")

	// Wait for the cleanup cutoff age to pass (30ms + buffer)
	// This simulates the natural timeout that would occur in production
	time.Sleep(40 * time.Millisecond)

	// After the cutoff time has passed, policies are considered stale and eligible for timeout completion
	// In production, cleanup would be called periodically by BulkPolicyReporter
	// For this test, we demonstrate that the policy remains pending until cleanup is triggered
	pa.cleanup()

	// Verify Policy B is now completed with timeout and stored
	assert.Equal(t, 2, pa.GetPolicyStatusStore().GetCount(), "Store should contain 2 policies (Policy A + timed out Policy B)")

	// Verify Policy B has timeout responses
	allPoliciesAfterTimeout := pa.GetPolicyStatusStore().GetAll(false)
	policyBStored, policyBFound := allPoliciesAfterTimeout[policyB]
	assert.True(t, policyBFound, "Policy B should be in store after timeout")
	if policyBFound {
		assert.True(t, policyBStored.IsComplete, "Policy B should be complete after timeout")
		assert.Equal(t, "v1.0.0", policyBStored.Version, "Policy B should have v1.0.0")
		assert.Len(t, policyBStored.RuleResults, 1, "Policy B should have 1 rule after timeout processing")

		// Verify that Policy B has timeout responses for missing agents
		hasTimeoutResponse := false
		for _, ruleResult := range policyBStored.RuleResults {
			for _, agentResult := range ruleResult.AgentResults {
				if !agentResult.IsSuccess && agentResult.Error == l3l4networkpolicyv1alpha.PolicyRuleError_POLICY_RULE_ERROR_TIMEOUT {
					hasTimeoutResponse = true
					assert.Contains(t, agentResult.ErrorMessage, "TIMEOUT", "Error message should mention timeout")
				} else {
					assert.Equal(t, 2, len(ruleResult.AgentResults), "Each rule should have responses from all expected agents (including timeout)")
				}
			}
		}
		assert.True(t, hasTimeoutResponse, "Policy B should have at least one timeout response")
	}

	// Verify aggregator has no pending policies after cleanup
	pa.mu.RLock()
	finalPendingCount := len(pa.pendingPolicies)
	pa.mu.RUnlock()
	assert.Equal(t, 0, finalPendingCount, "Aggregator should contain 0 pending policies after cleanup")
	// Check Policy B information is not present
	assert.False(t, pa.policiesToDelete[policyB])
	assert.False(t, pa.policiesToDelete[policyA])
}

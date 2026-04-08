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
	"testing"
	"time"

	l3l4networkpolicyv1alpha "github.com/isovalent/ipa/l3l4networkpolicy/v1alpha"
	"github.com/stretchr/testify/assert"
)

func TestNewInMemoryPolicyStatusStore(t *testing.T) {
	store := NewInMemoryPolicyStatusStore()

	assert.NotNil(t, store, "Store should not be nil")
	assert.NotNil(t, store.policyStatus, "Policy status map should be initialized")
	assert.Equal(t, 0, store.GetCount(), "Store should be empty initially")
	assert.True(t, store.lastUpdated.Before(time.Now().Add(time.Second)), "Last updated should be recent")
}

func TestPolicyStatusStore_Store(t *testing.T) {
	store := NewInMemoryPolicyStatusStore()

	// Create a sample policy result
	policyResult := &PolicyAggregationResult{
		PolicyName:    "NetworkPolicy/default/test-policy",
		Version:       "v1.0.0",
		Policy:        "test-policy",
		RuleResults:   make(map[string]*RuleAggregationResult),
		FirstSeen:     time.Now().Add(-5 * time.Minute),
		LastUpdated:   time.Now().Add(-2 * time.Minute),
		IsComplete:    true,
		ExpectedCount: 2,
	}

	// Add a rule result
	ruleResult := &RuleAggregationResult{
		RuleName:      "allow-http",
		PolicyName:    policyResult.PolicyName,
		ExpectedCount: 2,
		AgentResults:  make(map[string]*AgentRuleResult),
	}

	ruleResult.AgentResults["agent-1"] = &AgentRuleResult{
		AgentUID:     "agent-1",
		IsSuccess:    true,
		Error:        l3l4networkpolicyv1alpha.PolicyRuleError_POLICY_RULE_ERROR_UNSPECIFIED,
		ErrorMessage: "",
		ReceivedAt:   time.Now().Add(-1 * time.Minute),
	}

	policyResult.RuleResults["allow-http"] = ruleResult

	// Store the policy
	store.Store(policyResult)

	// Verify storage
	assert.Equal(t, 1, store.GetCount(), "Store should contain 1 policy")

	storedPolicies := store.GetAll(false)
	assert.Equal(t, 1, len(storedPolicies), "Should retrieve 1 policy")

	storedPolicy, exists := storedPolicies[policyResult.PolicyName]
	assert.True(t, exists, "Policy should exist in store")
	assert.Equal(t, policyResult.PolicyName, storedPolicy.PolicyName, "Policy name should match")
	assert.Equal(t, policyResult.Version, storedPolicy.Version, "Version should match")
	assert.Equal(t, policyResult.IsComplete, storedPolicy.IsComplete, "IsComplete should match")

	// Verify deep copy - changes to original should not affect stored policy
	policyResult.Version = "v2.0.0"
	assert.Equal(t, "v1.0.0", storedPolicy.Version, "Stored policy should be independent copy")
}

func TestPolicyStatusStore_StoreNil(t *testing.T) {
	store := NewInMemoryPolicyStatusStore()

	// Storing nil should not panic or change store state
	store.Store(nil)

	assert.Equal(t, 0, store.GetCount(), "Store should remain empty after storing nil")
}

func TestPolicyStatusStore_StoreUpdate(t *testing.T) {
	store := NewInMemoryPolicyStatusStore()
	firstSeenTime := time.Now().Add(-10 * time.Minute)

	// Store initial policy
	originalPolicy := &PolicyAggregationResult{
		PolicyName:    "NetworkPolicy/default/test-policy",
		Version:       "v1.0.0",
		Policy:        "test-policy",
		RuleResults:   make(map[string]*RuleAggregationResult),
		FirstSeen:     firstSeenTime,
		LastUpdated:   time.Now().Add(-5 * time.Minute),
		IsComplete:    true,
		ExpectedCount: 2,
	}

	store.Store(originalPolicy)

	// Store updated policy with same name but different version
	updatedPolicy := &PolicyAggregationResult{
		PolicyName:    "NetworkPolicy/default/test-policy", // Same name
		Version:       "v2.0.0",                            // Different version
		Policy:        "test-policy",
		RuleResults:   make(map[string]*RuleAggregationResult),
		FirstSeen:     time.Now(), // Different FirstSeen
		LastUpdated:   time.Now(),
		IsComplete:    true,
		ExpectedCount: 3,
	}

	store.Store(updatedPolicy)

	// Verify the store still has only 1 policy (updated, not added)
	assert.Equal(t, 1, store.GetCount(), "Store should still contain 1 policy after update")

	storedPolicies := store.GetAll(false)
	storedPolicy := storedPolicies[originalPolicy.PolicyName]

	// Verify update behavior
	assert.Equal(t, "v2.0.0", storedPolicy.Version, "Version should be updated")
	assert.Equal(t, 3, storedPolicy.ExpectedCount, "ExpectedCount should be updated")

	// Verify FirstSeen is preserved from original (not updated)
	assert.Equal(t, firstSeenTime.Truncate(time.Second), storedPolicy.FirstSeen.Truncate(time.Second),
		"FirstSeen should be preserved from original policy")
}

func TestPolicyStatusStore_GetAll(t *testing.T) {
	store := NewInMemoryPolicyStatusStore()

	// Test GetAll on empty store
	emptyResults := store.GetAll(false)
	assert.Equal(t, 0, len(emptyResults), "Empty store should return empty map")

	// Add multiple policies
	policy1 := &PolicyAggregationResult{
		PolicyName:  "NetworkPolicy/default/policy-1",
		Version:     "v1.0.0",
		RuleResults: make(map[string]*RuleAggregationResult),
		FirstSeen:   time.Now(),
		IsComplete:  true,
	}

	policy2 := &PolicyAggregationResult{
		PolicyName:  "NetworkPolicy/default/policy-2",
		Version:     "v2.0.0",
		RuleResults: make(map[string]*RuleAggregationResult),
		FirstSeen:   time.Now(),
		IsComplete:  false,
	}

	store.Store(policy1)
	store.Store(policy2)

	// Test GetAll without clearing
	results := store.GetAll(false)
	assert.Equal(t, 2, len(results), "Should return all policies")
	assert.Equal(t, 2, store.GetCount(), "Store should still contain policies after GetAll(false)")

	_, exists1 := results[policy1.PolicyName]
	_, exists2 := results[policy2.PolicyName]
	assert.True(t, exists1, "Policy 1 should be in results")
	assert.True(t, exists2, "Policy 2 should be in results")

	// Test GetAll with clearing
	resultsClearing := store.GetAll(true)
	assert.Equal(t, 2, len(resultsClearing), "Should return all policies before clearing")
	assert.Equal(t, 0, store.GetCount(), "Store should be empty after GetAll(true)")

	// Verify store is actually cleared
	afterClearResults := store.GetAll(false)
	assert.Equal(t, 0, len(afterClearResults), "Store should be empty after clearing")
}

func TestPolicyStatusStore_GetCount(t *testing.T) {
	store := NewInMemoryPolicyStatusStore()

	// Test empty store
	assert.Equal(t, 0, store.GetCount(), "Empty store should have count 0")

	// Add policies and verify count
	policy1 := &PolicyAggregationResult{
		PolicyName:  "NetworkPolicy/default/policy-1",
		Version:     "v1.0.0",
		RuleResults: make(map[string]*RuleAggregationResult),
		FirstSeen:   time.Now(),
		IsComplete:  true,
	}

	store.Store(policy1)
	assert.Equal(t, 1, store.GetCount(), "Store should have count 1 after storing 1 policy")

	policy2 := &PolicyAggregationResult{
		PolicyName:  "NetworkPolicy/default/policy-2",
		Version:     "v1.0.0",
		RuleResults: make(map[string]*RuleAggregationResult),
		FirstSeen:   time.Now(),
		IsComplete:  true,
	}

	store.Store(policy2)
	assert.Equal(t, 2, store.GetCount(), "Store should have count 2 after storing 2 policies")

	// Update existing policy should not change count
	updatedPolicy1 := &PolicyAggregationResult{
		PolicyName:  "NetworkPolicy/default/policy-1", // Same name as policy1
		Version:     "v2.0.0",
		RuleResults: make(map[string]*RuleAggregationResult),
		FirstSeen:   time.Now(),
		IsComplete:  true,
	}

	store.Store(updatedPolicy1)
	assert.Equal(t, 2, store.GetCount(), "Store count should remain 2 after updating existing policy")
}

func TestPolicyStatusStore_Clear(t *testing.T) {
	store := NewInMemoryPolicyStatusStore()

	// Add some policies
	policy1 := &PolicyAggregationResult{
		PolicyName:  "NetworkPolicy/default/policy-1",
		Version:     "v1.0.0",
		RuleResults: make(map[string]*RuleAggregationResult),
		FirstSeen:   time.Now(),
		IsComplete:  true,
	}

	policy2 := &PolicyAggregationResult{
		PolicyName:  "NetworkPolicy/default/policy-2",
		Version:     "v1.0.0",
		RuleResults: make(map[string]*RuleAggregationResult),
		FirstSeen:   time.Now(),
		IsComplete:  true,
	}

	store.Store(policy1)
	store.Store(policy2)
	assert.Equal(t, 2, store.GetCount(), "Store should have 2 policies before clear")

	// Clear the store
	store.Clear()

	// Verify store is cleared
	assert.Equal(t, 0, store.GetCount(), "Store should be empty after clear")
	results := store.GetAll(false)
	assert.Equal(t, 0, len(results), "GetAll should return empty map after clear")

	// Clearing empty store should not panic
	store.Clear()
	assert.Equal(t, 0, store.GetCount(), "Store should remain empty after clearing empty store")
}

func TestPolicyStatusStore_UpdateValidationError(t *testing.T) {
	store := NewInMemoryPolicyStatusStore()

	policyName := "NetworkPolicy/default/invalid-policy"
	errorMsg := "Policy validation failed: invalid selector"

	// Update validation error on non-existing policy
	store.UpdateValidationError(policyName, errorMsg)

	// Verify policy was created with validation error
	assert.Equal(t, 1, store.GetCount(), "Store should contain 1 policy after validation error")

	policies := store.GetAll(false)
	policy, exists := policies[policyName]
	assert.True(t, exists, "Policy with validation error should exist")
	assert.True(t, policy.IsComplete, "Policy with validation error should be marked complete")
	assert.Equal(t, "", policy.Version, "Policy with validation error should have empty version")

	// Verify validation error rule
	validationRule, hasValidationRule := policy.RuleResults["validation-error"]
	assert.True(t, hasValidationRule, "Policy should have validation-error rule")
	assert.Equal(t, "validation-error", validationRule.RuleName, "Validation rule name should be correct")

	// Verify validation error agent result
	validationAgent, hasValidationAgent := validationRule.AgentResults["validation"]
	assert.True(t, hasValidationAgent, "Validation rule should have validation agent result")
	assert.False(t, validationAgent.IsSuccess, "Validation agent result should be failure")
	assert.Equal(t, errorMsg, validationAgent.ErrorMessage, "Error message should match")
	assert.Equal(t, l3l4networkpolicyv1alpha.PolicyRuleError_POLICY_RULE_ERROR_FORMAT,
		validationAgent.Error, "Error type should be POLICY_RULE_ERROR_FORMAT")

	// Update validation error on existing policy
	newErrorMsg := "Policy validation failed: duplicate name"
	store.UpdateValidationError(policyName, newErrorMsg)

	// Verify policy was updated (not duplicated)
	assert.Equal(t, 1, store.GetCount(), "Store should still contain 1 policy after validation error update")

	updatedPolicies := store.GetAll(false)
	updatedPolicy := updatedPolicies[policyName]
	updatedValidationRule := updatedPolicy.RuleResults["validation-error"]
	updatedValidationAgent := updatedValidationRule.AgentResults["validation"]
	assert.Equal(t, newErrorMsg, updatedValidationAgent.ErrorMessage, "Error message should be updated")
}

func TestPolicyStatusStore_UpdateVRFError(t *testing.T) {
	store := NewInMemoryPolicyStatusStore()

	policyName := "NetworkPolicy/default/vrf-policy"
	errorMsg := "VRF configuration error: invalid VRF ID"

	// Update VRF error on non-existing policy
	store.UpdateVRFError(policyName, errorMsg)

	// Verify policy was created with VRF error
	assert.Equal(t, 1, store.GetCount(), "Store should contain 1 policy after VRF error")

	policies := store.GetAll(false)
	policy, exists := policies[policyName]
	assert.True(t, exists, "Policy with VRF error should exist")
	assert.True(t, policy.IsComplete, "Policy with VRF error should be marked complete")

	// Verify VRF error rule
	vrfRule, hasVRFRule := policy.RuleResults["vrf-error"]
	assert.True(t, hasVRFRule, "Policy should have vrf-error rule")
	assert.Equal(t, "vrf-error", vrfRule.RuleName, "VRF rule name should be correct")

	// Verify VRF error agent result
	vrfAgent, hasVRFAgent := vrfRule.AgentResults["vrf"]
	assert.True(t, hasVRFAgent, "VRF rule should have vrf agent result")
	assert.False(t, vrfAgent.IsSuccess, "VRF agent result should be failure")
	assert.Equal(t, errorMsg, vrfAgent.ErrorMessage, "Error message should match")

	// Update VRF error on existing policy
	newErrorMsg := "VRF configuration error: VRF not found"
	store.UpdateVRFError(policyName, newErrorMsg)

	// Verify policy was updated (not duplicated)
	assert.Equal(t, 1, store.GetCount(), "Store should still contain 1 policy after VRF error update")

	updatedPolicies := store.GetAll(false)
	updatedPolicy := updatedPolicies[policyName]
	updatedVRFRule := updatedPolicy.RuleResults["vrf-error"]
	updatedVRFAgent := updatedVRFRule.AgentResults["vrf"]
	assert.Equal(t, newErrorMsg, updatedVRFAgent.ErrorMessage, "Error message should be updated")
}

func TestPolicyStatusStore_HasPolicy(t *testing.T) {
	store := NewInMemoryPolicyStatusStore()

	policyName := "NetworkPolicy/default/test-policy"

	// Test non-existing policy
	assert.False(t, store.HasPolicy(policyName), "Non-existing policy should return false")

	// Add policy
	policy := &PolicyAggregationResult{
		PolicyName:  policyName,
		Version:     "v1.0.0",
		RuleResults: make(map[string]*RuleAggregationResult),
		FirstSeen:   time.Now(),
		IsComplete:  true,
	}

	store.Store(policy)

	// Test existing policy
	assert.True(t, store.HasPolicy(policyName), "Existing policy should return true")

	// Test different policy name
	assert.False(t, store.HasPolicy("NetworkPolicy/default/other-policy"),
		"Different policy name should return false")
}

func TestPolicyStatusStore_GetPolicyVersion(t *testing.T) {
	store := NewInMemoryPolicyStatusStore()

	policyName := "NetworkPolicy/default/test-policy"

	// Test non-existing policy
	assert.Equal(t, "", store.GetPolicyVersion(policyName),
		"Non-existing policy should return empty string")

	// Add policy with version
	policy := &PolicyAggregationResult{
		PolicyName:  policyName,
		Version:     "v1.2.3",
		RuleResults: make(map[string]*RuleAggregationResult),
		FirstSeen:   time.Now(),
		IsComplete:  true,
	}

	store.Store(policy)

	// Test existing policy
	assert.Equal(t, "v1.2.3", store.GetPolicyVersion(policyName),
		"Should return correct policy version")

	// Test different policy name
	assert.Equal(t, "", store.GetPolicyVersion("NetworkPolicy/default/other-policy"),
		"Different policy name should return empty string")

	// Test policy with empty version
	policyEmptyVersion := &PolicyAggregationResult{
		PolicyName:  "NetworkPolicy/default/no-version-policy",
		Version:     "",
		RuleResults: make(map[string]*RuleAggregationResult),
		FirstSeen:   time.Now(),
		IsComplete:  true,
	}

	store.Store(policyEmptyVersion)
	assert.Equal(t, "", store.GetPolicyVersion("NetworkPolicy/default/no-version-policy"),
		"Policy with empty version should return empty string")
}

func TestPolicyStatusStore_Delete(t *testing.T) {
	store := NewInMemoryPolicyStatusStore()

	policyName := "NetworkPolicy/default/test-policy"

	// Test deleting non-existing policy
	deleted := store.Delete(policyName)
	assert.False(t, deleted, "Deleting non-existing policy should return false")
	assert.Equal(t, 0, store.GetCount(), "Store count should remain 0")

	// Add policy
	policy := &PolicyAggregationResult{
		PolicyName:  policyName,
		Version:     "v1.0.0",
		RuleResults: make(map[string]*RuleAggregationResult),
		FirstSeen:   time.Now(),
		IsComplete:  true,
	}

	store.Store(policy)
	assert.Equal(t, 1, store.GetCount(), "Store should contain 1 policy")

	// Test deleting existing policy
	deleted = store.Delete(policyName)
	assert.True(t, deleted, "Deleting existing policy should return true")
	assert.Equal(t, 0, store.GetCount(), "Store should be empty after deletion")
	assert.False(t, store.HasPolicy(policyName), "Policy should not exist after deletion")

	// Test deleting already deleted policy
	deletedAgain := store.Delete(policyName)
	assert.False(t, deletedAgain, "Deleting already deleted policy should return false")
}

func TestPolicyStatusStore_DeepCopy(t *testing.T) {
	store := NewInMemoryPolicyStatusStore()

	// Create complex policy with nested rule results
	policyResult := &PolicyAggregationResult{
		PolicyName:    "NetworkPolicy/default/complex-policy",
		Version:       "v1.0.0",
		Policy:        "complex-policy",
		RuleResults:   make(map[string]*RuleAggregationResult),
		FirstSeen:     time.Now().Add(-10 * time.Minute),
		LastUpdated:   time.Now().Add(-5 * time.Minute),
		IsComplete:    true,
		ExpectedCount: 2,
	}

	// Add rule with multiple agents
	ruleResult := &RuleAggregationResult{
		RuleName:      "allow-http",
		PolicyName:    policyResult.PolicyName,
		ExpectedCount: 2,
		AgentResults:  make(map[string]*AgentRuleResult),
	}

	ruleResult.AgentResults["agent-1"] = &AgentRuleResult{
		AgentUID:     "agent-1",
		IsSuccess:    true,
		Error:        l3l4networkpolicyv1alpha.PolicyRuleError_POLICY_RULE_ERROR_UNSPECIFIED,
		ErrorMessage: "",
		ReceivedAt:   time.Now().Add(-3 * time.Minute),
	}

	ruleResult.AgentResults["agent-2"] = &AgentRuleResult{
		AgentUID:     "agent-2",
		IsSuccess:    false,
		Error:        l3l4networkpolicyv1alpha.PolicyRuleError_POLICY_RULE_ERROR_TIMEOUT,
		ErrorMessage: "Agent timeout",
		ReceivedAt:   time.Now().Add(-2 * time.Minute),
	}

	policyResult.RuleResults["allow-http"] = ruleResult

	// Store policy
	store.Store(policyResult)

	// Get stored policy
	storedPolicies := store.GetAll(false)
	storedPolicy := storedPolicies[policyResult.PolicyName]

	// Verify deep copy by modifying original structures
	originalAgentResult := policyResult.RuleResults["allow-http"].AgentResults["agent-1"]
	originalAgentResult.IsSuccess = false
	originalAgentResult.ErrorMessage = "Modified original"

	policyResult.Version = "v2.0.0"
	policyResult.RuleResults["allow-http"].RuleName = "modified-rule"

	// Stored policy should be unaffected
	storedAgentResult := storedPolicy.RuleResults["allow-http"].AgentResults["agent-1"]
	assert.True(t, storedAgentResult.IsSuccess, "Stored agent result should be unaffected by original modification")
	assert.Equal(t, "", storedAgentResult.ErrorMessage, "Stored error message should be unaffected")
	assert.Equal(t, "v1.0.0", storedPolicy.Version, "Stored version should be unaffected")
	assert.Equal(t, "allow-http", storedPolicy.RuleResults["allow-http"].RuleName, "Stored rule name should be unaffected")
}

func TestPolicyStatusStore_ConcurrentAccess(t *testing.T) {
	store := NewInMemoryPolicyStatusStore()

	// Test basic concurrent safety with Store and GetCount
	done := make(chan bool, 2)

	// Goroutine 1: Store policies
	go func() {
		for i := 0; i < 100; i++ {
			policy := &PolicyAggregationResult{
				PolicyName:  "NetworkPolicy/default/policy-" + string(rune(i)),
				Version:     "v1.0.0",
				RuleResults: make(map[string]*RuleAggregationResult),
				FirstSeen:   time.Now(),
				IsComplete:  true,
			}
			store.Store(policy)
		}
		done <- true
	}()

	// Goroutine 2: Read count and check policies
	go func() {
		for i := 0; i < 100; i++ {
			count := store.GetCount()
			assert.True(t, count >= 0, "Count should never be negative")
			policies := store.GetAll(false)
			assert.True(t, len(policies) >= 0, "Policy map length should never be negative")
		}
		done <- true
	}()

	// Wait for both goroutines to complete
	<-done
	<-done

	// Final verification
	finalCount := store.GetCount()
	assert.Equal(t, 100, finalCount, "Should have stored all 100 policies")
}

func TestPolicyStatusStore_ComplexScenario(t *testing.T) {
	store := NewInMemoryPolicyStatusStore()

	// Scenario: Store policy, update it, add validation error, then clear
	policyName := "NetworkPolicy/default/complex-scenario"

	// 1. Store initial policy
	initialPolicy := &PolicyAggregationResult{
		PolicyName:  policyName,
		Version:     "v1.0.0",
		RuleResults: make(map[string]*RuleAggregationResult),
		FirstSeen:   time.Now().Add(-20 * time.Minute),
		IsComplete:  true,
	}

	store.Store(initialPolicy)
	assert.Equal(t, 1, store.GetCount(), "Should have 1 policy after initial store")
	assert.Equal(t, "v1.0.0", store.GetPolicyVersion(policyName), "Should have correct initial version")

	// 2. Update policy version
	updatedPolicy := &PolicyAggregationResult{
		PolicyName:  policyName, // Same name
		Version:     "v2.0.0",   // Different version
		RuleResults: make(map[string]*RuleAggregationResult),
		FirstSeen:   time.Now().Add(-10 * time.Minute), // This should be ignored (FirstSeen preserved)
		IsComplete:  true,                              // Different completion status
	}

	store.Store(updatedPolicy)
	assert.Equal(t, 1, store.GetCount(), "Should still have 1 policy after update")
	assert.Equal(t, "v2.0.0", store.GetPolicyVersion(policyName), "Should have updated version")

	storedPolicies := store.GetAll(false)
	storedPolicy := storedPolicies[policyName]
	assert.True(t, storedPolicy.IsComplete, "Should have updated completion status")
	assert.Equal(t, initialPolicy.FirstSeen.Truncate(time.Second),
		storedPolicy.FirstSeen.Truncate(time.Second), "FirstSeen should be preserved from original")

	// 3. Add validation error (should not overwrite existing policy completely)
	store.UpdateValidationError(policyName, "Validation failed")

	assert.Equal(t, 1, store.GetCount(), "Should still have 1 policy after validation error")

	finalPolicies := store.GetAll(false)
	finalPolicy := finalPolicies[policyName]
	assert.Equal(t, "v2.0.0", finalPolicy.Version, "Version should be preserved after validation error")
	assert.True(t, finalPolicy.IsComplete, "Should preserve existing completion status after validation error")
	_, hasValidationError := finalPolicy.RuleResults["validation-error"]
	assert.True(t, hasValidationError, "POLICY_RULE_ERROR_FORMAT")

	// 4. Clear store
	store.Clear()
	assert.Equal(t, 0, store.GetCount(), "Should be empty after clear")
	assert.False(t, store.HasPolicy(policyName), "Policy should not exist after clear")
	assert.Equal(t, "", store.GetPolicyVersion(policyName), "Version should be empty after clear")
}

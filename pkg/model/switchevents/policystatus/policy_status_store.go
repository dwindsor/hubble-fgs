// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

// PolicyStatusStore provides persistent in-memory storage for policy status results
// This enables periodic state-based reporting where the same policies are reported every interval
// with their current status, rather than clearing after each report

package policystatus

import (
	"sync"
	"time"

	"github.com/cilium/tetragon/pkg/logger"
	l3l4networkpolicyv1alpha "github.com/isovalent/ipa/l3l4networkpolicy/v1alpha"
)

// PolicyStatusStore interface defines the contract for policy status storage
type PolicyStatusStore interface {
	// Store saves the complete policy result
	Store(policyResult *PolicyAggregationResult)

	// GetAll returns all stored policy results and optionally clears the store
	GetAll(clearAfterRead bool) map[string]*PolicyAggregationResult

	// GetCount returns the current number of stored policies
	GetCount() int

	// Clear removes all stored policy results
	Clear()

	// UpdateValidationError updates policy with validation error
	UpdateValidationError(policyName, errorMsg string)

	// UpdateVRFError updates policy with VRF error
	UpdateVRFError(policyName, errorMsg string)

	// Delete removes a specific policy from the store
	Delete(policyName string) bool
}

// InMemoryPolicyStatusStore implements PolicyStatusStore with in-memory storage
type InMemoryPolicyStatusStore struct {
	mu           sync.RWMutex
	policyStatus map[string]*PolicyAggregationResult // policyName -> result
	lastUpdated  time.Time
}

// NewInMemoryPolicyStatusStore creates a new in-memory policy status store
func NewInMemoryPolicyStatusStore() *InMemoryPolicyStatusStore {
	return &InMemoryPolicyStatusStore{
		policyStatus: make(map[string]*PolicyAggregationResult),
		lastUpdated:  time.Now(),
	}
}

// Store saves the complete policy result
func (s *InMemoryPolicyStatusStore) Store(policyResult *PolicyAggregationResult) {
	if policyResult == nil {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if this is an update to an existing policy
	existingResult, exists := s.policyStatus[policyResult.PolicyName]
	var firstSeenTime time.Time
	var isUpdate bool

	if exists {
		// This is a policy update - preserve the original FirstSeen timestamp
		firstSeenTime = existingResult.FirstSeen
		isUpdate = true
	} else {
		// This is a new policy
		firstSeenTime = policyResult.FirstSeen
		isUpdate = false
	}

	// Create a copy to avoid concurrent modification issues
	storedResult := &PolicyAggregationResult{
		PolicyName:    policyResult.PolicyName,
		Version:       policyResult.Version,
		Policy:        policyResult.Policy,
		RuleResults:   make(map[string]*RuleAggregationResult),
		FirstSeen:     firstSeenTime, // Preserve original FirstSeen for updates
		LastUpdated:   time.Now(),
		IsComplete:    policyResult.IsComplete,
		ExpectedCount: policyResult.ExpectedCount,
	}

	// Deep copy rule results
	for ruleName, ruleResult := range policyResult.RuleResults {
		copiedRuleResult := &RuleAggregationResult{
			RuleName:      ruleResult.RuleName,
			PolicyName:    ruleResult.PolicyName,
			ExpectedCount: ruleResult.ExpectedCount,
			AgentResults:  make(map[string]*AgentRuleResult),
		}

		// Deep copy agent results
		for agentUID, agentResult := range ruleResult.AgentResults {
			copiedRuleResult.AgentResults[agentUID] = &AgentRuleResult{
				AgentUID:     agentResult.AgentUID,
				IsSuccess:    agentResult.IsSuccess,
				Error:        agentResult.Error,
				ErrorMessage: agentResult.ErrorMessage,
				ReceivedAt:   agentResult.ReceivedAt,
			}
		}

		storedResult.RuleResults[ruleName] = copiedRuleResult
	}

	s.policyStatus[policyResult.PolicyName] = storedResult
	s.lastUpdated = time.Now()

	if isUpdate {
		logger.GetLogger().Debug("updated existing policy result in policy status store",
			"policyName", policyResult.PolicyName,
			"version", policyResult.Version,
			"isComplete", policyResult.IsComplete,
			"ruleCount", len(policyResult.RuleResults),
			"totalStored", len(s.policyStatus))
	} else {
		logger.GetLogger().Debug("stored new policy result in policy status store",
			"policyName", policyResult.PolicyName,
			"version", policyResult.Version,
			"isComplete", policyResult.IsComplete,
			"ruleCount", len(policyResult.RuleResults),
			"totalStored", len(s.policyStatus))
	}
}

// GetAll returns all stored policy results and optionally clears the store
func (s *InMemoryPolicyStatusStore) GetAll(clearAfterRead bool) map[string]*PolicyAggregationResult {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.policyStatus) == 0 {
		return make(map[string]*PolicyAggregationResult)
	}

	// Create a copy of all stored results
	results := make(map[string]*PolicyAggregationResult, len(s.policyStatus))
	for policyName, policyResult := range s.policyStatus {
		results[policyName] = policyResult
	}

	logger.GetLogger().Debug("retrieved all policy results from store",
		"count", len(results),
		"clearAfterRead", clearAfterRead)

	if clearAfterRead {
		s.policyStatus = make(map[string]*PolicyAggregationResult)
	} else {
		logger.GetLogger().Debug("preserved policy status store for state-based reporting")
	}

	return results
}

// GetCount returns the current number of stored policies
func (s *InMemoryPolicyStatusStore) GetCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.policyStatus)
}

// Clear removes all stored policy results
func (s *InMemoryPolicyStatusStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.policyStatus = make(map[string]*PolicyAggregationResult)
}

// UpdateValidationError updates policy with validation error
func (s *InMemoryPolicyStatusStore) UpdateValidationError(policyName, errorMsg string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Extract policy name from full path (kind/namespace/name -> name)
	policyNameOnly := extractPolicyNameFromPath(policyName)

	// Create or update policy result with validation error
	policyResult, exists := s.policyStatus[policyName]
	if !exists {
		policyResult = &PolicyAggregationResult{
			PolicyName:  policyName,     // Full path: kind/namespace/name
			Version:     "",             // No version for validation errors
			Policy:      policyNameOnly, // Just the policy name part
			RuleResults: make(map[string]*RuleAggregationResult),
			FirstSeen:   time.Now(),
			IsComplete:  true, // Validation errors are immediately complete
		}
		s.policyStatus[policyName] = policyResult
	}

	policyResult.LastUpdated = time.Now()
	policyResult.IsComplete = true // Mark as complete since validation errors are final

	// Add validation error as a special rule result
	validationRuleResult := &RuleAggregationResult{
		RuleName:     "validation-error",
		PolicyName:   policyName,
		AgentResults: make(map[string]*AgentRuleResult),
	}

	validationRuleResult.AgentResults["validation"] = &AgentRuleResult{
		AgentUID:     "validation",
		IsSuccess:    false,
		Error:        l3l4networkpolicyv1alpha.PolicyRuleError_POLICY_RULE_ERROR_FORMAT, // Use format error for validation
		ErrorMessage: errorMsg,
		ReceivedAt:   time.Now(),
	}

	policyResult.RuleResults["validation-error"] = validationRuleResult
	s.lastUpdated = time.Now()

	logger.GetLogger().Debug("updated policy with validation error",
		"policyName", policyName,
		"errorMsg", errorMsg)
}

// UpdateVRFError updates policy with VRF error
func (s *InMemoryPolicyStatusStore) UpdateVRFError(policyName, errorMsg string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Create or update policy result with VRF error
	policyResult, exists := s.policyStatus[policyName]
	if !exists {
		policyResult = &PolicyAggregationResult{
			PolicyName:  policyName,
			RuleResults: make(map[string]*RuleAggregationResult),
			FirstSeen:   time.Now(),
			IsComplete:  true, // VRF errors are immediately complete
		}
		s.policyStatus[policyName] = policyResult
	}

	policyResult.LastUpdated = time.Now()

	// Add VRF error as a special rule result
	vrfRuleResult := &RuleAggregationResult{
		RuleName:     "vrf-error",
		PolicyName:   policyName,
		AgentResults: make(map[string]*AgentRuleResult),
	}

	vrfRuleResult.AgentResults["vrf"] = &AgentRuleResult{
		AgentUID:     "vrf",
		IsSuccess:    false,
		ErrorMessage: errorMsg,
		ReceivedAt:   time.Now(),
	}

	policyResult.RuleResults["vrf-error"] = vrfRuleResult
	s.lastUpdated = time.Now()

	logger.GetLogger().Info("updated policy with VRF error",
		"policyName", policyName,
		"errorMsg", errorMsg)
}

// HasPolicy checks if a policy exists in the store
func (s *InMemoryPolicyStatusStore) HasPolicy(policyName string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, exists := s.policyStatus[policyName]
	return exists
}

// GetPolicyVersion returns the version of a stored policy, or empty string if not found
func (s *InMemoryPolicyStatusStore) GetPolicyVersion(policyName string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if policyResult, exists := s.policyStatus[policyName]; exists {
		return policyResult.Version
	}
	return ""
}

// Delete removes a specific policy from the store
func (s *InMemoryPolicyStatusStore) Delete(policyName string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.policyStatus[policyName]; exists {
		delete(s.policyStatus, policyName)
		logger.GetLogger().Info("deleted policy from store",
			"policyName", policyName)
		return true
	}
	logger.GetLogger().Info("attempted to delete policy from store but it was not found",
		"policyName", policyName)
	return false
}

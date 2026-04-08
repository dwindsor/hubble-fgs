// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

// BulkPolicyReporter handles periodic state-based reporting of policy status to timescape
// Every 15 minutes, it reports the current status of ALL policies (not just changes)
// Policies persist in the store and are reported with their latest status each interval

package policystatus

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/cilium/tetragon/pkg/logger"
	"google.golang.org/protobuf/types/known/timestamppb"

	l3l4networkpolicyv1alpha "github.com/isovalent/ipa/l3l4networkpolicy/v1alpha"
	v1alpha "github.com/isovalent/ipa/system_status/v1alpha"

	ss "github.com/isovalent/hubble-fgs/pkg/model/switchevents/systemstatus"
	"github.com/isovalent/hubble-fgs/pkg/timescape/types"
)

const (
	// MaxPoliciesPerBatch is the maximum number of policies to include in a single SystemStatusEvent batch
	MaxPoliciesPerBatch = 10000
)

// BulkPolicyReporter handles periodic bulk policy status reporting
type BulkPolicyReporter struct {
	mu                sync.RWMutex
	store             PolicyStatusStore
	reportingInterval time.Duration
	timescapeClient   types.Client
	dataProvider      PolicyStatusDataProvider // Add data provider for serial number
	policyAggregator  *PolicyAggregator
	running           bool
	stopCh            chan struct{}
	wg                sync.WaitGroup
	lastReportTime    time.Time
	totalPolicyCount  int64
}

// NewBulkPolicyReporter creates a new bulk policy status reporter
func NewBulkPolicyReporter(store PolicyStatusStore, timescapeClient types.Client, dataProvider PolicyStatusDataProvider, policyAggregator *PolicyAggregator, reportingInterval time.Duration) *BulkPolicyReporter {
	if reportingInterval <= 0 {
		reportingInterval = types.DefaultPolicyStatusReportingInterval
	}

	return &BulkPolicyReporter{
		store:             store,
		reportingInterval: reportingInterval,
		timescapeClient:   timescapeClient,
		dataProvider:      dataProvider,
		policyAggregator:  policyAggregator,
		stopCh:            make(chan struct{}),
		lastReportTime:    time.Now(),
	}
}

// Start begins the periodic bulk reporting process
func (r *BulkPolicyReporter) Start(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.running {
		logger.GetLogger().Info("bulk policy reporter already running")
		return nil
	}

	r.running = true

	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		r.reportingLoop(ctx)
	}()

	return nil
}

// Stop stops the periodic bulk reporting
func (r *BulkPolicyReporter) Stop(ctx context.Context) {
	r.mu.Lock()
	if !r.running {
		r.mu.Unlock()
		return
	}
	r.running = false
	r.mu.Unlock()

	close(r.stopCh)
	r.wg.Wait()

	// Send final report with any remaining policies
	r.sendBulkReport(ctx)

	logger.GetLogger().Info("bulk policy reporter stopped")
}

// reportingLoop runs the periodic bulk reporting
func (r *BulkPolicyReporter) reportingLoop(ctx context.Context) {
	ticker := time.NewTicker(r.reportingInterval)
	defer ticker.Stop()

	logger.GetLogger().Info("started bulk policy reporting loop",
		"interval", r.reportingInterval)

	for {
		select {
		case <-ctx.Done():
			logger.GetLogger().Info("bulk policy reporter context cancelled")
			return
		case <-r.stopCh:
			logger.GetLogger().Info("bulk policy reporter stop signal received")
			return
		case <-ticker.C:
			r.sendBulkReport(ctx)
		}
	}
}

// sendBulkReport sends all stored policies to timescape in bulk
func (r *BulkPolicyReporter) sendBulkReport(ctx context.Context) {
	// Call cleanup to detect any policies that have timed out
	if r.policyAggregator != nil {
		r.policyAggregator.cleanup()
	}

	// Get all stored policies WITHOUT clearing the store (state-based reporting)
	storedPolicies := r.store.GetAll(false)

	if len(storedPolicies) == 0 {
		logger.GetLogger().Debug("no policies to report in bulk")
		return
	}

	// Convert stored policies to PolicyAggregationResult array for batching
	policyResults := make([]*PolicyAggregationResult, 0, len(storedPolicies))
	for _, policyResult := range storedPolicies {
		policyResults = append(policyResults, policyResult)
	}

	// Send in batches of up to 10,000 policies each
	for i := 0; i < len(policyResults); i += MaxPoliciesPerBatch {
		end := i + MaxPoliciesPerBatch
		if end > len(policyResults) {
			end = len(policyResults)
		}

		batch := policyResults[i:end]
		r.sendPolicyBatch(ctx, batch)
	}

	r.mu.Lock()
	r.lastReportTime = time.Now()
	r.totalPolicyCount += int64(len(policyResults))
	r.mu.Unlock()

	logger.GetLogger().Debug("sent bulk policy status report",
		"policyCount", len(storedPolicies))
}

// sendPolicyBatch sends a batch of policies to timescape
func (r *BulkPolicyReporter) sendPolicyBatch(ctx context.Context, policies []*PolicyAggregationResult) {
	if len(policies) == 0 {
		return
	}

	// Create a single SystemStatusEvent with all policies in the batch
	statusEvent := r.createBatchSystemStatusEvent(policies)
	if statusEvent != nil {
		if r.timescapeClient != nil {
			errorCode := r.timescapeClient.Send(ctx, statusEvent, types.PriorityLow)
			if errorCode == types.ErrCodeQueueBusy {
				logger.GetLogger().Info("timescape: queue full, waiting before retry for policy event")

				// Wait and retry once
				select {
				case <-ctx.Done():
					logger.GetLogger().Info("timescape: context cancelled while waiting to retry policy event")
					return
				case <-r.stopCh:
					logger.GetLogger().Debug("timescape: policy reporter handler stopped while waiting to retry policy event")
					return
				case <-time.After(3 * time.Second):
					errorCode = r.timescapeClient.Send(ctx, statusEvent, types.PriorityLow)
				}
			}
			if errorCode != types.ErrCodeSuccess {
				logger.GetLogger().Error("failed to send bulk policy status event",
					"policyCount", len(policies), "errorCode", errorCode)
			} else {
				logger.GetLogger().Debug("successfully sent bulk policy status event",
					"policyCount", len(policies))
			}
		} else {
			logger.GetLogger().Error("timescape: queue not available to send policy reporting")
		}
	}
}

// createBatchSystemStatusEvent creates a single SystemStatusEvent with multiple policies
func (r *BulkPolicyReporter) createBatchSystemStatusEvent(policies []*PolicyAggregationResult) *v1alpha.SystemStatusEvent {
	if len(policies) == 0 {
		return nil
	}

	// Get node name from data provider (lowercased like in previous design)
	serialNumber := "unknown"
	if r.dataProvider.GetSerialNumber != nil {
		serialNumber = strings.ToLower(r.dataProvider.GetSerialNumber())
	}

	// Create policy statuses for all policies in the batch
	var policyStatuses []*v1alpha.PolicyStatus

	for _, policy := range policies {
		if policy == nil {
			continue
		}

		// Extract namespace from PolicyName (kind/namespace/name) - same as previous design
		namespace := r.extractNamespaceFromPolicyName(policy.PolicyName)

		// Use PolicyGroupId from policyAggregator if available, otherwise use default value
		policyNameForTimescape := r.policyAggregator.GetPolicyGroupId(policy.PolicyName)

		// Aggregate all failures across all rules in this policy - same logic as previous design
		var failingConditions []*v1alpha.FailingCondition

		// Check overall policy state before processing rule errors
		policyIsComplete := policy.IsComplete
		hasAnyRuleFailure := false

		// Same failure condition logic as previous design with rule indexing
		ruleIndex := 1
		for ruleName, ruleResult := range policy.RuleResults {
			for agentUID, agentResult := range ruleResult.AgentResults {
				if !agentResult.IsSuccess {
					hasAnyRuleFailure = true

					// Override conditionId for validation errors
					conditionId := agentResult.Error.String()
					if ruleName == "validation-error" {
						conditionId = "POLICY_VALIDATION_ERROR"
					}

					failingConditions = append(failingConditions, &v1alpha.FailingCondition{
						ConditionId: conditionId,
						Severity:    r.convertErrorToSeverity(agentResult.Error),
						Message:     fmt.Sprintf("Rule %d, Agent %s: %s", ruleIndex, agentUID, r.getErrorMessage(agentResult)),
					})
				}
			}
			ruleIndex++
		}

		// If some agents didn't respond for any rule, add timeout conditions - same as previous design
		hasTimeoutFailures := false
		var policyIsSuccess bool
		if len(policy.RuleResults) > 1 {
			// Check if all rules have the same timeout pattern
			failingRuleCount := 0
			for _, ruleResult := range policy.RuleResults {
				if len(ruleResult.AgentResults) < policy.ExpectedCount {
					failingRuleCount++
				}
			}
			if failingRuleCount > 0 {
				hasTimeoutFailures = true
				failingConditions = append(failingConditions, &v1alpha.FailingCondition{
					ConditionId: "TIMEOUT_AGENT_RESPONSES",
					Severity:    v1alpha.Severity_SEVERITY_MAJOR,
					Message: fmt.Sprintf("%d rules: Expected %d agents. Did not receive responses from some agents",
						failingRuleCount, policy.ExpectedCount),
				})
			}
		}

		// Update overall policy success state considering timeout failures
		policyIsSuccess = policyIsComplete && !hasAnyRuleFailure && !hasTimeoutFailures

		// Create policy status exactly like previous design
		policyStatus := &v1alpha.PolicyStatus{
			Type:              v1alpha.PolicyType_POLICY_TYPE_SMARTSWITCH_NETWORK_POLICY,
			Id:                policy.PolicyName, // PolicyName (kind/namespace/name)
			Name:              policy.Policy,     // Policy name
			Namespace:         namespace,
			Version:           policy.Version,
			FailingConditions: failingConditions,
			ExtraData: map[string]string{
				"PolicyGroupId": policyNameForTimescape,
			},
		}

		policyStatuses = append(policyStatuses, policyStatus)

		logger.GetLogger().Debug("policy status evaluation for batch timescape",
			"policyName", policy.PolicyName,
			"isComplete", policyIsComplete,
			"hasRuleFailures", hasAnyRuleFailure,
			"hasTimeoutFailures", hasTimeoutFailures,
			"overallSuccess", policyIsSuccess,
			"failingConditionsCount", len(failingConditions))
	}

	// Create the PolicyStatusUpdate with all policies in the batch
	policyUpdate := &v1alpha.PolicyStatusUpdate{
		ClusterName: ss.ClusterName, // "smartswitch" - same as systemstatus.ClusterName
		NodeName:    serialNumber,   // same as previous design
		Statuses:    policyStatuses,
	}

	// Create the SystemStatusEvent
	statusEvent := &v1alpha.SystemStatusEvent{
		Time: timestamppb.New(time.Now()),
		Event: &v1alpha.SystemStatusEvent_Policy{
			Policy: policyUpdate,
		},
	}

	// Debug log the complete SystemStatusEvent being created
	logger.GetLogger().Debug("Batch SystemStatusEvent created for timescape",
		"policyCount", len(policyStatuses),
		"clusterName", policyUpdate.ClusterName,
		"nodeName", policyUpdate.NodeName,
		"timestamp", statusEvent.Time.String())

	return statusEvent
}

// extractNamespaceFromPolicyName extracts the namespace from a policy name in format "kind/namespace/name"
func (r *BulkPolicyReporter) extractNamespaceFromPolicyName(policyName string) string {
	parts := strings.Split(policyName, "/")
	if len(parts) >= 3 {
		return parts[1]
	}
	return ""
}

// convertErrorToSeverity maps PolicyRuleError to Severity - same as policy_handler.go
func (r *BulkPolicyReporter) convertErrorToSeverity(err l3l4networkpolicyv1alpha.PolicyRuleError) v1alpha.Severity {
	switch err {
	case l3l4networkpolicyv1alpha.PolicyRuleError_POLICY_RULE_ERROR_UNSPECIFIED:
		return v1alpha.Severity_SEVERITY_MINOR
	case l3l4networkpolicyv1alpha.PolicyRuleError_POLICY_RULE_ERROR_TIMEOUT:
		return v1alpha.Severity_SEVERITY_MAJOR
	case l3l4networkpolicyv1alpha.PolicyRuleError_POLICY_RULE_ERROR_OOM:
		return v1alpha.Severity_SEVERITY_CRITICAL
	case l3l4networkpolicyv1alpha.PolicyRuleError_POLICY_RULE_ERROR_UNSUPPORTED:
		return v1alpha.Severity_SEVERITY_MINOR
	default:
		return v1alpha.Severity_SEVERITY_MINOR
	}
}

// getErrorMessage gets the error message from an agent result - same as policy_handler.go
func (r *BulkPolicyReporter) getErrorMessage(agentResult *AgentRuleResult) string {
	if agentResult.ErrorMessage != "" {
		return agentResult.ErrorMessage
	}
	// Fallback to error type
	return agentResult.Error.String()
}

// GetStats returns reporting statistics
func (r *BulkPolicyReporter) GetStats() (lastReportTime time.Time, totalPolicies int64) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return r.lastReportTime, r.totalPolicyCount
}

// TriggerReport manually triggers an immediate bulk report
func (r *BulkPolicyReporter) TriggerReport(ctx context.Context) {
	r.sendBulkReport(ctx)
}

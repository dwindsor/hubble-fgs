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

	ss "github.com/isovalent/hubble-fgs/pkg/model/switchevents/systemstatus"
	"github.com/isovalent/hubble-fgs/pkg/timescape/types"
	l3l4networkpolicyv1alpha "github.com/isovalent/ipa/l3l4networkpolicy/v1alpha"
	v1alpha "github.com/isovalent/ipa/system_status/v1alpha"
)

const (
	// MaxPoliciesPerBatch is the maximum number of policies to include in a single SystemStatusEvent batch
	MaxPoliciesPerBatch = 10000
)

// BulkPolicyReporter handles periodic bulk policy status reporting
type BulkPolicyReporter struct {
	mu                 sync.RWMutex
	store              PolicyStatusStore
	reportingInterval  time.Duration
	timescapeQueue     types.TimescapeQueue
	dataProvider       PolicyStatusDataProvider // Add data provider for serial number
	policyAggregator   *PolicyAggregator
	running            bool
	stopCh             chan struct{}
	wg                 sync.WaitGroup
	lastReportTime     time.Time
	totalReportedCount int64
	totalPolicyCount   int64
}

// NewBulkPolicyReporter creates a new bulk policy status reporter
func NewBulkPolicyReporter(store PolicyStatusStore, timescapeQueue types.TimescapeQueue, dataProvider PolicyStatusDataProvider, policyAggregator *PolicyAggregator, reportingInterval time.Duration) *BulkPolicyReporter {
	if reportingInterval <= 0 {
		reportingInterval = types.DefaultPolicyStatusReportingInterval
	}

	return &BulkPolicyReporter{
		store:             store,
		reportingInterval: reportingInterval,
		timescapeQueue:    timescapeQueue,
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

	logger.GetLogger().Info("bulk policy reporter started",
		"reportingInterval", r.reportingInterval)

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
		logger.GetLogger().Info("no policies to report in bulk")
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
	r.totalReportedCount += 1
	r.mu.Unlock()

	logger.GetLogger().Info("sent bulk policy status report (state-based)",
		"policyCount", len(storedPolicies),
		"reportNumber", r.totalReportedCount)
}

// sendPolicyBatch sends a batch of policies to timescape
func (r *BulkPolicyReporter) sendPolicyBatch(ctx context.Context, policies []*PolicyAggregationResult) {
	if len(policies) == 0 {
		return
	}

	// Create a single SystemStatusEvent with all policies in the batch
	statusEvent := r.createBatchSystemStatusEvent(policies)
	if statusEvent != nil {
		if r.timescapeQueue != nil {
			err := r.timescapeQueue.EnqueueHighPriority(ctx, statusEvent)
			if err != nil {
				logger.GetLogger().Error("failed to enqueue batch policy status event",
					"policyCount", len(policies), "error", err)
			} else {
				logger.GetLogger().Debug("successfully enqueued batch policy status event",
					"policyCount", len(policies))
			}
		} else {
			logger.GetLogger().Error("timescape queue not available for policy reporting")
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

		// Use PolicyGroupId from annotations if available, otherwise use default value - same as previous design
		policyNameForTimescape := "NotFound" // DefaultPolicyGroupId
		if policy.PolicyGroupId != "" {
			policyNameForTimescape = policy.PolicyGroupId
		}

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

		// Overall policy success state: complete AND no rule failures
		policyIsSuccess := policyIsComplete && !hasAnyRuleFailure

		// If some agents didn't respond for any rule, add timeout conditions - same as previous design
		hasTimeoutFailures := false
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
				"PolicyGroupId":      policyNameForTimescape,
				"IsComplete":         fmt.Sprintf("%t", policyIsComplete),
				"IsSuccess":          fmt.Sprintf("%t", policyIsSuccess),
				"HasRuleFailures":    fmt.Sprintf("%t", hasAnyRuleFailure),
				"HasTimeoutFailures": fmt.Sprintf("%t", hasTimeoutFailures),
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

/*
// createSystemStatusEvent converts PolicyAggregationResult to SystemStatusEvent
func (r *BulkPolicyReporter) createSystemStatusEvent(policy *PolicyAggregationResult) *v1alpha.SystemStatusEvent {
	if policy == nil {
		return nil
	}

	// Get node name from data provider (lowercased like in previous design)
	serialNumber := "unknown"
	if r.dataProvider.GetSerialNumber != nil {
		serialNumber = strings.ToLower(r.dataProvider.GetSerialNumber())
	}

	// Extract namespace from PolicyName (kind/namespace/name) - same as previous design
	namespace := r.extractNamespaceFromPolicyName(policy.PolicyName)

	// Use PolicyGroupId from annotations if available, otherwise use default value - same as previous design
	policyNameForTimescape := "NotFound" // DefaultPolicyGroupId
	if policy.PolicyGroupId != "" {
		policyNameForTimescape = policy.PolicyGroupId
	}

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

	// Overall policy success state: complete AND no rule failures
	policyIsSuccess := policyIsComplete && !hasAnyRuleFailure

	// If some agents didn't respond for any rule, add timeout conditions - same as previous design
	hasTimeoutFailures := false
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

	logger.GetLogger().Debug("policy status evaluation for timescape",
		"policyName", policy.PolicyName,
		"isComplete", policyIsComplete,
		"hasRuleFailures", hasAnyRuleFailure,
		"hasTimeoutFailures", hasTimeoutFailures,
		"overallSuccess", policyIsSuccess,
		"failingConditionsCount", len(failingConditions))

	// Create policy status exactly like previous design
	policyStatus := &v1alpha.PolicyStatus{
		Type:              v1alpha.PolicyType_POLICY_TYPE_SMARTSWITCH_NETWORK_POLICY,
		Id:                policy.PolicyName, // PolicyName (kind/namespace/name)
		Name:              policy.Policy,     // Policy name
		Namespace:         namespace,
		Version:           policy.Version,
		FailingConditions: failingConditions,
		ExtraData: map[string]string{
			"PolicyGroupId":      policyNameForTimescape,
			"IsComplete":         fmt.Sprintf("%t", policyIsComplete),
			"IsSuccess":          fmt.Sprintf("%t", policyIsSuccess),
			"HasRuleFailures":    fmt.Sprintf("%t", hasAnyRuleFailure),
			"HasTimeoutFailures": fmt.Sprintf("%t", hasTimeoutFailures),
		},
	}

	// Create the PolicyStatusUpdate with single policy (same structure as previous design)
	policyUpdate := &v1alpha.PolicyStatusUpdate{
		ClusterName: ss.ClusterName, // "smartswitch" - same as systemstatus.ClusterName
		NodeName:    serialNumber,   // same as previous design
		Statuses:    []*v1alpha.PolicyStatus{policyStatus},
	}

	// Create the SystemStatusEvent
	statusEvent := &v1alpha.SystemStatusEvent{
		Time: timestamppb.New(time.Now()),
		Event: &v1alpha.SystemStatusEvent_Policy{
			Policy: policyUpdate,
		},
	}

	// Debug log the complete SystemStatusEvent being created
	logger.GetLogger().Info("SystemStatusEvent created for timescape",
		"policyName", policy.PolicyName,
		"clusterName", policyUpdate.ClusterName,
		"nodeName", policyUpdate.NodeName,
		"statusesCount", len(policyUpdate.Statuses),
		"hasFailingConditions", len(failingConditions) > 0,
		"timestamp", statusEvent.Time.String())

	return statusEvent
}
*/

// generateReportId generates a unique report identifier
func (r *BulkPolicyReporter) generateReportId() string {
	r.mu.RLock()
	count := r.totalReportedCount
	r.mu.RUnlock()

	return time.Now().Format("20060102-150405") + "-" +
		time.Now().Format("000000") + "-" +
		"bulk-" + string(rune(count))
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
func (r *BulkPolicyReporter) GetStats() (lastReportTime time.Time, totalReports int64, totalPolicies int64) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return r.lastReportTime, r.totalReportedCount, r.totalPolicyCount
}

// TriggerReport manually triggers an immediate bulk report
func (r *BulkPolicyReporter) TriggerReport(ctx context.Context) {
	logger.GetLogger().Info("manually triggering bulk policy status report")
	r.sendBulkReport(ctx)
}

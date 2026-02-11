// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

// PolicyStatusHandler manages policy status updates to timescape
// The package exclusively handles policy-level aggregation where:
// - Each policy can have multiple rules
// - All rules within a policy must complete before the policy is considered complete
// - Up to `DefaultMaxBatchSize` completed policies are batched per PolicyStatusUpdate
// - The Name field contains comma-separated rule names
// - The Id field contains the full policy name (kind/namespace/name)

package policystatus

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/cilium/tetragon/pkg/logger"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/isovalent/hubble-fgs/pkg/model/switchevents/systemstatus"
	"github.com/isovalent/hubble-fgs/pkg/timescape/types"

	l3l4networkpolicyv1alpha "github.com/isovalent/ipa/l3l4networkpolicy/v1alpha"
	"github.com/isovalent/ipa/system_status/v1alpha"
)

const (
	POLICY_VALIDATION_ERROR = "POLICY_VALIDATION_ERROR"
)

type PolicyStatusHandler interface {
	Start(ctx context.Context) error
	Stop(ctx context.Context)
	// ReportPolicyStatus manually triggers a policy status report
	ReportPolicyStatus(ctx context.Context) error
	// ReportPolicyValidationStatus reports a policy validation failure or success
	ReportPolicyValidationStatus(ctx context.Context, policyName string, namespace string, ruleName string, resourceVersion string, validationError error) error
	// SetClient sets the timescape client for this handler
	SetClient(client types.Client)
	// ProcessPolicyRuleEvent processes a policy rule event from StreamEvents
	ProcessPolicyRuleEvent(ctx context.Context, agentUID string, ruleEvent *l3l4networkpolicyv1alpha.PolicyRuleEvent) error
	// Update the expected agent count (dpus) from data provider
	UpdateExpectedAgentCountFromProvider()
}

// PolicyStatusDataProvider provides data needed by the policy status handler
type PolicyStatusDataProvider struct {
	// GetSerialNumber returns the system serial number
	GetSerialNumber func() string
	// GetNumDpu returns the number of DPUs from NXOS
	GetNumDpu func() int
}

// policyStatusHandler implements PolicyStatusHandler
type policyStatusHandler struct {
	mu               sync.RWMutex
	running          bool
	stopCh           chan struct{}
	client           types.Client
	dataProvider     PolicyStatusDataProvider
	policyAggregator *PolicyAggregator
}

// NewPolicyStatusHandler creates a new policy status handler
func NewPolicyStatusHandler(dataProvider PolicyStatusDataProvider) PolicyStatusHandler {
	handler := &policyStatusHandler{
		running:      false,
		stopCh:       make(chan struct{}),
		client:       nil, // Client will be set when needed
		dataProvider: dataProvider,

		// Default to 4 FWA agents, 1 minute timeout
		policyAggregator: NewPolicyAggregator(DefaultExpectedAgentCount, DefaultAggregationTimeout),
	}

	// Set policy batch callback
	handler.policyAggregator.SetBatchCallback(handler.handleAggregatedPolicyBatch)

	// Set expected agent count from data provider
	if dataProvider.GetNumDpu != nil {
		numDpu := dataProvider.GetNumDpu()
		handler.setExpectedAgentCount(numDpu)
		logger.GetLogger().Info("set expected agent count from data provider", "numDpu", numDpu)
	} else {
		// Fallback to default
		handler.setExpectedAgentCount(DefaultExpectedAgentCount)
		logger.GetLogger().Warn("GetNumDpu not provided in data provider, using default count", "DpuCount", DefaultExpectedAgentCount)
	}

	return handler
}

// setExpectedAgentCount sets the expected number of FWA agents (2 or 4)
func (h *policyStatusHandler) setExpectedAgentCount(count int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.policyAggregator.expectedAgentCount = count
	logger.GetLogger().Debug("updated expected agent count", "count", count)
}

// UpdateExpectedAgentCountFromProvider updates count from the data provider
// when the Dpu changes in nxos
func (h *policyStatusHandler) UpdateExpectedAgentCountFromProvider() {
	if h.dataProvider.GetNumDpu != nil {
		numDpu := h.dataProvider.GetNumDpu()

		h.mu.RLock()
		currentCount := h.policyAggregator.expectedAgentCount
		h.mu.RUnlock()

		logger.GetLogger().Debug("checking DPU count update",
			"newCount", numDpu,
			"currentCount", currentCount)

		if numDpu == currentCount {
			// No change
			logger.GetLogger().Debug("DPU count unchanged, no update needed")
			return
		}
		if numDpu > 0 {
			h.setExpectedAgentCount(numDpu)
			logger.GetLogger().Info("dynamically updated expected agent count from data provider", "numDpu", numDpu)
		}
	}
}

func (h *policyStatusHandler) periodicDpuCountUpdate(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Check if we have a valid expected agent count
			h.mu.RLock()
			currentCount := h.policyAggregator.expectedAgentCount
			h.mu.RUnlock()

			if currentCount > 0 {
				logger.GetLogger().Info("stopping periodic DPU count updates, valid count already set", "count", currentCount)
				// This will exit the entire goroutine
				return
			}

			// Update expected agent count from data provider
			logger.GetLogger().Debug("periodic DPU count update check", "currentCount", currentCount)
			h.UpdateExpectedAgentCountFromProvider()
		case <-ctx.Done():
			logger.GetLogger().Info("stopping periodic DPU count updates, context cancelled")
			return
		case <-h.stopCh:
			logger.GetLogger().Info("stopping periodic DPU count updates, handler stopped")
			return
		}
	}
}

// SetClient sets the timescape client for this handler
func (h *policyStatusHandler) SetClient(client types.Client) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.client = client
}

// Start begins policy status monitoring
func (h *policyStatusHandler) Start(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.running {
		return nil // Already running
	}

	h.running = true
	h.policyAggregator.Start(ctx)

	// Start periodic DPU count updates (every 5 minutes)
	go h.periodicDpuCountUpdate(ctx)

	logger.GetLogger().Debug("timescape: policy status handler started")
	return nil
}

// Stop terminates policy status monitoring
func (h *policyStatusHandler) Stop(_ context.Context) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if !h.running {
		return
	}

	h.running = false
	h.policyAggregator.Stop()
	close(h.stopCh) // Signal goroutines to stop
	logger.GetLogger().Info("timescape: policy status handler stopped")
}

// ReportPolicyStatus manually triggers a policy status report
func (h *policyStatusHandler) ReportPolicyStatus(_ context.Context) error {
	logger.GetLogger().Debug("timescape: manual policy status report triggered")
	return nil
}

// writePolicyStatusUpdate sends a policy status update to timescape
func (h *policyStatusHandler) writePolicyStatusUpdate(ctx context.Context, event *v1alpha.SystemStatusEvent) error {
	if h.client == nil {
		logger.GetLogger().Error("timescape client not set, cannot send policy status update")
		return fmt.Errorf("timescape client not set")
	}

	errCode := h.client.Send(ctx, event, types.PriorityLow)
	if errCode == types.ErrCodeQueueBusy {
		logger.GetLogger().Debug("timescape: queue full, waiting before retry for policy event")

		// Wait and retry once
		select {
		case <-ctx.Done():
			logger.GetLogger().Debug("timescape: context cancelled while waiting to retry policy event")
			return ctx.Err()
		case <-time.After(3 * time.Second):
			errCode = h.client.Send(ctx, event, types.PriorityLow)
		}
	}
	if errCode != types.ErrCodeSuccess {
		logger.GetLogger().Error("timescape: failed to send policy status update", "error", errCode)
		return fmt.Errorf("failed to send policy status update")
	}

	logger.GetLogger().Debug("timescape: policy status update sent to timescape")
	return nil
}

// ProcessPolicyRuleEvent processes a policy rule event from StreamEvents and converts it to PolicyStatusUpdate
func (h *policyStatusHandler) ProcessPolicyRuleEvent(_ context.Context, agentUID string, ruleEvent *l3l4networkpolicyv1alpha.PolicyRuleEvent) error {
	if !h.running {
		logger.GetLogger().Warn("received policy rule event while handler is not running, ignoring",
			"agentUID", agentUID,
			"policyName", ruleEvent.PolicyName,
			"ruleName", ruleEvent.RuleName)
		return fmt.Errorf("policy status handler not running")
	}

	logger.GetLogger().Debug("timescape: processing policy rule event",
		"agentUID", agentUID,
		"policyName", ruleEvent.PolicyName,
		"ruleName", ruleEvent.RuleName,
		"isSuccess", ruleEvent.IsSuccess)

	// Pass to rule aggregator
	h.policyAggregator.ProcessRuleEvent(agentUID, ruleEvent)
	return nil
}

func (h *policyStatusHandler) handleAggregatedPolicyBatch(policies []*PolicyAggregationResult) {
	logger.GetLogger().Info("handling aggregated policy batch",
		"policyCount", len(policies))

	// Convert batch of policies to PolicyStatusUpdate
	policyStatusUpdate := h.convertPolicyBatchToPolicyStatus(policies)

	// Create SystemStatusEvent with policy update
	now := time.Now()
	event := &v1alpha.SystemStatusEvent{
		Time: timestamppb.New(now),
		Event: &v1alpha.SystemStatusEvent_Policy{
			Policy: policyStatusUpdate,
		},
	}

	// Send to timescape
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := h.writePolicyStatusUpdate(ctx, event); err != nil {
		logger.GetLogger().Error("failed to send aggregated policy batch",
			"policyCount", len(policies),
			"error", err)
	}
}

func (h *policyStatusHandler) convertPolicyBatchToPolicyStatus(policies []*PolicyAggregationResult) *v1alpha.PolicyStatusUpdate {
	serialNumber := "unknown"
	if h.dataProvider.GetSerialNumber != nil {
		serialNumber = h.dataProvider.GetSerialNumber()
	}

	var statuses []*v1alpha.PolicyStatus

	for _, policyResult := range policies {
		// Extract namespace from PolicyName (kind/namespace/name)
		namespace := h.extractNamespaceFromPolicyName(policyResult.PolicyName)

		// Collect all rule names for this policy
		var ruleNames []string
		for ruleName := range policyResult.RuleResults {
			ruleNames = append(ruleNames, ruleName)
		}

		// Create comma-separated rule names for the Name field
		commaSeparatedRuleNames := strings.Join(ruleNames, ",")

		// Aggregate all failures across all rules in this policy
		var failingConditions []*v1alpha.FailingCondition

		// For example, there are 4 agents response expected.
		// If any agent reports failure for a rule, overallSuccess is false.
		// Let's say, there are 4 agents.
		// 2 agents report success, 1 reports failure, and 1 times out with no response.
		// The failingConditions will have the 2 failingConditions:
		//   -  failure from 1 agent,
		//   -  and a timeout condition.

		for ruleName, ruleResult := range policyResult.RuleResults {
			for agentUID, agentResult := range ruleResult.AgentResults {
				if !agentResult.IsSuccess {
					failingConditions = append(failingConditions, &v1alpha.FailingCondition{
						ConditionId: agentResult.Error.String(),
						Severity:    h.convertErrorToSeverity(agentResult.Error),
						Message:     fmt.Sprintf("Rule %s, Agent %s: %s", ruleName, agentUID, h.getErrorMessage(agentResult)),
					})
				}
			}
		}

		// If some agents didn't respond for any rule, add timeout conditions
		for ruleName, ruleResult := range policyResult.RuleResults {
			if len(ruleResult.AgentResults) < policyResult.ExpectedCount {
				failingConditions = append(failingConditions, &v1alpha.FailingCondition{
					ConditionId: "TIMEOUT_AGENT_RESPONSES",
					Severity:    v1alpha.Severity_SEVERITY_MAJOR,
					Message: fmt.Sprintf("Rule %s: Expected %d agents, received %d responses",
						ruleName, policyResult.ExpectedCount, len(ruleResult.AgentResults)),
				})
			}
		}

		policyStatus := &v1alpha.PolicyStatus{
			Type:              v1alpha.PolicyType_POLICY_TYPE_SMARTSWITCH_NETWORK_POLICY,
			Id:                policyResult.PolicyName, // PolicyName (kind/namespace/name)
			Name:              commaSeparatedRuleNames, // Comma-separated rule names
			Namespace:         namespace,
			Version:           policyResult.Version,
			FailingConditions: failingConditions,
		}

		statuses = append(statuses, policyStatus)
	}

	return &v1alpha.PolicyStatusUpdate{
		ClusterName: systemstatus.ClusterName,
		NodeName:    serialNumber,
		Statuses:    statuses, // Up to 3 policy statuses
	}
}

// convertErrorToSeverity maps PolicyRuleError to Severity
func (h *policyStatusHandler) convertErrorToSeverity(err l3l4networkpolicyv1alpha.PolicyRuleError) v1alpha.Severity {
	switch err {
	case l3l4networkpolicyv1alpha.PolicyRuleError_POLICY_RULE_ERROR_UNSPECIFIED:
		return v1alpha.Severity_SEVERITY_MINOR
	case l3l4networkpolicyv1alpha.PolicyRuleError_POLICY_RULE_ERROR_TIMEOUT:
		return v1alpha.Severity_SEVERITY_MAJOR
	case l3l4networkpolicyv1alpha.PolicyRuleError_POLICY_RULE_ERROR_OOM:
		return v1alpha.Severity_SEVERITY_CRITICAL
	case l3l4networkpolicyv1alpha.PolicyRuleError_POLICY_RULE_ERROR_UNSUPPORTED:
		return v1alpha.Severity_SEVERITY_MINOR
	case l3l4networkpolicyv1alpha.PolicyRuleError_POLICY_RULE_ERROR_FORMAT:
		return v1alpha.Severity_SEVERITY_MAJOR
	}
	return v1alpha.Severity_SEVERITY_MINOR
}

// getErrorMessage gets the error message from an agent result
func (h *policyStatusHandler) getErrorMessage(agentResult *AgentRuleResult) string {
	if agentResult.ErrorMessage != "" {
		return agentResult.ErrorMessage
	}
	return agentResult.Error.String()
}

// extractNamespaceFromPolicyName extracts the namespace from a policy name in format "kind/namespace/name"
// Returns the namespace or empty string if the format is invalid
func (h *policyStatusHandler) extractNamespaceFromPolicyName(policyName string) string {
	if policyName == "" {
		return ""
	}

	// Split by "/" to get parts: [kind, namespace, name]
	parts := strings.Split(policyName, "/")

	// Expected format is "kind/namespace/name", so we need at least 3 parts
	if len(parts) < 3 {
		logger.GetLogger().Debug("policy name format invalid, expected 'kind/namespace/name'",
			"policyName", policyName,
			"parts", len(parts))
		return ""
	}

	// Return the namespace (second part, index 1)
	namespace := parts[1]

	logger.GetLogger().Debug("extracted namespace from policy name",
		"policyName", policyName,
		"namespace", namespace)

	return namespace
}

// ReportPolicyValidationStatus reports a policy validation failure or success to timescape
// This function is invoked to report AGW policy validation failure, when the policy is not sent to DPUs
func (h *policyStatusHandler) ReportPolicyValidationStatus(ctx context.Context, policyName string, namespace string, ruleName string, resourceVersion string, validationError error) error {
	isSuccess := validationError == nil
	logger.GetLogger().Info("reporting policy validation to timescape",
		"policyName", policyName,
		"namespace", namespace,
		"ruleName", ruleName,
		"resourceVersion", resourceVersion,
		"isSuccess", isSuccess,
		"error", validationError)

	// Create policy status with validation failure
	policyStatus := h.createPolicyValidationStatus(policyName, namespace, ruleName, resourceVersion, validationError)

	// Create PolicyStatusUpdate
	serialNumber := "unknown"
	if h.dataProvider.GetSerialNumber != nil {
		serialNumber = h.dataProvider.GetSerialNumber()
	}

	policyStatusUpdate := &v1alpha.PolicyStatusUpdate{
		ClusterName: systemstatus.ClusterName,
		NodeName:    serialNumber,
		Statuses:    []*v1alpha.PolicyStatus{policyStatus},
	}

	// Create SystemStatusEvent
	now := time.Now()
	event := &v1alpha.SystemStatusEvent{
		Time: timestamppb.New(now),
		Event: &v1alpha.SystemStatusEvent_Policy{
			Policy: policyStatusUpdate,
		},
	}

	// Send to timescape
	if err := h.writePolicyStatusUpdate(ctx, event); err != nil {
		logger.GetLogger().Error("failed to send policy validation result to timescape",
			"policyName", policyName,
			"isSuccess", isSuccess,
			"error", err)
		return err
	}

	logger.GetLogger().Debug("successfully reported policy validation result to timescape",
		"policyName", policyName,
		"resourceVersion", resourceVersion,
		"isSuccess", isSuccess)

	return nil
}

// createPolicyValidationStatus creates a PolicyStatus for a validation failure or success
func (h *policyStatusHandler) createPolicyValidationStatus(policyName string, namespace string, ruleName string, resourceVersion string, validationError error) *v1alpha.PolicyStatus {
	policyStatus := &v1alpha.PolicyStatus{
		Type:      v1alpha.PolicyType_POLICY_TYPE_SMARTSWITCH_NETWORK_POLICY,
		Id:        policyName, // Full policy name (kind/namespace/name)
		Name:      ruleName,
		Namespace: namespace,
		Version:   resourceVersion,
	}

	// Only populate FailingConditions if there's an error (failure case)
	if validationError != nil {
		// Set error severity, condition ID and error message
		errorMsg := validationError.Error()
		failingCondition := &v1alpha.FailingCondition{
			ConditionId: POLICY_VALIDATION_ERROR,
			Severity:    v1alpha.Severity_SEVERITY_MAJOR,
			Message:     fmt.Sprintf("Policy validation failed: %s", errorMsg),
		}

		policyStatus.FailingConditions = []*v1alpha.FailingCondition{failingCondition}
	}
	return policyStatus
}

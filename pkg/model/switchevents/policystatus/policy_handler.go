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

	"github.com/isovalent/hubble-fgs/pkg/timescape/types"

	l3l4networkpolicyv1alpha "github.com/isovalent/ipa/l3l4networkpolicy/v1alpha"
	"github.com/isovalent/ipa/system_status/v1alpha"
)

const (
	POLICY_VALIDATION_ERROR = "POLICY_VALIDATION_ERROR"
	DefaultPolicyGroupId    = "NotFound"
)

type PolicyStatusHandler interface {
	Start(ctx context.Context) error
	Stop(ctx context.Context)
	// ReportPolicyStatus manually triggers a policy status report
	ReportPolicyStatus(ctx context.Context) error
	// ReportPolicyValidationStatus reports a policy validation failure or success
	ReportPolicyValidationStatus(ctx context.Context, policyName string, namespace string, ruleName string, resourceVersion string, policyGroupId string, validationError error) error
	// SetClient sets the timescape client for this handler
	SetClient(client types.Client)
	// SetPolicyGroupId sets the PolicyGroupId for a specific policy
	SetPolicyGroupId(policyName string, policyGroupId string)
	// ProcessPolicyRuleEvent processes a policy rule event from StreamEvents
	ProcessPolicyRuleEvent(ctx context.Context, agentUID string, ruleEvent *l3l4networkpolicyv1alpha.PolicyRuleEvent) error
	// SetExpectedRuleCount sets the expected number of rules for a policy
	SetExpectedRuleCount(policyName string, expectedRuleCount int)
	// Update the expected agent count (dpus) from data provider
	UpdateExpectedAgentCountFromProvider()
	// MarkPolicyForDeletion marks a policy to be deleted from the store after successful completion
	MarkPolicyForDeletion(policyName string)
}

// PolicyStatusDataProvider provides data needed by the policy status handler
type PolicyStatusDataProvider struct {
	// GetSerialNumber returns the system serial number
	GetSerialNumber func() string
	// GetNumDpu returns the number of DPUs from NXOS
	GetNumDpu func() int
}

// policyStatusHandler implements PolicyStatusHandler with periodic bulk reporting
type policyStatusHandler struct {
	mu                    sync.RWMutex
	running               bool
	stopCh                chan struct{}
	client                types.Client
	dataProvider          PolicyStatusDataProvider
	policyAggregator      *PolicyAggregator
	policyStatusStore     PolicyStatusStore
	bulkPolicyReporter    *BulkPolicyReporter
	bulkReportingInterval time.Duration // Configured reporting interval for bulk policy reporter
}

// NewPolicyStatusHandler creates a new policy status handler with default configuration
func NewPolicyStatusHandler(dataProvider PolicyStatusDataProvider) PolicyStatusHandler {
	return NewPolicyStatusHandlerWithConfig(dataProvider, types.DefaultPolicyStatusReportingInterval)
}

// NewPolicyStatusHandlerWithConfig creates a new policy status handler with custom configuration
func NewPolicyStatusHandlerWithConfig(dataProvider PolicyStatusDataProvider, bulkReportingInterval time.Duration) PolicyStatusHandler {
	// Create policy status store
	policyStatusStore := NewInMemoryPolicyStatusStore()

	// Create policy aggregator with store
	policyAggregator := NewPolicyAggregator(DefaultExpectedAgentCount, bulkReportingInterval, policyStatusStore)

	handler := &policyStatusHandler{
		running:               false,
		stopCh:                make(chan struct{}),
		client:                nil, // Client will be set when needed
		dataProvider:          dataProvider,
		policyAggregator:      policyAggregator,
		policyStatusStore:     policyStatusStore,
		bulkPolicyReporter:    nil, // Will be created when timescape queue is available
		bulkReportingInterval: bulkReportingInterval,
	}

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
	h.policyAggregator.SetExpectedAgentCount(count)
	logger.GetLogger().Debug("updated expected agent count", "count", count)
}

// UpdateExpectedAgentCountFromProvider updates count from the data provider
// when the Dpu changes in nxos
func (h *policyStatusHandler) UpdateExpectedAgentCountFromProvider() {
	if h.dataProvider.GetNumDpu != nil {
		numDpu := h.dataProvider.GetNumDpu()

		currentCount := h.policyAggregator.GetExpectedAgentCount()

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
		} else {
			logger.GetLogger().Warn("GetNumDpu returned non-positive count, ignoring", "numDpu", numDpu)
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
			currentCount := h.policyAggregator.GetExpectedAgentCount()

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

// Start begins policy status monitoring with bulk reporting
func (h *policyStatusHandler) Start(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.running {
		logger.GetLogger().Info("PolicyHandler: Already running, ignoring start request")
		return nil // Already running
	}

	if h.client == nil {
		logger.GetLogger().Error("PolicyHandler: Cannot start - client is nil")
		return fmt.Errorf("client is nil")
	}

	// Initialize bulk policy reporter if not already created
	if h.bulkPolicyReporter == nil {
		if timescapeQueue := h.client.GetQueue(); timescapeQueue != nil {
			h.bulkPolicyReporter = NewBulkPolicyReporter(h.policyStatusStore, timescapeQueue, h.dataProvider, h.policyAggregator, h.bulkReportingInterval)
			logger.GetLogger().Info("initialized bulk policy reporter", "interval", h.bulkReportingInterval)
		} else {
			logger.GetLogger().Error("timescape queue not available for bulk reporting")
			return fmt.Errorf("timescape queue not available")
		}
	}

	h.running = true
	h.policyAggregator.Start(ctx)

	// Start bulk policy reporter
	if h.bulkPolicyReporter != nil {
		err := h.bulkPolicyReporter.Start(ctx)
		if err != nil {
			logger.GetLogger().Error("failed to start bulk policy reporter", "error", err)
			return fmt.Errorf("failed to start bulk policy reporter: %w", err)
		}
	}

	// Start periodic DPU count updates (every 5 minutes)
	go h.periodicDpuCountUpdate(ctx)

	logger.GetLogger().Debug("timescape: policy status handler started with bulk reporting")
	return nil
}

// Stop terminates policy status monitoring
func (h *policyStatusHandler) Stop(ctx context.Context) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if !h.running {
		return
	}

	h.running = false

	// Stop bulk policy reporter first
	if h.bulkPolicyReporter != nil {
		h.bulkPolicyReporter.Stop(ctx)
	}

	h.policyAggregator.Stop()
	close(h.stopCh) // Signal goroutines to stop

	logger.GetLogger().Info("timescape: policy status handler stopped")
}

// ReportPolicyStatus manually triggers a policy status report
func (h *policyStatusHandler) ReportPolicyStatus(ctx context.Context) error {
	logger.GetLogger().Debug("timescape: manual policy status report triggered")
	if h.bulkPolicyReporter != nil {
		h.bulkPolicyReporter.TriggerReport(ctx)
	}
	return nil
}

// writePolicyStatusUpdate sends a policy status update to timescape
func (h *policyStatusHandler) writePolicyStatusUpdate(ctx context.Context, event *v1alpha.SystemStatusEvent) error {
	if h.client == nil {
		logger.GetLogger().Error("timescape client not set, cannot send policy status update")
		return fmt.Errorf("timescape client not set")
	}

	if !h.running {
		logger.GetLogger().Error("timescape: policy handler not running, cannot send policy status update")
		return fmt.Errorf("timescape: policy handler not running")
	}

	logger.GetLogger().Info("timescape: sending policy status update to timescape",
		"hasEvent", event != nil,
		"clientSet", h.client != nil)

	errCode := h.client.Send(ctx, event, types.PriorityLow)
	if errCode == types.ErrCodeQueueBusy {
		logger.GetLogger().Info("timescape: queue full, waiting before retry for policy event")

		// Wait and retry once
		select {
		case <-ctx.Done():
			logger.GetLogger().Info("timescape: context cancelled while waiting to retry policy event")
			return ctx.Err()
		case <-h.stopCh:
			logger.GetLogger().Debug("timescape: policy handler stopped while waiting to retry policy event")
			return fmt.Errorf("timescape: policy handler stopped")
		case <-time.After(3 * time.Second):
			errCode = h.client.Send(ctx, event, types.PriorityLow)
		}
	}
	if errCode != types.ErrCodeSuccess {
		logger.GetLogger().Error("timescape: failed to send policy status update", "error", errCode)
		return fmt.Errorf("timescape: failed to send policy status update")
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
		return fmt.Errorf("timescape: policy status handler not running")
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

// StoreValidationError stores a policy with validation error for bulk reporting
func (h *policyStatusHandler) StoreValidationError(policyName, errorMsg string) {
	h.policyAggregator.StoreValidationError(policyName, errorMsg)
	logger.GetLogger().Debug("stored validation error for bulk reporting",
		"policyName", policyName,
		"error", errorMsg)
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
func (h *policyStatusHandler) ReportPolicyValidationStatus(ctx context.Context, policyName string, namespace string, ruleName string, resourceVersion string, policyGroupId string, validationError error) error {
	isSuccess := validationError == nil
	logger.GetLogger().Debug("reporting policy validation to timescape",
		"policyName", policyName,
		"namespace", namespace,
		"ruleName", ruleName,
		"resourceVersion", resourceVersion,
		"policyGroupId", policyGroupId,
		"isSuccess", isSuccess,
		"error", validationError)

	// Store validation error in policy store for periodic bulk reporting
	if validationError != nil {
		h.policyAggregator.StoreValidationError(policyName, validationError.Error())
		logger.GetLogger().Info("stored policy validation error for periodic reporting",
			"policyName", policyName,
			"error", validationError.Error())
	} else {
		// For successful validation, we could store a success status or just let it be handled by normal policy processing
		logger.GetLogger().Debug("policy validation successful, will be handled by normal policy flow",
			"policyName", policyName)
	}

	return nil
}

// SetPolicyGroupId sets the PolicyGroupId for a specific policy
func (h *policyStatusHandler) SetPolicyGroupId(policyName string, policyGroupId string) {
	// Set it in the aggregator directly
	if h.policyAggregator != nil {
		h.policyAggregator.SetPolicyGroupId(policyName, policyGroupId)
	}

	logger.GetLogger().Debug("timescape: set PolicyGroupId",
		"policyName", policyName,
		"policyGroupId", policyGroupId)
}

// SetExpectedRuleCount sets the expected number of rules for a policy
func (h *policyStatusHandler) SetExpectedRuleCount(policyName string, expectedRuleCount int) {
	if h.policyAggregator != nil {
		h.policyAggregator.SetExpectedRuleCount(policyName, expectedRuleCount)
	}
	logger.GetLogger().Debug("timescape: set expected rule count",
		"policyName", policyName,
		"expectedRuleCount", expectedRuleCount)
}

// MarkPolicyForDeletion marks a policy to be deleted from the store after successful completion
func (h *policyStatusHandler) MarkPolicyForDeletion(policyName string) {
	if h.policyAggregator != nil {
		h.policyAggregator.MarkPolicyForDeletion(policyName)
	}
}

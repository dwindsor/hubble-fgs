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
	"time"

	"github.com/cilium/tetragon/pkg/logger"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/isovalent/hubble-fgs/pkg/timescape/types"

	"github.com/isovalent/ipa/system_status/v1alpha"
)

// PolicyStatusHandler manages policy status updates to timescape
type PolicyStatusHandler interface {
	Start(ctx context.Context) error
	Stop(ctx context.Context)
	// ReportPolicyStatus manually triggers a policy status report
	ReportPolicyStatus(ctx context.Context) error
	// SetClient sets the timescape client for this handler
	SetClient(client types.Client)
}

// PolicyStatusDataProvider provides data needed by the policy status handler
type PolicyStatusDataProvider struct {
	// GetSerialNumber returns the system serial number
	GetSerialNumber func() string
}

// policyStatusHandler implements PolicyStatusHandler
type policyStatusHandler struct {
	mu           sync.RWMutex
	running      bool
	stopCh       chan struct{}
	client       types.Client
	dataProvider PolicyStatusDataProvider
}

// NewPolicyStatusHandler creates a new policy status handler
func NewPolicyStatusHandler(dataProvider PolicyStatusDataProvider) PolicyStatusHandler {
	return &policyStatusHandler{
		running:      false,
		stopCh:       make(chan struct{}),
		client:       nil, // Client will be set when needed
		dataProvider: dataProvider,
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
	// TODO: Implement policy status monitoring
	logger.GetLogger().Debug("timescape: policy status handler started")
	h.ReportPolicyStatus(ctx)
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
	close(h.stopCh)
	logger.GetLogger().Debug("timescape: policy status handler stopped")
}

// ReportPolicyStatus manually triggers a policy status report
func (h *policyStatusHandler) ReportPolicyStatus(ctx context.Context) error {
	logger.GetLogger().Debug("timescape: manual policy status report triggered")
	// TODO: Implement policy status reporting
	h.testPolicyStatusUpdate(ctx)
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
		logger.GetLogger().Warn("timescape: queue full, waiting before retry")

		// Retry after waiting
		errCode = h.client.Send(ctx, event, types.PriorityLow)
		if errCode == types.ErrCodeFailure {
			logger.GetLogger().Error("timescape: failed to send policy status update to timescape after retry", "error", errCode)
			return fmt.Errorf("failed to send policy status update after retry")
		}
	} else if errCode != types.ErrCodeSuccess {
		logger.GetLogger().Error("failed to send policy status update to timescape", "error", errCode)
		return fmt.Errorf("failed to send policy status update")
	}

	logger.GetLogger().Debug("timescape: policy status update sent to timescape")
	return nil
}

// testPolicyStatusUpdate validates the timescape endpoint with policy status events
func (h *policyStatusHandler) testPolicyStatusUpdate(ctx context.Context) error {
	logger.GetLogger().Debug("timescape: sending policy status update to timescape")

	// Create a test policy status event
	now := time.Now()
	serialNumber := h.dataProvider.GetSerialNumber()

	testEvent := &v1alpha.SystemStatusEvent{
		Time: timestamppb.New(now),
		Event: &v1alpha.SystemStatusEvent_Policy{
			Policy: &v1alpha.PolicyStatusUpdate{
				ClusterName: "smartswitch",
				NodeName:    serialNumber,
				Statuses: []*v1alpha.PolicyStatus{
					{
						Type:      v1alpha.PolicyType_POLICY_TYPE_SMARTSWITCH_NETWORK_POLICY,
						Id:        "policy-test-001",
						Name:      "test-network-policy",
						Namespace: "default",
						Version:   "v1.0.0-test",
						FailingConditions: []*v1alpha.FailingCondition{
							{
								ConditionId: "policy_test_condition",
								Severity:    v1alpha.Severity_SEVERITY_MINOR,
								Message:     "This is a policy test condition",
							},
						},
					},
					{
						Type:              v1alpha.PolicyType_POLICY_TYPE_SMARTSWITCH_NETWORK_POLICY,
						Id:                "smartswitch-policy-test-002",
						Name:              "smartswitch-test-policy",
						Namespace:         "kube-system",
						Version:           "v2.1.0-test",
						FailingConditions: []*v1alpha.FailingCondition{},
					},
				},
			},
		},
	}

	return h.writePolicyStatusUpdate(ctx, testEvent)
}

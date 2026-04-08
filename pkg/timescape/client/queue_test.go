// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package client

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/isovalent/hubble-fgs/pkg/timescape/types"

	systemstatus "github.com/isovalent/ipa/system_status/v1alpha"
)

// MockTransport implements types.Transport for testing
type MockTransport struct {
	mu           sync.Mutex
	batches      [][]types.Msg
	pushError    error
	pushDelay    time.Duration
	callCount    int
	maxFailures  int // Number of failures before success
	currentFails int
}

func (mt *MockTransport) PushBatch(ctx context.Context, messages []types.Msg) error {
	mt.mu.Lock()
	defer mt.mu.Unlock()

	mt.callCount++

	// Simulate failures for retry testing
	if mt.currentFails < mt.maxFailures {
		mt.currentFails++
		return mt.pushError
	}

	// If pushError is set and we've exceeded maxFailures, still fail if maxFailures is very high
	// This handles the "always fail" test case
	if mt.pushError != nil && mt.maxFailures >= 10 {
		return mt.pushError
	}

	// Simulate delay if configured
	if mt.pushDelay > 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(mt.pushDelay):
		}
	}

	// Record the batch (only if we're past the failure phase)
	batch := make([]types.Msg, len(messages))
	copy(batch, messages)
	mt.batches = append(mt.batches, batch)

	return nil
}

func (mt *MockTransport) GetBatches() [][]types.Msg {
	mt.mu.Lock()
	defer mt.mu.Unlock()
	result := make([][]types.Msg, len(mt.batches))
	copy(result, mt.batches)
	return result
}

func (mt *MockTransport) GetCallCount() int {
	mt.mu.Lock()
	defer mt.mu.Unlock()
	return mt.callCount
}

func (mt *MockTransport) Reset() {
	mt.mu.Lock()
	defer mt.mu.Unlock()
	mt.batches = nil
	mt.callCount = 0
	mt.currentFails = 0
}

func (mt *MockTransport) Name() string {
	return "MockTransport"
}

// Helper function to create test event
func createTestEvent(t *testing.T, eventType string) *systemstatus.SystemStatusEvent {
	now := time.Now()

	switch eventType {
	case "system":
		return &systemstatus.SystemStatusEvent{
			Time: timestamppb.New(now),
			Event: &systemstatus.SystemStatusEvent_Status{
				Status: &systemstatus.SystemStatusUpdate{
					ClusterName: "test-cluster",
					NodeName:    "test-node",
					System: &systemstatus.SystemID{
						Name:    "test-system",
						Version: "1.0.0",
					},
					StartedAt:       timestamppb.New(now),
					TotalConditions: 1,
					FailingConditions: []*systemstatus.FailingCondition{
						{
							ConditionId: "connection_test_condition",
							Severity:    2,
							Message:     "This is a connection test condition",
						},
					},
					ExtraData: map[string]string{
						"test_type":   "connection_validation",
						"test_id":     uuid.New().String(),
						"client_type": "agw",
					},
				},
			},
		}
	case "policy":
		return &systemstatus.SystemStatusEvent{
			Time: timestamppb.New(now),
			Event: &systemstatus.SystemStatusEvent_Policy{
				Policy: &systemstatus.PolicyStatusUpdate{
					ClusterName: "test-cluster",
					NodeName:    "test-node",
					Statuses: []*systemstatus.PolicyStatus{
						{
							Type:      systemstatus.PolicyType_POLICY_TYPE_SMARTSWITCH_NETWORK_POLICY,
							Id:        "policy-test-001",
							Name:      "test-network-policy",
							Namespace: "default",
							Version:   "v1.0.0-test",
							FailingConditions: []*systemstatus.FailingCondition{
								{
									ConditionId: "policy_test_condition",
									Severity:    1, // SEVERITY_MINOR
									Message:     "This is a policy test condition",
								},
							},
						},
						{
							Type:              systemstatus.PolicyType_POLICY_TYPE_SMARTSWITCH_NETWORK_POLICY,
							Id:                "smartswitch-policy-test-002",
							Name:              "smartswitch-test-policy",
							Namespace:         "kube-system",
							Version:           "v2.1.0-test",
							FailingConditions: []*systemstatus.FailingCondition{},
						},
					},
				},
			},
		}
	default:
		t.Fatalf("Unknown event type: %s", eventType)
		return nil
	}
}

func TestNewQueue(t *testing.T) {
	tests := []struct {
		name   string
		config types.Config
	}{
		{
			name: "valid_config",
			config: types.Config{
				Transport:    &MockTransport{},
				BatchTimeout: 100 * time.Millisecond,
				SendTimeout:  5 * time.Second,
				MaxRetries:   3,
				BaseBackoff:  100 * time.Millisecond,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			queue, err := NewQueue(ctx, tt.config)

			require.NoError(t, err)
			assert.NotNil(t, queue)
			assert.Equal(t, tt.config.Transport, queue.transport)
			assert.Equal(t, tt.config, queue.cfg)

			// Cleanup
			err = queue.Close()
			assert.NoError(t, err)
		})
	}
}

func TestQueueSend(t *testing.T) {
	tests := []struct {
		name     string
		priority types.Priority
		event    *systemstatus.SystemStatusEvent
		expected types.ErrorCode
	}{
		{
			name:     "high_priority_system_event",
			priority: types.PriorityHigh,
			event:    createTestEvent(t, "system"),
			expected: types.ErrCodeSuccess,
		},
		{
			name:     "low_priority_policy_event",
			priority: types.PriorityLow,
			event:    createTestEvent(t, "policy"),
			expected: types.ErrCodeSuccess,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			mockTransport := &MockTransport{}

			config := types.Config{
				Transport:    mockTransport,
				BatchTimeout: 100 * time.Millisecond,
				SendTimeout:  5 * time.Second,
				MaxRetries:   3,
				BaseBackoff:  100 * time.Millisecond,
			}

			queue, err := NewQueue(ctx, config)
			require.NoError(t, err)
			defer queue.Close()

			result := queue.Send(ctx, tt.event, tt.priority)
			assert.Equal(t, tt.expected, result)

			// Wait a bit for processing
			time.Sleep(50 * time.Millisecond)
		})
	}
}

func TestQueueEnqueue(t *testing.T) {
	ctx := context.Background()
	mockTransport := &MockTransport{}

	config := types.Config{
		Transport: mockTransport,

		BatchTimeout: 100 * time.Millisecond,
		SendTimeout:  5 * time.Second,
		MaxRetries:   3,
		BaseBackoff:  100 * time.Millisecond,
	}

	queue, err := NewQueue(ctx, config)
	require.NoError(t, err)
	defer queue.Close()

	tests := []struct {
		name     string
		msg      types.Msg
		expected types.ErrorCode
	}{
		{
			name: "successful_enqueue_high",
			msg: types.Msg{
				ID:       uuid.New().String(),
				Priority: types.PriorityHigh,
				Event:    createTestEvent(t, "system"),
			},
			expected: types.ErrCodeSuccess,
		},
		{
			name: "successful_enqueue_low",
			msg: types.Msg{
				ID:       uuid.New().String(),
				Priority: types.PriorityLow,
				Event:    createTestEvent(t, "policy"),
			},
			expected: types.ErrCodeSuccess,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := queue.Enqueue(tt.msg)
			assert.Equal(t, tt.expected, result)
		})
	}

	// Wait for processing
	time.Sleep(200 * time.Millisecond)
}

func TestQueueChannelFor(t *testing.T) {
	ctx := context.Background()
	mockTransport := &MockTransport{}

	config := types.Config{
		Transport: mockTransport,

		BatchTimeout: 100 * time.Millisecond,
		SendTimeout:  5 * time.Second,
		MaxRetries:   3,
		BaseBackoff:  100 * time.Millisecond,
	}

	queue, err := NewQueue(ctx, config)
	require.NoError(t, err)
	defer queue.Close()

	tests := []struct {
		name     string
		priority types.Priority
		expected chan types.Msg
	}{
		{
			name:     "high_priority",
			priority: types.PriorityHigh,
			expected: queue.highCh,
		},
		{
			name:     "low_priority",
			priority: types.PriorityLow,
			expected: queue.lowCh,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := queue.channelFor(tt.priority)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestQueueQueueBusy(t *testing.T) {
	ctx := context.Background()

	// Create a transport that blocks forever to prevent channel draining
	blockingTransport := &MockTransport{
		pushDelay: 1 * time.Hour, // Effectively blocks forever for this test
	}

	config := types.Config{
		Transport:    blockingTransport,
		BatchTimeout: 1 * time.Millisecond, // Very short timeout
		SendTimeout:  5 * time.Second,
		MaxRetries:   3,
		BaseBackoff:  100 * time.Millisecond,
	}

	queue, err := NewQueue(ctx, config)
	require.NoError(t, err)

	// Fill the high priority queue completely (capacity is 10)
	// The first message will be taken by the worker but will block in transport
	// Messages 1-10 fill the channel buffer completely
	for i := 0; i < 10; i++ {
		msg := types.Msg{
			ID:       uuid.New().String(),
			Priority: types.PriorityHigh,
			Event:    createTestEvent(t, "system"),
		}
		result := queue.Enqueue(msg)
		assert.Equal(t, types.ErrCodeSuccess, result, "Message %d should succeed", i+1)
	}

	// Give worker time to pick up first message and get blocked in transport
	time.Sleep(50 * time.Millisecond)

	// Now the 11th message should return ErrCodeQueueBusy since:
	// - Worker has 1st message and is blocked in transport
	// - Channel buffer has messages 2-10 (9 messages, buffer is full at 10 capacity)
	// - Actually, the channel should have room for 1 more since worker took 1
	// So let's add 2 more messages to definitely fill it

	// Add one more that should succeed (filling the last buffer slot)
	msg := types.Msg{
		ID:       uuid.New().String(),
		Priority: types.PriorityHigh,
		Event:    createTestEvent(t, "system"),
	}
	result := queue.Enqueue(msg)
	// This might succeed if there's still buffer space
	if result != types.ErrCodeSuccess {
		assert.Equal(t, types.ErrCodeQueueBusy, result, "Expected either success or queue busy")
	}

	// This message should definitely return ErrCodeQueueBusy
	msg2 := types.Msg{
		ID:       uuid.New().String(),
		Priority: types.PriorityHigh,
		Event:    createTestEvent(t, "system"),
	}
	result2 := queue.Enqueue(msg2)
	assert.Equal(t, types.ErrCodeQueueBusy, result2)

	// Close the queue (this will cancel context and unblock workers)
	err = queue.Close()
	assert.NoError(t, err)
}

func TestQueueContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	// Use a transport that blocks forever to keep workers busy
	mockTransport := &MockTransport{
		pushDelay: 24 * time.Hour, // Blocks essentially forever
	}

	config := types.Config{
		Transport:    mockTransport,
		BatchTimeout: 1 * time.Millisecond,
		SendTimeout:  5 * time.Second,
		MaxRetries:   0, // No retries to avoid retry loop complexity
		BaseBackoff:  100 * time.Millisecond,
	}

	queue, err := NewQueue(ctx, config)
	require.NoError(t, err)

	// Fill the high priority queue completely (capacity 10)
	for i := 0; i < 10; i++ {
		msg := types.Msg{
			ID:       uuid.New().String(),
			Priority: types.PriorityHigh,
			Event:    createTestEvent(t, "system"),
		}
		result := queue.Enqueue(msg)
		assert.Equal(t, types.ErrCodeSuccess, result)
	}

	// Give worker time to take first message and get blocked in transport
	time.Sleep(50 * time.Millisecond)

	// Cancel the context
	cancel()

	// Give time for cancellation to propagate
	time.Sleep(10 * time.Millisecond)

	// Try to enqueue - should block on channel send and detect context cancellation
	msg := types.Msg{
		ID:       uuid.New().String(),
		Priority: types.PriorityHigh,
		Event:    createTestEvent(t, "system"),
	}

	result := queue.Enqueue(msg)
	assert.Equal(t, types.ErrCodeShuttingDown, result)

	err = queue.Close()
	assert.NoError(t, err)
}

func TestQueueImmediateMessageProcessing(t *testing.T) {
	ctx := context.Background()
	mockTransport := &MockTransport{}

	config := types.Config{
		Transport:    mockTransport,
		BatchTimeout: 200 * time.Millisecond,
		SendTimeout:  5 * time.Second,
		MaxRetries:   3,
		BaseBackoff:  100 * time.Millisecond,
	}

	queue, err := NewQueue(ctx, config)
	require.NoError(t, err)
	defer queue.Close()

	// Send 2 low priority messages (should be processed immediately)
	for i := 0; i < 2; i++ {
		msg := types.Msg{
			ID:       uuid.New().String(),
			Priority: types.PriorityLow,
			Event:    createTestEvent(t, "system"),
		}
		result := queue.Enqueue(msg)
		assert.Equal(t, types.ErrCodeSuccess, result)
	}

	// Wait for processing
	time.Sleep(100 * time.Millisecond)

	batches := mockTransport.GetBatches()
	assert.Len(t, batches, 2, "Should have 2 batches (one per message)")
	for _, batch := range batches {
		assert.Len(t, batch, 1, "Each batch should contain 1 message")
	}
}

func TestQueueImmediateProcessing(t *testing.T) {
	ctx := context.Background()
	mockTransport := &MockTransport{}

	config := types.Config{
		Transport:    mockTransport,
		BatchTimeout: 1 * time.Second, // Long timeout, but messages processed immediately
		SendTimeout:  5 * time.Second,
		MaxRetries:   3,
		BaseBackoff:  100 * time.Millisecond,
	}

	queue, err := NewQueue(ctx, config)
	require.NoError(t, err)
	defer queue.Close()

	// Send 3 low priority messages
	for i := 0; i < 3; i++ {
		msg := types.Msg{
			ID:       uuid.New().String(),
			Priority: types.PriorityLow,
			Event:    createTestEvent(t, "system"),
		}
		result := queue.Enqueue(msg)
		assert.Equal(t, types.ErrCodeSuccess, result)
	}

	// Wait for processing
	time.Sleep(100 * time.Millisecond)

	batches := mockTransport.GetBatches()
	assert.Len(t, batches, 3, "Should have 3 batches (each message processed immediately)")
	for _, batch := range batches {
		assert.Len(t, batch, 1, "Each batch should contain 1 message")
	}
}

func TestQueueRetryLogic(t *testing.T) {
	ctx := context.Background()
	mockTransport := &MockTransport{
		pushError:   errors.New("transport error"),
		maxFailures: 2, // Fail twice, then succeed
	}

	config := types.Config{
		Transport:    mockTransport,
		BatchTimeout: 100 * time.Millisecond,
		SendTimeout:  5 * time.Second,
		MaxRetries:   3,
		BaseBackoff:  10 * time.Millisecond, // Fast backoff for testing
	}

	queue, err := NewQueue(ctx, config)
	require.NoError(t, err)
	defer queue.Close()

	// Send a high priority message
	msg := types.Msg{
		ID:       uuid.New().String(),
		Priority: types.PriorityHigh,
		Event:    createTestEvent(t, "system"),
	}

	result := queue.Enqueue(msg)
	assert.Equal(t, types.ErrCodeSuccess, result)

	// Wait for processing and retries
	time.Sleep(500 * time.Millisecond)

	// Should have made 3 calls (2 failures + 1 success)
	assert.Equal(t, 3, mockTransport.GetCallCount())

	// Should have successfully sent 1 batch
	batches := mockTransport.GetBatches()
	assert.Len(t, batches, 1)
}

func TestQueueMaxRetriesExceeded(t *testing.T) {
	ctx := context.Background()
	mockTransport := &MockTransport{
		pushError:   errors.New("persistent transport error"),
		maxFailures: 10, // Always fail
	}

	config := types.Config{
		Transport:    mockTransport,
		BatchTimeout: 100 * time.Millisecond,
		SendTimeout:  5 * time.Second,
		MaxRetries:   2,
		BaseBackoff:  10 * time.Millisecond, // Fast backoff for testing
	}

	queue, err := NewQueue(ctx, config)
	require.NoError(t, err)
	defer queue.Close()

	// Send a high priority message
	msg := types.Msg{
		ID:       uuid.New().String(),
		Priority: types.PriorityHigh,
		Event:    createTestEvent(t, "system"),
	}

	result := queue.Enqueue(msg)
	assert.Equal(t, types.ErrCodeSuccess, result)

	// Wait for processing and retries
	time.Sleep(300 * time.Millisecond)

	// Should have made 3 calls (initial + 2 retries)
	assert.Equal(t, 3, mockTransport.GetCallCount())

	// Should have no successful batches
	batches := mockTransport.GetBatches()
	assert.Len(t, batches, 0)
}

func TestQueueHighPriorityImmediate(t *testing.T) {
	ctx := context.Background()
	mockTransport := &MockTransport{}

	config := types.Config{
		Transport:    mockTransport,
		BatchTimeout: 1 * time.Second, // Long timeout to ensure immediate processing
		SendTimeout:  5 * time.Second,
		MaxRetries:   3,
		BaseBackoff:  100 * time.Millisecond,
	}

	queue, err := NewQueue(ctx, config)
	require.NoError(t, err)
	defer queue.Close()

	// Send a high priority message
	msg := types.Msg{
		ID:       uuid.New().String(),
		Priority: types.PriorityHigh,
		Event:    createTestEvent(t, "system"),
	}

	result := queue.Enqueue(msg)
	assert.Equal(t, types.ErrCodeSuccess, result)

	// Wait minimal time for immediate processing
	time.Sleep(50 * time.Millisecond)

	batches := mockTransport.GetBatches()
	assert.Len(t, batches, 1, "High priority message should be processed immediately")
	assert.Len(t, batches[0], 1, "Should contain 1 message")
	assert.Equal(t, types.PriorityHigh, batches[0][0].Priority)
}

func TestResetTimer(t *testing.T) {
	timer := time.NewTimer(100 * time.Millisecond)
	defer timer.Stop()

	// Wait for timer to expire
	<-timer.C

	// Reset the timer
	resetTimer(timer, 50*time.Millisecond)

	// Timer should fire again after reset
	select {
	case <-timer.C:
		// Expected
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Timer did not fire after reset")
	}
}

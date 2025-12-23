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
	"sync"
	"time"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/google/uuid"

	"github.com/isovalent/hubble-fgs/pkg/timescape/types"

	systemstatus "github.com/isovalent/ipa/system_status/v1alpha"
)

// contextKey is a custom type for context keys to avoid collisions
type contextKey string

const (
	priorityKey contextKey = "priority"
)

// Queue implements the Client interface with 2-queue priority-based processing
type Queue struct {
	cfg       types.Config
	transport types.Transport
	ctx       context.Context
	cancel    context.CancelFunc

	// Two buffered queues for priority separation
	highCh chan types.Msg // High priority - immediate processing (buffered)
	lowCh  chan types.Msg // Low priority - batched processing (buffered)

	wg sync.WaitGroup
}

// NewQueue creates a new timescape client with the given configuration
func NewQueue(ctx context.Context, cfg types.Config) (*Queue, error) {
	queueCtx, cancel := context.WithCancel(ctx)
	q := &Queue{
		cfg:       cfg,
		transport: cfg.Transport,
		ctx:       queueCtx,
		cancel:    cancel,
		highCh:    make(chan types.Msg, 10), // Buffered high priority channel (10 messages)
		lowCh:     make(chan types.Msg, 50), // Buffered low priority channel (50 messages)
	}

	q.start()
	return q, nil
}

// Close gracefully shuts down the client
func (q *Queue) Close() error {
	q.cancel()
	q.wg.Wait()
	logger.GetLogger().Info("timescape client shut down gracefully")
	return nil
}

// Send queues an event for delivery to timescape with specified priority
func (q *Queue) Send(_ context.Context, event *systemstatus.SystemStatusEvent, priority types.Priority) types.ErrorCode {
	msg := types.Msg{
		ID:       uuid.New().String(),
		Priority: priority,
		Event:    event,
	}
	return q.Enqueue(msg)
}

// Enqueue adds a message to the appropriate priority queue
// Returns immediately with an error code if the worker is busy, providing backpressure
// instead of blocking the caller indefinitely. Callers should handle ErrCodeQueueBusy
// by implementing retry logic, dropping messages, or applying rate limiting.
func (q *Queue) Enqueue(m types.Msg) types.ErrorCode {
	// Check if context is already cancelled before attempting to send
	select {
	case <-q.ctx.Done():
		logger.GetLogger().Info("timescape Enqueue: client is shutting down")
		return types.ErrCodeShuttingDown
	default:
	}

	ch := q.channelFor(m.Priority)
	select {
	case ch <- m:
		return types.ErrCodeSuccess
	case <-q.ctx.Done():
		logger.GetLogger().Info("timescape Enqueue: client is shutting down")
		return types.ErrCodeShuttingDown
	default:
		// Non-blocking: return error code immediately if worker is not ready
		// This provides backpressure to prevent memory buildup and allows
		// callers to implement their own flow control strategies
		logger.GetLogger().Info("timescape Enqueue: queue busy", "messageID", m.ID, "priority", m.Priority)
		return types.ErrCodeQueueBusy
	}
}

// channelFor routes messages to appropriate queue based on priority
func (q *Queue) channelFor(p types.Priority) chan types.Msg {
	if p == types.PriorityHigh {
		return q.highCh
	}
	// Medium and Low priorities go to the same queue
	return q.lowCh
}

// start launches the worker goroutines for processing the queues
func (q *Queue) start() {
	// Start high priority worker (immediate processing)
	q.wg.Add(1)
	go func() {
		defer q.wg.Done()
		q.highPriorityWorker()
	}()

	// Start low priority worker (batched processing)
	q.wg.Add(1)
	go func() {
		defer q.wg.Done()
		q.lowPriorityWorker()
	}()
}

// highPriorityWorker processes high priority messages immediately
func (q *Queue) highPriorityWorker() {
	for {
		select {
		case <-q.ctx.Done():
			return
		case msg := <-q.highCh:
			// Process immediately - no batching for high priority
			batch := []types.Msg{msg}
			q.flushBatch(q.ctx, types.PriorityHigh, batch)
		}
	}
}

// lowPriorityWorker processes low priority messages with batching
func (q *Queue) lowPriorityWorker() {
	batch := make([]types.Msg, 0, q.cfg.MaxBatchSize)
	timer := time.NewTimer(q.cfg.BatchTimeout)
	defer timer.Stop()

	for {
		select {
		case <-q.ctx.Done():
			// Flush remaining batch before shutting down
			if len(batch) > 0 {
				q.flushBatch(q.ctx, types.PriorityLow, batch)
			}
			return

		case msg := <-q.lowCh:
			batch = append(batch, msg)
			if len(batch) >= q.cfg.MaxBatchSize {
				q.flushBatch(q.ctx, msg.Priority, batch)
				batch = batch[:0]
				resetTimer(timer, q.cfg.BatchTimeout)
			}

		case <-timer.C:
			if len(batch) > 0 {
				// Use the priority of the first message in batch
				priority := types.PriorityLow
				if len(batch) > 0 {
					priority = batch[0].Priority
				}
				q.flushBatch(q.ctx, priority, batch)
				batch = batch[:0]
			}
			resetTimer(timer, q.cfg.BatchTimeout)
		}
	}
}

// resetTimer safely resets a timer to the given duration
func resetTimer(t *time.Timer, d time.Duration) {
	// Safely stop the timer first
	if !t.Stop() {
		// Timer already expired, drain the channel
		select {
		case <-t.C:
		default:
		}
	}
	// Safe reset - timer is properly stopped and drained
	t.Reset(d)
}

func (q *Queue) flushBatch(ctx context.Context, p types.Priority, batch []types.Msg) {
	if len(batch) == 0 {
		return
	}

	ctx = context.WithValue(ctx, priorityKey, p)
	ctx, cancel := context.WithTimeout(ctx, q.cfg.SendTimeout)
	defer cancel()

	// Implement exponential backoff retry
	retries := 0
	for {
		err := q.transport.PushBatch(ctx, batch)
		if err == nil {
			logger.GetLogger().Debug("timescape: batch sent successfully", "priority", p)
			return
		}

		retries++
		if retries > q.cfg.MaxRetries {
			logger.GetLogger().Error("timescape: failed to send batch after max retries. Drop", "error", err, "priority", p, "retries", retries)
			return
		}

		// Exponential backoff: 2^retries * baseDelay (100ms, 200ms, 400ms, 800ms...)
		backoff := time.Duration(1<<(retries-1)) * q.cfg.BaseBackoff
		logger.GetLogger().Warn("timescape: retrying batch send", "error", err, "priority", p, "retry", retries, "backoff", backoff)

		select {
		case <-ctx.Done():
			logger.GetLogger().Error("timescape: Context cancelled during retry backoff", "priority", p)
			return
		case <-time.After(backoff):
			// Continue to next retry
		}
	}
}

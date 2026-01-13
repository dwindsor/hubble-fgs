// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package smartqueue

import (
	"context"
	"sync"
	"time"
)

// New creates a new SmartQueue with the given configuration
func New[T any](ctx context.Context, config Config[T]) *SmartQueue[T] {
	config = config.validate()

	return &SmartQueue[T]{
		ctx:     ctx,
		config:  config,
		queue:   make(chan T, config.MaxSize),
		batchCh: make(chan []T, config.WorkerCount*2),
		stopCh:  make(chan struct{}),
		flushCh: make(chan struct{}, 1),
	}
}

// SmartQueue is a thread-safe queue with batching and periodic flush capabilities
type SmartQueue[T any] struct {
	ctx    context.Context
	config Config[T]

	queue   chan T
	batchCh chan []T

	mu        sync.RWMutex
	running   bool
	stopped   bool
	runCtx    context.Context
	runCancel context.CancelFunc

	wg      sync.WaitGroup
	stopCh  chan struct{}
	flushCh chan struct{}
}

// Start begins processing the queue with worker goroutines.
// Can be called after Stop() to restart the queue.
func (sq *SmartQueue[T]) Start() {
	sq.mu.Lock()
	if sq.running {
		sq.mu.Unlock()
		return
	}
	if sq.stopped {
		// Reset for restart - recreate closed channels
		sq.stopped = false
		sq.stopCh = make(chan struct{})
		sq.batchCh = make(chan []T, sq.config.WorkerCount*2)
	}
	// Create a child context for this run cycle that will be cancelled on Stop()
	sq.runCtx, sq.runCancel = context.WithCancel(sq.ctx)
	sq.running = true
	sq.mu.Unlock()

	// Start worker goroutines for handling callbacks
	for i := 0; i < sq.config.WorkerCount; i++ {
		sq.wg.Add(1)
		go sq.worker()
	}

	// Start the batch collector goroutine
	sq.wg.Add(1)
	go sq.batchCollector()
}

// Stop gracefully stops the queue and flushes remaining items.
// After Stop() returns, Start() can be called to restart the queue.
//
// The lock is held during the entire stop operation (including waiting for
// goroutines).  A timeout prevents indefinite blocking if goroutines fail to exit.
func (sq *SmartQueue[T]) Stop() {
	sq.mu.Lock()
	defer sq.mu.Unlock()

	if sq.stopped || !sq.running {
		return
	}
	sq.stopped = true
	sq.running = false

	close(sq.stopCh)

	// Wait for goroutines with timeout to avoid holding lock forever
	done := make(chan struct{})
	go func() {
		sq.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Goroutines exited cleanly
	case <-time.After(30 * time.Second):
		// Timeout - goroutines may still be running. Reset the WaitGroup so
		// Start() can safely be called. Orphaned goroutines will eventually
		// call Done() on the old WaitGroup (captured by the goroutine above),
		// which is harmless since we no longer reference it.
		sq.wg = sync.WaitGroup{}
	}

	// Cancel the run context to signal callbacks and workers to stop
	if sq.runCancel != nil {
		sq.runCancel()
	}
}

// IsStopped returns true if the queue has been stopped
func (sq *SmartQueue[T]) IsStopped() bool {
	sq.mu.RLock()
	defer sq.mu.RUnlock()
	return sq.stopped
}

// Enqueue adds an item to the queue. Returns false if queue is full after timeout.
// If EnqueueTimeout is 0, returns immediately if queue is full (non-blocking).
func (sq *SmartQueue[T]) Enqueue(ctx context.Context, item T) bool {
	sq.mu.RLock()
	if sq.stopped {
		sq.mu.RUnlock()
		return false
	}
	sq.mu.RUnlock()

	// No timeout (0) - non-blocking, fail immediately if queue is full
	if sq.config.EnqueueTimeout == 0 {
		select {
		case sq.queue <- item:
			sq.triggerFlushCheck()
			return true
		case <-ctx.Done():
			return false
		case <-sq.stopCh:
			return false
		default:
			return false
		}
	}

	// With timeout - block until timeout expires
	timer := time.NewTimer(sq.config.EnqueueTimeout)
	defer timer.Stop()

	select {
	case sq.queue <- item:
		sq.triggerFlushCheck()
		return true
	case <-timer.C:
		return false
	case <-ctx.Done():
		return false
	case <-sq.stopCh:
		return false
	}
}

// EnqueueBatch adds multiple items to the queue. Returns the number of items successfully enqueued.
func (sq *SmartQueue[T]) EnqueueBatch(ctx context.Context, items []T) int {
	count := 0
	for _, item := range items {
		if sq.Enqueue(ctx, item) {
			count++
		} else {
			break
		}
	}
	return count
}

// Len returns the current number of items in the queue
func (sq *SmartQueue[T]) Len() int {
	return len(sq.queue)
}

// triggerFlushCheck signals the batch collector to check if a flush is needed
func (sq *SmartQueue[T]) triggerFlushCheck() {
	select {
	case sq.flushCh <- struct{}{}:
	default:
	}
}

// batchCollector collects items from the queue and sends batches to workers
func (sq *SmartQueue[T]) batchCollector() {
	defer sq.wg.Done()
	defer close(sq.batchCh)

	// If FlushInterval is 0, no periodic flush - only flush on batch size
	if sq.config.FlushInterval == 0 {
		for {
			select {
			case <-sq.stopCh:
				sq.flushRemaining()
				return
			case <-sq.flushCh:
				if len(sq.queue) >= sq.config.BatchSize {
					sq.flushBatch()
				}
			}
		}
	}

	// With periodic flush
	ticker := time.NewTicker(sq.config.FlushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-sq.stopCh:
			sq.flushRemaining()
			return
		case <-ticker.C:
			sq.flushBatch()
		case <-sq.flushCh:
			if len(sq.queue) >= sq.config.BatchSize {
				sq.flushBatch()
			}
		}
	}
}

// flushBatch collects up to BatchSize items and sends them to workers
func (sq *SmartQueue[T]) flushBatch() {
	batch := sq.collectBatch(sq.config.BatchSize)
	if len(batch) > 0 {
		sq.batchCh <- batch
	}
}

// flushRemaining flushes all remaining items in the queue
func (sq *SmartQueue[T]) flushRemaining() {
	for {
		batch := sq.collectBatch(sq.config.BatchSize)
		if len(batch) == 0 {
			break
		}
		sq.batchCh <- batch
	}
}

// collectBatch collects up to maxItems from the queue
func (sq *SmartQueue[T]) collectBatch(maxItems int) []T {
	batch := make([]T, 0, maxItems)
	for i := 0; i < maxItems; i++ {
		select {
		case item, ok := <-sq.queue:
			if !ok {
				return batch
			}
			batch = append(batch, item)
		default:
			return batch
		}
	}
	return batch
}

// worker processes batches from the batch channel
func (sq *SmartQueue[T]) worker() {
	defer sq.wg.Done()

	for batch := range sq.batchCh {
		if sq.config.Callback != nil && len(batch) > 0 {
			sq.config.Callback(sq.runCtx, batch)
		}
	}
}

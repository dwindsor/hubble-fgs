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
	"time"
)

// Default configuration values
const (
	DefaultMaxSize        = 128
	DefaultBatchSize      = 64
	DefaultFlushInterval  = 0 * time.Second // 0 means no periodic flush, only flush on batch size
	DefaultEnqueueTimeout = 0 * time.Second // 0 means non-blocking
	DefaultWorkerCount    = 1
)

// CallbackFunc is the function type called when batch is ready
type CallbackFunc[T any] func(context.Context, []T)

// Queue defines the interface for a smart queue
type Queue[T any] interface {
	// Enqueue adds an item to the queue. Returns false if queue is full after timeout.
	Enqueue(context.Context, T) bool
	// EnqueueBatch adds multiple items to the queue. Returns the number of items successfully enqueued.
	EnqueueBatch(context.Context, []T) int
	// Len returns the current number of items in the queue
	Len() int
	// Start begins processing the queue
	Start()
	// Stop gracefully stops the queue, flushing remaining items
	Stop()
	// IsStopped returns true if the queue has been stopped
	IsStopped() bool
}

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

import "time"

// Config holds the configuration for SmartQueue
type Config[T any] struct {
	// MaxSize is the maximum capacity of the queue
	MaxSize int
	// BatchSize is the threshold at which callback is triggered
	BatchSize int
	// FlushInterval is the time interval for periodic flush
	FlushInterval time.Duration
	// EnqueueTimeout is the timeout for enqueue when queue is full
	EnqueueTimeout time.Duration
	// WorkerCount is the number of worker goroutines for callbacks
	WorkerCount int
	// Callback is the function called with batched items
	Callback CallbackFunc[T]
}

// validate applies defaults to invalid configuration values and returns the validated config
func (c Config[T]) validate() Config[T] {
	if c.MaxSize <= 0 {
		c.MaxSize = DefaultMaxSize
	}
	if c.BatchSize <= 0 {
		c.BatchSize = DefaultBatchSize
	}
	if c.BatchSize > c.MaxSize {
		c.BatchSize = c.MaxSize
	}
	if c.FlushInterval < 0 {
		c.FlushInterval = DefaultFlushInterval
	}
	if c.EnqueueTimeout < 0 {
		c.EnqueueTimeout = DefaultEnqueueTimeout
	}
	if c.WorkerCount <= 0 {
		c.WorkerCount = DefaultWorkerCount
	}
	return c
}

// DefaultConfig returns a Config with default values
func DefaultConfig[T any](callback CallbackFunc[T]) Config[T] {
	return Config[T]{
		MaxSize:        DefaultMaxSize,
		BatchSize:      DefaultBatchSize,
		FlushInterval:  DefaultFlushInterval,
		EnqueueTimeout: DefaultEnqueueTimeout,
		WorkerCount:    DefaultWorkerCount,
		Callback:       callback,
	}
}

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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNew_DefaultValues(t *testing.T) {
	callback := func(_ context.Context, _ []int) {}
	sq := New(context.Background(), Config[int]{Callback: callback})

	assert.Equal(t, DefaultMaxSize, sq.config.MaxSize)
	assert.Equal(t, DefaultBatchSize, sq.config.BatchSize)
	assert.Equal(t, DefaultFlushInterval, sq.config.FlushInterval)
	assert.Equal(t, DefaultEnqueueTimeout, sq.config.EnqueueTimeout)
	assert.Equal(t, DefaultWorkerCount, sq.config.WorkerCount)
}

func TestNew_CustomValues(t *testing.T) {
	callback := func(_ context.Context, _ []int) {}
	config := Config[int]{
		MaxSize:        500,
		BatchSize:      50,
		FlushInterval:  10 * time.Second,
		EnqueueTimeout: 2 * time.Second,
		WorkerCount:    4,
		Callback:       callback,
	}
	sq := New(context.Background(), config)

	assert.Equal(t, 500, sq.config.MaxSize)
	assert.Equal(t, 50, sq.config.BatchSize)
	assert.Equal(t, 10*time.Second, sq.config.FlushInterval)
	assert.Equal(t, 2*time.Second, sq.config.EnqueueTimeout)
	assert.Equal(t, 4, sq.config.WorkerCount)
}

func TestNew_BatchSizeExceedsMaxSize(t *testing.T) {
	callback := func(_ context.Context, _ []int) {}
	config := Config[int]{
		MaxSize:   100,
		BatchSize: 200,
		Callback:  callback,
	}
	sq := New(context.Background(), config)

	assert.Equal(t, 100, sq.config.BatchSize, "BatchSize should be capped at MaxSize")
}

func TestDefaultConfig(t *testing.T) {
	callback := func(_ context.Context, _ []string) {}
	config := DefaultConfig(callback)

	assert.Equal(t, DefaultMaxSize, config.MaxSize)
	assert.Equal(t, DefaultBatchSize, config.BatchSize)
	assert.Equal(t, DefaultFlushInterval, config.FlushInterval)
	assert.Equal(t, DefaultEnqueueTimeout, config.EnqueueTimeout)
	assert.Equal(t, DefaultWorkerCount, config.WorkerCount)
	assert.NotNil(t, config.Callback)
}

func TestConfigValidate(t *testing.T) {
	t.Run("negative values get defaults", func(t *testing.T) {
		config := Config[int]{
			MaxSize:        -1,
			BatchSize:      -1,
			FlushInterval:  -1,
			EnqueueTimeout: -1,
			WorkerCount:    -1,
		}
		validated := config.validate()

		assert.Equal(t, DefaultMaxSize, validated.MaxSize)
		assert.Equal(t, DefaultBatchSize, validated.BatchSize)
		assert.Equal(t, DefaultFlushInterval, validated.FlushInterval)
		assert.Equal(t, DefaultEnqueueTimeout, validated.EnqueueTimeout)
		assert.Equal(t, DefaultWorkerCount, validated.WorkerCount)
	})

	t.Run("zero values get defaults except FlushInterval and EnqueueTimeout", func(t *testing.T) {
		config := Config[int]{}
		validated := config.validate()

		assert.Equal(t, DefaultMaxSize, validated.MaxSize)
		assert.Equal(t, DefaultBatchSize, validated.BatchSize)
		assert.Equal(t, time.Duration(0), validated.FlushInterval, "FlushInterval 0 is valid (no periodic flush)")
		assert.Equal(t, time.Duration(0), validated.EnqueueTimeout, "EnqueueTimeout 0 is valid (non-blocking)")
		assert.Equal(t, DefaultWorkerCount, validated.WorkerCount)
	})

	t.Run("zero FlushInterval is preserved", func(t *testing.T) {
		config := Config[int]{
			MaxSize:       100,
			BatchSize:     10,
			FlushInterval: 0,
			WorkerCount:   1,
		}
		validated := config.validate()

		assert.Equal(t, time.Duration(0), validated.FlushInterval, "FlushInterval 0 should be preserved")
	})

	t.Run("zero EnqueueTimeout is preserved", func(t *testing.T) {
		config := Config[int]{
			MaxSize:        100,
			BatchSize:      10,
			FlushInterval:  time.Second,
			EnqueueTimeout: 0,
			WorkerCount:    1,
		}
		validated := config.validate()

		assert.Equal(t, time.Duration(0), validated.EnqueueTimeout, "EnqueueTimeout 0 should be preserved")
	})

	t.Run("valid values preserved", func(t *testing.T) {
		config := Config[int]{
			MaxSize:        500,
			BatchSize:      50,
			FlushInterval:  10 * time.Second,
			EnqueueTimeout: 2 * time.Second,
			WorkerCount:    4,
		}
		validated := config.validate()

		assert.Equal(t, 500, validated.MaxSize)
		assert.Equal(t, 50, validated.BatchSize)
		assert.Equal(t, 10*time.Second, validated.FlushInterval)
		assert.Equal(t, 2*time.Second, validated.EnqueueTimeout)
		assert.Equal(t, 4, validated.WorkerCount)
	})

	t.Run("batch size capped at max size", func(t *testing.T) {
		config := Config[int]{
			MaxSize:   100,
			BatchSize: 200,
		}
		validated := config.validate()

		assert.Equal(t, 100, validated.BatchSize)
	})
}

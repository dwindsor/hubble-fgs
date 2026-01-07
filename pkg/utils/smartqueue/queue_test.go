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
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestEnqueue_Success(t *testing.T) {
	callback := func(_ []int) {}
	sq := New(Config[int]{
		MaxSize:        10,
		BatchSize:      5,
		FlushInterval:  time.Hour,
		EnqueueTimeout: time.Second,
		Callback:       callback,
	})
	sq.Start()
	defer sq.Stop()

	ctx := context.Background()
	ok := sq.Enqueue(ctx, 42)

	assert.True(t, ok)
	assert.Equal(t, 1, sq.Len())
}

func TestEnqueue_QueueFull_Timeout(t *testing.T) {
	// Use a blocking callback to prevent queue from being drained
	blockCh := make(chan struct{})
	callback := func(_ []int) {
		<-blockCh
	}
	sq := New(Config[int]{
		MaxSize:        2,
		BatchSize:      10,
		FlushInterval:  time.Hour,
		EnqueueTimeout: 50 * time.Millisecond,
		Callback:       callback,
	})
	// Don't start the queue - this way items won't be drained
	// We can still enqueue to the channel directly

	ctx := context.Background()
	// Fill the queue without starting (channel still works)
	sq.queue <- 1
	sq.queue <- 2

	start := time.Now()
	ok := sq.Enqueue(ctx, 3)
	elapsed := time.Since(start)

	assert.False(t, ok, "Enqueue should fail when queue is full")
	assert.GreaterOrEqual(t, elapsed, 50*time.Millisecond, "Should wait for timeout")
	close(blockCh)
}

func TestEnqueue_ContextCanceled(t *testing.T) {
	callback := func(_ []int) {}
	sq := New(Config[int]{
		MaxSize:        2,
		BatchSize:      10,
		FlushInterval:  time.Hour,
		EnqueueTimeout: time.Second,
		Callback:       callback,
	})
	// Don't start - fill queue directly
	sq.queue <- 1
	sq.queue <- 2

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	ok := sq.Enqueue(ctx, 3)
	elapsed := time.Since(start)

	assert.False(t, ok, "Enqueue should fail when context is canceled")
	assert.Less(t, elapsed, 500*time.Millisecond, "Should return quickly after cancel")
}

func TestEnqueue_AfterStop(t *testing.T) {
	callback := func(_ []int) {}
	sq := New(Config[int]{
		MaxSize:        10,
		BatchSize:      5,
		FlushInterval:  time.Hour,
		EnqueueTimeout: time.Second,
		Callback:       callback,
	})
	sq.Start()
	sq.Stop()

	ctx := context.Background()
	ok := sq.Enqueue(ctx, 42)

	assert.False(t, ok, "Enqueue should fail after Stop")
}

func TestEnqueueBatch(t *testing.T) {
	callback := func(_ []int) {}
	sq := New(Config[int]{
		MaxSize:        5,
		BatchSize:      10,
		FlushInterval:  time.Hour,
		EnqueueTimeout: 50 * time.Millisecond,
		Callback:       callback,
	})
	// Don't start - test raw enqueue behavior

	ctx := context.Background()
	items := []int{1, 2, 3, 4, 5, 6, 7}
	count := sq.EnqueueBatch(ctx, items)

	assert.Equal(t, 5, count, "Should enqueue up to MaxSize items")
	assert.Equal(t, 5, sq.Len())
}

func TestBatchCallback_ThresholdReached(t *testing.T) {
	var received []int
	var mu sync.Mutex
	done := make(chan struct{})

	callback := func(items []int) {
		mu.Lock()
		received = append(received, items...)
		mu.Unlock()
		if len(received) >= 5 {
			close(done)
		}
	}

	sq := New(Config[int]{
		MaxSize:        100,
		BatchSize:      5,
		FlushInterval:  time.Hour,
		EnqueueTimeout: time.Second,
		Callback:       callback,
	})
	sq.Start()
	defer sq.Stop()

	ctx := context.Background()
	for i := 1; i <= 5; i++ {
		sq.Enqueue(ctx, i)
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Callback was not triggered within timeout")
	}

	mu.Lock()
	assert.Equal(t, []int{1, 2, 3, 4, 5}, received)
	mu.Unlock()
}

func TestBatchCallback_PeriodicFlush(t *testing.T) {
	var received []int
	var mu sync.Mutex
	done := make(chan struct{})

	callback := func(items []int) {
		mu.Lock()
		received = append(received, items...)
		mu.Unlock()
		close(done)
	}

	sq := New(Config[int]{
		MaxSize:        100,
		BatchSize:      10,
		FlushInterval:  100 * time.Millisecond,
		EnqueueTimeout: time.Second,
		Callback:       callback,
	})
	sq.Start()
	defer sq.Stop()

	ctx := context.Background()
	sq.Enqueue(ctx, 1)
	sq.Enqueue(ctx, 2)
	sq.Enqueue(ctx, 3)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Periodic flush was not triggered within timeout")
	}

	mu.Lock()
	assert.Equal(t, []int{1, 2, 3}, received)
	mu.Unlock()
}

func TestStop_FlushesRemaining(t *testing.T) {
	var received []int
	var mu sync.Mutex

	callback := func(items []int) {
		mu.Lock()
		received = append(received, items...)
		mu.Unlock()
	}

	sq := New(Config[int]{
		MaxSize:        100,
		BatchSize:      100,
		FlushInterval:  time.Hour,
		EnqueueTimeout: time.Second,
		Callback:       callback,
	})
	sq.Start()

	ctx := context.Background()
	for i := 1; i <= 10; i++ {
		sq.Enqueue(ctx, i)
	}

	sq.Stop()

	mu.Lock()
	assert.Len(t, received, 10, "All items should be flushed on Stop")
	mu.Unlock()
}

func TestMultipleWorkers(t *testing.T) {
	var totalItems atomic.Int32
	done := make(chan struct{})

	callback := func(items []int) {
		if totalItems.Add(int32(len(items))) >= 10 {
			select {
			case <-done:
			default:
				close(done)
			}
		}
	}

	sq := New(Config[int]{
		MaxSize:        100,
		BatchSize:      2,
		FlushInterval:  50 * time.Millisecond,
		EnqueueTimeout: time.Second,
		WorkerCount:    4,
		Callback:       callback,
	})
	sq.Start()
	defer sq.Stop()

	ctx := context.Background()
	for i := 0; i < 10; i++ {
		sq.Enqueue(ctx, i)
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Not all items were processed within timeout")
	}

	assert.GreaterOrEqual(t, totalItems.Load(), int32(10))
}

func TestConcurrentEnqueue(t *testing.T) {
	var received []int
	var mu sync.Mutex

	callback := func(items []int) {
		mu.Lock()
		received = append(received, items...)
		mu.Unlock()
	}

	sq := New(Config[int]{
		MaxSize:        1000,
		BatchSize:      50,
		FlushInterval:  50 * time.Millisecond,
		EnqueueTimeout: time.Second,
		WorkerCount:    4,
		Callback:       callback,
	})
	sq.Start()

	ctx := context.Background()
	var wg sync.WaitGroup
	numGoroutines := 10
	itemsPerGoroutine := 100

	for g := 0; g < numGoroutines; g++ {
		wg.Add(1)
		go func(base int) {
			defer wg.Done()
			for i := 0; i < itemsPerGoroutine; i++ {
				sq.Enqueue(ctx, base*itemsPerGoroutine+i)
			}
		}(g)
	}

	wg.Wait()
	sq.Stop()

	mu.Lock()
	assert.Len(t, received, numGoroutines*itemsPerGoroutine, "All items should be received")
	mu.Unlock()
}

func TestIsStopped(t *testing.T) {
	callback := func(_ []int) {}
	sq := New(Config[int]{Callback: callback})

	assert.False(t, sq.IsStopped())

	sq.Start()
	assert.False(t, sq.IsStopped())

	sq.Stop()
	assert.True(t, sq.IsStopped())
}

func TestStop_Idempotent(t *testing.T) {
	callback := func(_ []int) {}
	sq := New(Config[int]{Callback: callback})
	sq.Start()

	sq.Stop()
	sq.Stop()
	sq.Stop()

	assert.True(t, sq.IsStopped())
}

func TestStart_AfterStop(t *testing.T) {
	var received []int
	var mu sync.Mutex
	done := make(chan struct{})

	callback := func(items []int) {
		mu.Lock()
		received = append(received, items...)
		if len(received) >= 2 {
			select {
			case <-done:
			default:
				close(done)
			}
		}
		mu.Unlock()
	}

	sq := New(Config[int]{
		MaxSize:        10,
		BatchSize:      2,
		FlushInterval:  time.Hour,
		EnqueueTimeout: time.Second,
		Callback:       callback,
	})

	// First run
	sq.Start()
	ctx := context.Background()
	sq.Enqueue(ctx, 1)
	sq.Enqueue(ctx, 2)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("First batch not processed")
	}

	sq.Stop()
	assert.True(t, sq.IsStopped())

	// Restart
	done = make(chan struct{})
	sq.Start()
	assert.False(t, sq.IsStopped(), "Queue should be running after restart")

	sq.Enqueue(ctx, 3)
	sq.Enqueue(ctx, 4)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Second batch not processed after restart")
	}

	mu.Lock()
	assert.Equal(t, []int{1, 2, 3, 4}, received)
	mu.Unlock()

	sq.Stop()
}

func TestGenericTypes(t *testing.T) {
	t.Run("string type", func(t *testing.T) {
		var received []string
		var mu sync.Mutex
		done := make(chan struct{})

		callback := func(items []string) {
			mu.Lock()
			received = append(received, items...)
			mu.Unlock()
			close(done)
		}

		sq := New(Config[string]{
			MaxSize:        10,
			BatchSize:      2,
			FlushInterval:  time.Hour,
			EnqueueTimeout: time.Second,
			Callback:       callback,
		})
		sq.Start()
		defer sq.Stop()

		ctx := context.Background()
		sq.Enqueue(ctx, "hello")
		sq.Enqueue(ctx, "world")

		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("Callback not triggered")
		}

		mu.Lock()
		assert.Equal(t, []string{"hello", "world"}, received)
		mu.Unlock()
	})

	t.Run("struct type", func(t *testing.T) {
		type Event struct {
			ID   int
			Name string
		}

		var received []Event
		var mu sync.Mutex
		done := make(chan struct{})

		callback := func(items []Event) {
			mu.Lock()
			received = append(received, items...)
			mu.Unlock()
			close(done)
		}

		sq := New(Config[Event]{
			MaxSize:        10,
			BatchSize:      2,
			FlushInterval:  time.Hour,
			EnqueueTimeout: time.Second,
			Callback:       callback,
		})
		sq.Start()
		defer sq.Stop()

		ctx := context.Background()
		sq.Enqueue(ctx, Event{ID: 1, Name: "first"})
		sq.Enqueue(ctx, Event{ID: 2, Name: "second"})

		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("Callback not triggered")
		}

		mu.Lock()
		assert.Equal(t, []Event{{ID: 1, Name: "first"}, {ID: 2, Name: "second"}}, received)
		mu.Unlock()
	})
}

func TestNilCallback(_ *testing.T) {
	sq := New(Config[int]{
		MaxSize:        10,
		BatchSize:      2,
		FlushInterval:  50 * time.Millisecond,
		EnqueueTimeout: time.Second,
		Callback:       nil,
	})
	sq.Start()

	ctx := context.Background()
	sq.Enqueue(ctx, 1)
	sq.Enqueue(ctx, 2)

	time.Sleep(100 * time.Millisecond)
	sq.Stop()
}

func TestLen(t *testing.T) {
	callback := func(_ []int) {}
	sq := New(Config[int]{
		MaxSize:        100,
		BatchSize:      100,
		FlushInterval:  time.Hour,
		EnqueueTimeout: time.Second,
		Callback:       callback,
	})
	sq.Start()
	defer sq.Stop()

	assert.Equal(t, 0, sq.Len())

	ctx := context.Background()
	sq.Enqueue(ctx, 1)
	assert.Equal(t, 1, sq.Len())

	sq.Enqueue(ctx, 2)
	sq.Enqueue(ctx, 3)
	assert.Equal(t, 3, sq.Len())
}

func TestQueueInterface(t *testing.T) {
	callback := func(_ []int) {}
	var q Queue[int] = New(Config[int]{Callback: callback})

	q.Start()
	defer q.Stop()

	ctx := context.Background()
	ok := q.Enqueue(ctx, 42)
	assert.True(t, ok)
	assert.Equal(t, 1, q.Len())
	assert.False(t, q.IsStopped())
}

func TestBatchSizeExactly(t *testing.T) {
	var totalItems atomic.Int32
	batchSizes := make([]int, 0)
	var mu sync.Mutex
	done := make(chan struct{})

	callback := func(items []int) {
		mu.Lock()
		batchSizes = append(batchSizes, len(items))
		mu.Unlock()
		if totalItems.Add(int32(len(items))) >= 10 {
			select {
			case <-done:
			default:
				close(done)
			}
		}
	}

	sq := New(Config[int]{
		MaxSize:        100,
		BatchSize:      5,
		FlushInterval:  50 * time.Millisecond,
		EnqueueTimeout: time.Second,
		Callback:       callback,
	})
	sq.Start()
	defer sq.Stop()

	ctx := context.Background()
	for i := 0; i < 10; i++ {
		sq.Enqueue(ctx, i)
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Not enough batches processed")
	}

	mu.Lock()
	for _, size := range batchSizes {
		assert.LessOrEqual(t, size, 5, "Batch size should not exceed BatchSize")
	}
	mu.Unlock()
}

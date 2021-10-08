//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.
//

package http

import (
	"github.com/isovalent/hubble-fgs/pkg/api"
	"github.com/isovalent/hubble-fgs/pkg/logger"
)

// http2FrameQueue implements in-order consumption of the HTTP/2
// header frames. Events may be potentially out-of-order due to the
// per-cpu perf arrays.
type http2FrameQueue struct {
	// Window into the next events, ordered by event counter.
	window []*api.MsgHttpEvent

	// The identifier of the next event that goes to 'head'
	next uint64

	// Current head position in the window, e.g. the event that
	// is going to have id 'next'.
	head int
}

func newHttp2FrameQueue(windowSize int) *http2FrameQueue {
	return &http2FrameQueue{
		window: make([]*api.MsgHttpEvent, windowSize),
		next:   0,
		head:   0,
	}
}

func (it *http2FrameQueue) reset(event *api.MsgHttpEvent) {
	it.next = event.Request.ReqId + 1
	it.head = 0
	it.window = make([]*api.MsgHttpEvent, len(it.window))
	it.window[0] = event
}

func (it *http2FrameQueue) push(event *api.MsgHttpEvent) {
	id := event.Request.ReqId

	if it.next == 0 {
		// This is the first event to arrive into the window.
		it.window[it.head] = event
		it.next = id
		//fmt.Printf("push %d, next=0 so pushing to head, head=%d, next=%d\n", id, it.head, it.next)
		return
	}

	// Difference to the current expected next event.
	diff := int(id - it.next)

	if id < it.next || diff >= len(it.window) {
		// It may happen that the fixed window is too small and events
		// are too much out of order. When this happens we'll log a message
		// here and reset the state. This can also happen if the initial
		// event that we push into the window is out of order.
		logger.GetLogger().Warnf("HTTP/2 frame too out of order (diff %d, max %d, received id %d, expected id %d). Dropping queued frames and carrying on",
			diff, len(it.window), id, it.next)
		it.reset(event)
		return
	}

	//fmt.Printf("diff: %d\n", diff)

	// Insert the event into the window.
	pos := (it.head + diff) % len(it.window)

	// Check the invariant that we never overwrite events.
	if it.window[pos] != nil {
		logger.GetLogger().Warnf("Impossible: frame_queue tried to overwrite existing frame. Resetting.")
		it.reset(event)
		return
	}
	it.window[pos] = event

	//fmt.Printf("push %d, pos=%d, head=%d\n", id, pos, it.head)
}

func (it *http2FrameQueue) pop() *api.MsgHttpEvent {
	event := it.window[it.head]
	if event == nil {
		// The head event hasn't arrived yet, so just return nil
		// and don't advance.
		return nil
	}

	// The head event exists, mark it consumed and advance.
	it.window[it.head] = nil
	it.head = (it.head + 1) % len(it.window)
	it.next++
	return event
}

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
	"github.com/cilium/tetragon/pkg/logger"
	api "github.com/isovalent/hubble-fgs/pkg/api/httpapi"
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

func newHttp2FrameQueue(windowSize int, nextId uint64) *http2FrameQueue {
	return &http2FrameQueue{
		window: make([]*api.MsgHttpEvent, windowSize),
		next:   nextId,
		head:   0,
	}
}

func (it *http2FrameQueue) reset(event *api.MsgHttpEvent) {
	it.next = event.Request.ReqId
	it.head = 0
	it.window = make([]*api.MsgHttpEvent, len(it.window))
	it.window[0] = event
}

func (it *http2FrameQueue) push(event *api.MsgHttpEvent) {
	id := event.Request.ReqId

	if id < it.next {
		// Initialization out of order as an older event received. Reset.
		logger.GetLogger().Warnf("HTTP/2 frame too old (%d < %d), resetting.", id, it.next)
		it.reset(event)
		return
	}

	// Difference to the expected next event. Used to position the new event into the window.
	diff := int(id - it.next)
	if diff >= len(it.window) {
		// It may happen that the fixed window is too small and events
		// are too much out of order. When this happens we'll log a message
		// here and reset the state. This can also happen if the initial
		// event that we push into the window is out of order.
		//
		// We try to recover from this by skipping over all the older missed events
		// and then trying again to insert this event into the window. If that fails,
		// then we reset the window.

		// Drain window until we hit an event.
		skipped := 0
		end := (it.head - 1) % len(it.window)
		for it.head != end && it.window[it.head] == nil {
			it.head = (it.head + 1) % len(it.window)
			it.next++
			skipped++
		}

		logger.GetLogger().Warnf("HTTP/2 frame too out of order (diff %d, max %d, received id %d, expected id %d). Skipping %d unseen events.",
			diff, len(it.window), id, it.next, skipped)

		// Check again if the event would fit
		diff = int(id - it.next)
		if diff >= len(it.window) {
			// Still not fitting into the window, just reset.
			logger.GetLogger().Warn("Frame still didn't fit into window after draining. Resetting.")
			it.reset(event)
			return
		}
	}

	// Insert the event into the window.
	pos := (it.head + diff) % len(it.window)

	// Verify the invariant that we never overwrite events.
	if it.window[pos] != nil {
		panic("Impossible: frame_queue tried to overwrite existing frame.")
	}
	it.window[pos] = event
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

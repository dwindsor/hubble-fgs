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
	"testing"

	"github.com/isovalent/hubble-fgs/pkg/api"
)

func makeEvent(reqId uint64) *api.MsgHttpEvent {
	return &api.MsgHttpEvent{
		Request: api.MsgHttp{ReqId: reqId},
	}

}

func withPermutations(xs []uint64, cb func([]uint64)) {
	var do func(i int)
	do = func(i int) {
		if i >= len(xs) {
			cb(xs)
			return
		}
		do(i + 1)
		for j := i + 1; j < len(xs); j++ {
			xs[i], xs[j] = xs[j], xs[i]
			do(i + 1)
			xs[i], xs[j] = xs[j], xs[i]
		}
	}
	do(0)
}

func TestFrameQueue(t *testing.T) {
	ids := []uint64{2, 3, 4, 5, 6}

	// Push initial event 1 and then test pushing and consuming
	// all permutations of [2 ... 10].
	withPermutations(append([]uint64{}, ids...), func(xs []uint64) {
		// Use a queue size that will wrap around, but is big enough to handle all permutations without
		// overflowing.
		q := newHttp2FrameQueue(len(ids), 1)

		q.push(makeEvent(1))
		e := q.pop()
		if e == nil {
			t.Error("initial element nil")
		}
		if e.Request.ReqId != 1 {
			t.Errorf("Initial element not 1, but %d", e.Request.ReqId)
		}

		pops := []uint64{}

		for _, x := range xs {
			q.push(makeEvent(x))

			for {
				e := q.pop()
				if e == nil {
					break
				}
				pops = append(pops, e.Request.ReqId)
			}
		}

		if len(pops) != len(ids) {
			t.Errorf("%d elements lost", len(ids)-len(pops))
		}

		for i, x := range pops {
			if x != ids[i] {
				t.Errorf("Expected %d, got %d", ids[i], x)
			}
		}

		if e := q.pop(); e != nil {
			t.Error("Expected nil")
		}
	})
}

func TestFrameQueueWrapAround(t *testing.T) {
	q := newHttp2FrameQueue(8, 1)
	i := uint64(0)

	checkPop := func(i uint64) {
		e := q.pop()
		if e == nil {
			t.Errorf("expected %d, not nil\n", i)
		}
		if e.Request.ReqId != i {
			t.Errorf("expected %d, got %d\n", i, e.Request.ReqId)
		}
	}

	// Test happy path with everything in order.
	for ; i < 1024; i++ {
		q.push(makeEvent(i))
		checkPop(i)
	}

	// Test with constantly misordered events
	for ; i < 2048; i += 2 {
		q.push(makeEvent(i + 1))
		e := q.pop()
		if e != nil {
			t.Errorf("expected nil, not %d\n", e.Request.ReqId)
		}

		q.push(makeEvent(i))
		checkPop(i)
		checkPop(i + 1)
	}
}

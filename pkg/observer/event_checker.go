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

package observer

import (
	"container/list"
	"fmt"
	"testing"

	"github.com/isovalent/hubble-fgs/api/v1/fgs"
)

// eventChecker checks a single event
type eventChecker interface {
	// check a single event.
	check(*fgs.GetEventsResponse, *testing.T) error
}

type eventCheckerMadeProgress struct {
	s string
}

func (e *eventCheckerMadeProgress) Error() string {
	return e.s
}

// eventCheckerFn is a wrapper that allows a function to be used as an eventChecker
type eventCheckerFn func(*fgs.GetEventsResponse, *testing.T) error

func (f eventCheckerFn) check(e *fgs.GetEventsResponse, t *testing.T) error {
	return f(e, t)
}

// countEventChecker wraps an event checker with counters
type countEventChecker struct {
	checker          eventChecker
	successes, total int
}

func (x *countEventChecker) check(ev *fgs.GetEventsResponse, t *testing.T) error {
	x.total++
	err := x.checker.check(ev, t)
	if err != nil {
		x.successes++
	}
	return err
}

// listEventChecker checks applies a list of checkers
type listEventChecker struct {
	checkers []eventChecker
	idx      int
}

func (cl *listEventChecker) check(ev *fgs.GetEventsResponse, t *testing.T) error {
	if cl.idx >= len(cl.checkers) {
		return nil
	}

	err := cl.checkers[cl.idx].check(ev, t)
	if err != nil {
		if e, ok := err.(*eventCheckerMadeProgress); ok {
			s := fmt.Sprintf("listEventChecker: %d/%d made progress: %s", cl.idx+1, len(cl.checkers), e.Error())
			return &eventCheckerMadeProgress{s}
		} else {
			return fmt.Errorf("listEventChecker: %d/%d failed: %w", cl.idx+1, len(cl.checkers), err)
		}
	}

	cl.idx += 1
	if cl.idx == len(cl.checkers) {
		t.Logf("listEventChecker: all %d checks succeeded", len(cl.checkers))
		return nil
	} else {
		s := fmt.Sprintf("listEventChecker: %d/%d matched", cl.idx, len(cl.checkers))
		return &eventCheckerMadeProgress{s}
	}

}

// checks that a list of events happen, in no particular order
type unorderedListEventChecker struct {
	checkers        *list.List
	total_ncheckers int
}

func newUnorderedListEventChecker(checkers ...eventChecker) *unorderedListEventChecker {
	l := list.New()
	for _, c := range checkers {
		l.PushBack(c)
	}

	return &unorderedListEventChecker{
		checkers:        l,
		total_ncheckers: len(checkers),
	}
}

func (cl *unorderedListEventChecker) check(ev *fgs.GetEventsResponse, t *testing.T) error {
	l := cl.checkers.Len()
	if l == 0 {
		return nil
	}

	t.Logf("unorderedListEventChecker: %d/%d checkers remain", l, cl.total_ncheckers)
	idx := 1
	for e := cl.checkers.Front(); e != nil; e = e.Next() {
		checker := e.Value.(eventChecker)
		err := checker.check(ev, t)
		if err == nil {
			t.Logf("unorderedListEventChecker: checking %d/%d: success", idx, l)
			cl.checkers.Remove(e)
			if clLen := cl.checkers.Len(); clLen > 0 {
				s := fmt.Sprintf("unorderedListEventChecker: %d (out of %d) matchers remaining", clLen, cl.total_ncheckers)
				return &eventCheckerMadeProgress{s}
			} else {
				return nil
			}
		}
		t.Logf("unorderedListEventChecker: checking %d/%d: failure: %s", idx, l, err)
		idx += 1
	}

	return fmt.Errorf("unorderedListEventChecker: all %d checks failed", cl.checkers.Len())
}

// chainEventChecker
//
// for example:
// newChainEventChecker().isListenEvent().hasCookie().match()
//
type chainEventChecker struct {
	chainCheck func(c interface{}, t *testing.T) (error, interface{})
}

func newChainEventChecker() chainEventChecker {
	return chainEventChecker{
		chainCheck: func(val interface{}, t *testing.T) (error, interface{}) {
			return nil, val
		},
	}
}

// match terminates the chain, and returns an eventChecker
func (x chainEventChecker) match() eventChecker {
	fn := func(ev *fgs.GetEventsResponse, t *testing.T) error {
		err, _ := x.chainCheck(ev, t)
		return err
	}

	return eventCheckerFn(fn)
}

func (x chainEventChecker) isListenEvent() chainEventChecker {

	fn := func(val interface{}, t *testing.T) (error, interface{}) {
		// boilerplate
		err, val := x.chainCheck(val, t)
		if err != nil {
			return err, val
		}

		fgsEv := val.(*fgs.GetEventsResponse)
		switch ev := fgsEv.Event.(type) {
		case *fgs.GetEventsResponse_ProcessListen:
			return nil, ev.ProcessListen
		default:
			return fmt.Errorf("not a listen FGS event (%T)", fgsEv.Event), val
		}
	}

	return chainEventChecker{
		chainCheck: fn,
	}
}

func (x chainEventChecker) isConnectEvent() chainEventChecker {

	fn := func(val interface{}, t *testing.T) (error, interface{}) {
		// boilerplate
		err, val := x.chainCheck(val, t)
		if err != nil {
			return err, val
		}

		fgsEv := val.(*fgs.GetEventsResponse)
		switch ev := fgsEv.Event.(type) {
		case *fgs.GetEventsResponse_ProcessConnect:
			return nil, ev.ProcessConnect
		default:
			return fmt.Errorf("not a connect FGS event (%T)", fgsEv.Event), fgsEv
		}
	}

	return chainEventChecker{
		chainCheck: fn,
	}
}

func (x chainEventChecker) isCloseEvent() chainEventChecker {

	fn := func(val interface{}, t *testing.T) (error, interface{}) {
		// boilerplate
		err, val := x.chainCheck(val, t)
		if err != nil {
			return err, val
		}

		fgsEv := val.(*fgs.GetEventsResponse)
		switch ev := fgsEv.Event.(type) {
		case *fgs.GetEventsResponse_ProcessClose:
			return nil, ev.ProcessClose
		default:
			return fmt.Errorf("not a close FGS event (%T)", fgsEv.Event), val
		}
	}

	return chainEventChecker{
		chainCheck: fn,
	}
}

func (x chainEventChecker) isAcceptEvent() chainEventChecker {

	fn := func(val interface{}, t *testing.T) (error, interface{}) {
		// boilerplate
		err, val := x.chainCheck(val, t)
		if err != nil {
			return err, val
		}

		fgsEv := val.(*fgs.GetEventsResponse)
		switch ev := fgsEv.Event.(type) {
		case *fgs.GetEventsResponse_ProcessAccept:
			return nil, ev.ProcessAccept
		default:
			return fmt.Errorf("not an accept FGS event (%T)", fgsEv.Event), val
		}
	}

	return chainEventChecker{
		chainCheck: fn,
	}
}

func (x chainEventChecker) hasCookie(cookie uint64) chainEventChecker {
	fn := func(val interface{}, t *testing.T) (error, interface{}) {
		// boilerplate
		err, val := x.chainCheck(val, t)
		if err != nil {
			return err, val
		}

		switch v := val.(type) {
		case *fgs.ProcessListen:
			if v.SockCookie == cookie {
				return nil, v
			} else {
				return fmt.Errorf("Expecting cookie %d but ProcessListen has %d", cookie, v.SockCookie), val
			}

		case *fgs.ProcessAccept:
			if v.SockCookie == cookie {
				return nil, v
			} else {
				return fmt.Errorf("Expecting cookie %d but ProcessAccept has %d", cookie, v.SockCookie), val
			}

		case *fgs.ProcessConnect:
			if v.SockCookie == cookie {
				return nil, v
			} else {
				return fmt.Errorf("Expecting cookie %d but ProcessConnect has %d", cookie, v.SockCookie), val
			}

		case *fgs.ProcessClose:
			if v.SockCookie == cookie {
				return nil, v
			} else {
				return fmt.Errorf("Expecting cookie %d but ProcessConnect has %d", cookie, v.SockCookie), val
			}

		default:
			return fmt.Errorf("type %T does not have cookie", v), val
		}
	}

	return chainEventChecker{
		chainCheck: fn,
	}
}

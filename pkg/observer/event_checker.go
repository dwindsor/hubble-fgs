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

	"github.com/isovalent/hubble-fgs/api/v1/fgs"
)

// CheckerLogger interface to be used in checkers
type CheckerLogger interface {
	Log(args ...interface{})
	Logf(format string, args ...interface{})
	Fatal(args ...interface{})
	Fatalf(format string, args ...interface{})
}

// ResponseChecker checks a single response
type ResponseChecker interface {
	// Check checks a single response.
	Check(*fgs.GetEventsResponse, CheckerLogger) error
}

// eventCheckerFn is a wrapper that allows a function to be used as an eventChecker
type ResponseCheckerFn func(*fgs.GetEventsResponse, CheckerLogger) error

// check implements ResponseChecker interface
func (f ResponseCheckerFn) Check(e *fgs.GetEventsResponse, log CheckerLogger) error {
	return f(e, log)
}

// ResponsesChecker is a stateful checker for checking a series of responses
type ResponsesChecker interface {
	// NextCheck checks a response and returns a boolean value indicating
	// whether the checker has concluded, and an error indicating whether the
	// check was successful. The boolean value allows short-circuting checks.
	//
	// Specifically:
	// (false,  nil): this response check was succesful, but need to check more events
	// (false, !nil): this response check not was succesful, but need to check more events
	// (true,   nil): checker was successful, no need to check more responses
	// (true,  !nil): checker failed, no need to check more responses
	NextCheck(*fgs.GetEventsResponse, CheckerLogger) (bool, error)

	// FinalCheck indicates that the sequence of events has ended, and asks
	// the checker to make a final decision.
	FinalCheck(CheckerLogger) error
}

type ResponsesCheckerFns struct {
	NextCheckFn  func(*fgs.GetEventsResponse, CheckerLogger) (bool, error)
	FinalCheckFn func(CheckerLogger) error
}

func (fns *ResponsesCheckerFns) NextCheck(r *fgs.GetEventsResponse, l CheckerLogger) (bool, error) {
	return fns.NextCheckFn(r, l)
}

func (fns *ResponsesCheckerFns) FinalCheck(l CheckerLogger) error {
	return fns.FinalCheckFn(l)
}

// OrderedResponsesChecker matches a list of ResponseCheckers over a sequence of responses
type OrderedResponsesChecker struct {
	checkers []ResponseChecker
	idx      int
}

// NewOrderedResponsesChecker retuns a new OrderedResponsesChecker
func NewOrderedResponsesChecker(checkers ...ResponseChecker) OrderedResponsesChecker {
	return OrderedResponsesChecker{
		checkers: checkers,
		idx:      0,
	}
}

func (c *OrderedResponsesChecker) NextCheck(r *fgs.GetEventsResponse, l CheckerLogger) (bool, error) {
	// all checkers have been verified
	if c.idx >= len(c.checkers) {
		return true, nil
	}

	err := c.checkers[c.idx].Check(r, l)
	if err != nil {
		return false, err
	}

	c.idx += 1
	if c.idx == len(c.checkers) {
		l.Logf("OrderedResponsesChecker: all %d checks succeeded", len(c.checkers))
		return true, nil
	} else {
		l.Logf("OrderedResponsesChecker: %d/%d matched", c.idx, len(c.checkers))
		return false, nil
	}
}

func (c *OrderedResponsesChecker) FinalCheck(l CheckerLogger) error {
	if c.idx >= len(c.checkers) {
		return nil
	}
	return fmt.Errorf("OrderedResponsesChecker: only %d/%d matched", c.idx, len(c.checkers))
}

// UnorderedResponsesChecker matches a list of ResponseCheckers over a
// squence of responses. The checkers can match in any order (no
// backtracking).
type UnorderedResponsesChecker struct {
	checkers        *list.List
	total_ncheckers int
}

func NewUnorderedResponsesChecker(checkers ...ResponseChecker) *UnorderedResponsesChecker {
	l := list.New()
	for _, c := range checkers {
		l.PushBack(c)
	}

	return &UnorderedResponsesChecker{
		checkers:        l,
		total_ncheckers: len(checkers),
	}
}

func (c *UnorderedResponsesChecker) NextCheck(ev *fgs.GetEventsResponse, log CheckerLogger) (bool, error) {
	clen := c.checkers.Len()
	if clen == 0 {
		return true, nil
	}

	log.Logf("UnorderedResponsesChecker: %d/%d checkers remain", clen, c.total_ncheckers)
	idx := 1
	for e := c.checkers.Front(); e != nil; e = e.Next() {
		checker := e.Value.(ResponseChecker)
		err := checker.Check(ev, log)
		if err == nil {
			log.Logf("UnorderedResponsesChecker: checking %d/%d: success", idx, clen)
			c.checkers.Remove(e)
			clen--
			if clen > 0 {
				log.Logf("UnorderedResponsesChecker: success: %d/%d matchers remaining", clen, c.total_ncheckers)
				return false, nil
			} else {
				log.Logf("UnorderedResponsesChecker: success: all %d matches matched", c.total_ncheckers)
				return true, nil
			}
		}
		log.Logf("UnorderedResponsesChecker: checking %d/%d: failure: %s", idx, clen, err)
		idx += 1
	}

	return false, fmt.Errorf("UnorderedResponsesChecker: all %d checks failed", c.checkers.Len())
}

func (c *UnorderedResponsesChecker) FinalCheck(log CheckerLogger) error {
	if l := c.checkers.Len(); l == 0 {
		return nil
	} else {
		return fmt.Errorf("UnorderedResponsesChecker: %d checks remain", c.checkers.Len())
	}
}

type fgsEvent interface {
	// used for FGS events such as:
	// fgs.ProcessExec
	// fgs.ProcessClose
	// etc.
}

type eventChainChecker struct {
	responseCheck func(*fgs.GetEventsResponse, CheckerLogger) (error, fgsEvent)
	eventCheck    func(fgsEvent, CheckerLogger) error
}

func checkEvent(r *fgs.GetEventsResponse, l CheckerLogger, types ...fgs.EventType) (error, fgsEvent) {

	checkTypes := func(ty fgs.EventType) error {
		for i := range types {
			if types[i] == ty {
				return nil
			}
		}
		return fmt.Errorf("type %s not in %+v", fgs.EventType_name[int32(ty)], types)
	}

	switch ev := r.Event.(type) {
	case *fgs.GetEventsResponse_ProcessExec:
		if err := checkTypes(fgs.EventType_PROCESS_EXEC); err != nil {
			return err, nil
		}
		return nil, ev.ProcessExec

	case *fgs.GetEventsResponse_ProcessConnect:
		if err := checkTypes(fgs.EventType_PROCESS_CONNECT); err != nil {
			return err, nil
		}
		return nil, ev.ProcessConnect

	case *fgs.GetEventsResponse_ProcessListen:
		if err := checkTypes(fgs.EventType_PROCESS_LISTEN); err != nil {
			return err, nil
		}
		return nil, ev.ProcessListen

	case *fgs.GetEventsResponse_Tls:
		if err := checkTypes(fgs.EventType_PROCESS_TLS); err != nil {
			return err, nil
		}
		return nil, ev.Tls

	case *fgs.GetEventsResponse_ProcessClose:
		if err := checkTypes(fgs.EventType_PROCESS_CLOSE); err != nil {
			return err, nil
		}
		return nil, ev.ProcessClose

	case *fgs.GetEventsResponse_ProcessAccept:
		if err := checkTypes(fgs.EventType_PROCESS_ACCEPT); err != nil {
			return err, nil
		}
		return nil, ev.ProcessAccept

	}

	return fmt.Errorf("Unknown event type (%T)", r.Event), nil
}

// NewListenEventChecker creates a new eventChainChecker for Listen events
func NewListenEventChecker() *eventChainChecker {
	return &eventChainChecker{
		responseCheck: func(r *fgs.GetEventsResponse, l CheckerLogger) (error, fgsEvent) {
			return checkEvent(r, l, fgs.EventType_PROCESS_LISTEN)
		},
		eventCheck: func(ev fgsEvent, l CheckerLogger) error {
			return nil
		},
	}
}

// NewConnectEventChecker creates a new eventChainChecker for Connect events
func NewConnectEventChecker() *eventChainChecker {
	return &eventChainChecker{
		responseCheck: func(r *fgs.GetEventsResponse, l CheckerLogger) (error, fgsEvent) {
			return checkEvent(r, l, fgs.EventType_PROCESS_CONNECT)
		},
		eventCheck: func(ev fgsEvent, l CheckerLogger) error {
			return nil
		},
	}
}

// NewAcceptEventChecker creates a new eventChainChecker for Accept events
func NewAcceptEventChecker() *eventChainChecker {
	return &eventChainChecker{
		responseCheck: func(r *fgs.GetEventsResponse, l CheckerLogger) (error, fgsEvent) {
			return checkEvent(r, l, fgs.EventType_PROCESS_ACCEPT)
		},
		eventCheck: func(ev fgsEvent, l CheckerLogger) error {
			return nil
		},
	}
}

// NewCloseEventChecker creates a new eventChainChecker for Close events
func NewCloseEventChecker() *eventChainChecker {
	return &eventChainChecker{
		responseCheck: func(r *fgs.GetEventsResponse, l CheckerLogger) (error, fgsEvent) {
			return checkEvent(r, l, fgs.EventType_PROCESS_CLOSE)
		},
		eventCheck: func(ev fgsEvent, l CheckerLogger) error {
			return nil
		},
	}
}

// End ends the chain
func (e *eventChainChecker) End() ResponseChecker {
	fn := func(r *fgs.GetEventsResponse, l CheckerLogger) error {
		if err, ev := e.responseCheck(r, l); err != nil {
			return err
		} else {
			return e.eventCheck(ev, l)
		}
	}
	return ResponseCheckerFn(fn)
}

func eventHasCookie(e fgsEvent, cookie uint64) error {
	switch v := e.(type) {
	case *fgs.ProcessListen:
		if v.SockCookie == cookie {
			return nil
		} else {
			return fmt.Errorf("Expecting cookie %d but ProcessListen has %d", cookie, v.SockCookie)
		}

	case *fgs.ProcessAccept:
		if v.SockCookie == cookie {
			return nil
		} else {
			return fmt.Errorf("Expecting cookie %d but ProcessAccept has %d", cookie, v.SockCookie)
		}

	case *fgs.ProcessConnect:
		if v.SockCookie == cookie {
			return nil
		} else {
			return fmt.Errorf("Expecting cookie %d but ProcessConnect has %d", cookie, v.SockCookie)
		}

	case *fgs.ProcessClose:
		if v.SockCookie == cookie {
			return nil
		} else {
			return fmt.Errorf("Expecting cookie %d but ProcessConnect has %d", cookie, v.SockCookie)
		}

	default:
		return fmt.Errorf("type %T does not have cookie", v)
	}
}

// HasCookie adds a check that the event has a cookie value matching to the argument
func (e *eventChainChecker) HasCookie(cookie uint64) *eventChainChecker {
	oldEventCheck := e.eventCheck
	e.eventCheck = func(e fgsEvent, l CheckerLogger) error {
		if err := oldEventCheck(e, l); err != nil {
			return err
		}
		return eventHasCookie(e, cookie)
	}
	return e
}

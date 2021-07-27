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
package eventchecker

import (
	"container/list"
	"fmt"
	"strings"

	"github.com/isovalent/hubble-fgs/api/v1/fgs"

	"github.com/golang/protobuf/ptypes/wrappers"
)

// ResponseChecker checks a single response
type ResponseChecker interface {
	// Check checks a single response.
	Check(*fgs.GetEventsResponse, Logger) error
}

// eventCheckerFn is a wrapper that allows a function to be used as an eventChecker
type ResponseCheckerFn func(*fgs.GetEventsResponse, Logger) error

// check implements ResponseChecker interface
func (f ResponseCheckerFn) Check(e *fgs.GetEventsResponse, log Logger) error {
	return f(e, log)
}

// MultiResponseChecker is a stateful checker for checking a series of responses
type MultiResponseChecker interface {
	// NextCheck checks a response and returns a boolean value indicating
	// whether the checker has concluded, and an error indicating whether the
	// check was successful. The boolean value allows short-circuting checks.
	//
	// Specifically:
	// (false,  nil): this response check was succesful, but need to check more events
	// (false, !nil): this response check not was succesful, but need to check more events
	// (true,   nil): checker was successful, no need to check more responses
	// (true,  !nil): checker failed, no need to check more responses
	NextCheck(*fgs.GetEventsResponse, Logger) (bool, error)

	// FinalCheck indicates that the sequence of events has ended, and asks
	// the checker to make a final decision.
	FinalCheck(Logger) error
}

type MultiResponseCheckerFns struct {
	NextCheckFn  func(*fgs.GetEventsResponse, Logger) (bool, error)
	FinalCheckFn func(Logger) error
}

func (fns *MultiResponseCheckerFns) NextCheck(r *fgs.GetEventsResponse, l Logger) (bool, error) {
	return fns.NextCheckFn(r, l)
}

func (fns *MultiResponseCheckerFns) FinalCheck(l Logger) error {
	return fns.FinalCheckFn(l)
}

// OrderedMultiResponseChecker matches a list of ResponseCheckers over a sequence of responses
type OrderedMultiResponseChecker struct {
	checkers []ResponseChecker
	idx      int
}

// NewOrderedMultiResponseChecker retuns a new OrderedMultiResponseChecker
func NewOrderedMultiResponseChecker(checkers ...ResponseChecker) OrderedMultiResponseChecker {
	return OrderedMultiResponseChecker{
		checkers: checkers,
		idx:      0,
	}
}

func (c *OrderedMultiResponseChecker) NextCheck(r *fgs.GetEventsResponse, l Logger) (bool, error) {
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
		l.Logf("OrderedMultiResponseChecker: all %d checks succeeded", len(c.checkers))
		return true, nil
	} else {
		l.Logf("OrderedMultiResponseChecker: %d/%d matched", c.idx, len(c.checkers))
		return false, nil
	}
}

func (c *OrderedMultiResponseChecker) FinalCheck(l Logger) error {
	if c.idx >= len(c.checkers) {
		return nil
	}
	return fmt.Errorf("OrderedMultiResponseChecker: only %d/%d matched", c.idx, len(c.checkers))
}

// UnorderedMultiResponseChecker matches a list of ResponseCheckers over a
// squence of responses. The checkers can match in any order (no
// backtracking).
type UnorderedMultiResponseChecker struct {
	checkers        *list.List
	total_ncheckers int
}

func NewUnorderedMultiResponseChecker(checkers ...ResponseChecker) *UnorderedMultiResponseChecker {
	l := list.New()
	for _, c := range checkers {
		l.PushBack(c)
	}

	return &UnorderedMultiResponseChecker{
		checkers:        l,
		total_ncheckers: len(checkers),
	}
}

func (c *UnorderedMultiResponseChecker) NextCheck(ev *fgs.GetEventsResponse, log Logger) (bool, error) {
	clen := c.checkers.Len()
	if clen == 0 {
		return true, nil
	}

	log.Logf("UnorderedMultiResponseChecker: %d/%d checkers remain", clen, c.total_ncheckers)
	idx := 1
	for e := c.checkers.Front(); e != nil; e = e.Next() {
		checker := e.Value.(ResponseChecker)
		err := checker.Check(ev, log)
		if err == nil {
			log.Logf("UnorderedMultiResponseChecker: checking %d/%d: success", idx, clen)
			c.checkers.Remove(e)
			clen--
			if clen > 0 {
				log.Logf("UnorderedMultiResponseChecker: success: %d/%d matchers remaining", clen, c.total_ncheckers)
				return false, nil
			} else {
				log.Logf("UnorderedMultiResponseChecker: success: all %d matches matched", c.total_ncheckers)
				return true, nil
			}
		}
		log.Logf("UnorderedMultiResponseChecker: checking %d/%d: failure: %s", idx, clen, err)
		idx += 1
	}

	return false, fmt.Errorf("UnorderedMultiResponseChecker: all %d checks failed", c.checkers.Len())
}

func (c *UnorderedMultiResponseChecker) FinalCheck(log Logger) error {
	if l := c.checkers.Len(); l == 0 {
		return nil
	} else {
		return fmt.Errorf("UnorderedMultiResponseChecker: %d checks remain", c.checkers.Len())
	}
}

type fgsEvent interface {
	// used for FGS events such as:
	// fgs.ProcessExec
	// fgs.ProcessClose
	// etc.
}

type eventChainChecker struct {
	responseCheck func(*fgs.GetEventsResponse, Logger) (error, fgsEvent)
	eventCheck    func(fgsEvent, Logger) error
}

func responseGetProcess(r *fgs.GetEventsResponse) *fgs.Process {
	switch ev := r.Event.(type) {
	case *fgs.GetEventsResponse_ProcessExec:
		return ev.ProcessExec.Process
	case *fgs.GetEventsResponse_ProcessConnect:
		return ev.ProcessConnect.Process
	case *fgs.GetEventsResponse_ProcessListen:
		return ev.ProcessListen.Process
	case *fgs.GetEventsResponse_Tls:
		return ev.Tls.Process
	case *fgs.GetEventsResponse_ProcessExit:
		return ev.ProcessExit.Process
	case *fgs.GetEventsResponse_ProcessClose:
		return ev.ProcessClose.Process
	case *fgs.GetEventsResponse_ProcessAccept:
		return ev.ProcessAccept.Process
	}
	return nil
}

func eventGetProcess(ev_ fgsEvent) *fgs.Process {
	switch ev := ev_.(type) {
	case *fgs.ProcessExec:
		return ev.Process
	case *fgs.ProcessConnect:
		return ev.Process
	case *fgs.ProcessListen:
		return ev.Process
	case *fgs.Tls:
		return ev.Process
	case *fgs.ProcessExit:
		return ev.Process
	case *fgs.ProcessClose:
		return ev.Process
	case *fgs.ProcessAccept:
		return ev.Process
	}
	return nil
}

func responseGetParent(r *fgs.GetEventsResponse) *fgs.Process {
	switch ev := r.Event.(type) {
	case *fgs.GetEventsResponse_ProcessExec:
		return ev.ProcessExec.Parent
	case *fgs.GetEventsResponse_ProcessConnect:
		return ev.ProcessConnect.Parent
	case *fgs.GetEventsResponse_ProcessListen:
		return ev.ProcessListen.Parent
	case *fgs.GetEventsResponse_Tls:
		return nil
	case *fgs.GetEventsResponse_ProcessExit:
		return ev.ProcessExit.Parent
	case *fgs.GetEventsResponse_ProcessClose:
		return ev.ProcessClose.Parent
	case *fgs.GetEventsResponse_ProcessAccept:
		return ev.ProcessAccept.Parent
	}
	return nil
}

func eventGetParent(ev_ fgsEvent) *fgs.Process {
	switch ev := ev_.(type) {
	case *fgs.ProcessExec:
		return ev.Parent
	case *fgs.ProcessConnect:
		return ev.Parent
	case *fgs.ProcessListen:
		return ev.Parent
	case *fgs.Tls:
		return nil
	case *fgs.ProcessExit:
		return ev.Parent
	case *fgs.ProcessClose:
		return ev.Parent
	case *fgs.ProcessAccept:
		return ev.Parent
	}
	return nil
}

func checkEvent(r *fgs.GetEventsResponse, l Logger, types ...fgs.EventType) (error, fgsEvent) {

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
		responseCheck: func(r *fgs.GetEventsResponse, l Logger) (error, fgsEvent) {
			return checkEvent(r, l, fgs.EventType_PROCESS_LISTEN)
		},
		eventCheck: func(ev fgsEvent, l Logger) error {
			return nil
		},
	}
}

// NewConnectEventChecker creates a new eventChainChecker for Connect events
func NewConnectEventChecker() *eventChainChecker {
	return &eventChainChecker{
		responseCheck: func(r *fgs.GetEventsResponse, l Logger) (error, fgsEvent) {
			return checkEvent(r, l, fgs.EventType_PROCESS_CONNECT)
		},
		eventCheck: func(ev fgsEvent, l Logger) error {
			return nil
		},
	}
}

// NewExecEventChecker creates a new eventChainChecker for Exec events
func NewExecEventChecker() *eventChainChecker {
	return &eventChainChecker{
		responseCheck: func(r *fgs.GetEventsResponse, l Logger) (error, fgsEvent) {
			return checkEvent(r, l, fgs.EventType_PROCESS_EXEC)
		},
		eventCheck: func(ev fgsEvent, l Logger) error {
			return nil
		},
	}
}

// NewAcceptEventChecker creates a new eventChainChecker for Accept events
func NewAcceptEventChecker() *eventChainChecker {
	return &eventChainChecker{
		responseCheck: func(r *fgs.GetEventsResponse, l Logger) (error, fgsEvent) {
			return checkEvent(r, l, fgs.EventType_PROCESS_ACCEPT)
		},
		eventCheck: func(ev fgsEvent, l Logger) error {
			return nil
		},
	}
}

// NewCloseEventChecker creates a new eventChainChecker for Close events
func NewCloseEventChecker() *eventChainChecker {
	return &eventChainChecker{
		responseCheck: func(r *fgs.GetEventsResponse, l Logger) (error, fgsEvent) {
			return checkEvent(r, l, fgs.EventType_PROCESS_CLOSE)
		},
		eventCheck: func(ev fgsEvent, l Logger) error {
			return nil
		},
	}
}

// End ends the chain
func (e *eventChainChecker) End() ResponseChecker {
	fn := func(r *fgs.GetEventsResponse, l Logger) error {
		if err, ev := e.responseCheck(r, l); err != nil {
			return err
		} else {
			return e.eventCheck(ev, l)
		}
	}
	return ResponseCheckerFn(fn)
}

func eventHasDstIP(e fgsEvent, ip string) error {
	if ev, ok := e.(interface{ GetDestinationIp() string }); ok {
		evIP := ev.GetDestinationIp()
		if evIP == ip {
			return nil
		}
		return fmt.Errorf("Expecting DstIP %s but %T has %s", ip, ev, evIP)
	}
	return fmt.Errorf("type %T does not have DstIP", e)
}

// HasDstIP adds a check that the event has a destination IP value matching to the argument
func (e *eventChainChecker) HasDstIP(ip string) *eventChainChecker {
	oldEventCheck := e.eventCheck
	e.eventCheck = func(e fgsEvent, l Logger) error {
		if err := oldEventCheck(e, l); err != nil {
			return err
		}
		return eventHasDstIP(e, ip)
	}
	return e
}

func checkPort(port uint32, val *wrappers.UInt32Value) error {
	if val == nil {
		return fmt.Errorf("%d does not match nil value", port)
	}
	if val.Value != port {
		return fmt.Errorf("%d does not match %d value", port, val.Value)
	}
	return nil
}

func eventHasDstPort(e fgsEvent, port uint32) error {
	if ev, ok := e.(interface{ GetDestinationPort() *wrappers.UInt32Value }); ok {
		evPort := ev.GetDestinationPort()
		if err := checkPort(port, evPort); err == nil {
			return nil
		} else {
			return fmt.Errorf("%T port check failed: %w", ev, err)
		}
	}
	return fmt.Errorf("type %T does not have Dst Port", e)
}

// HasDstIP adds a check that the event has a destination IP value matching to the argument
func (e *eventChainChecker) HasDstPort(port uint32) *eventChainChecker {
	oldEventCheck := e.eventCheck
	e.eventCheck = func(e fgsEvent, l Logger) error {
		if err := oldEventCheck(e, l); err != nil {
			return err
		}
		return eventHasDstPort(e, port)
	}
	return e
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
			return fmt.Errorf("Expecting cookie %d but ProcessClose has %d", cookie, v.SockCookie)
		}

	default:
		return fmt.Errorf("type %T does not have cookie", v)
	}
}

// HasCookie adds a check that the event has a cookie value matching to the argument
func (e *eventChainChecker) HasCookie(cookie uint64) *eventChainChecker {
	oldEventCheck := e.eventCheck
	e.eventCheck = func(e fgsEvent, l Logger) error {
		if err := oldEventCheck(e, l); err != nil {
			return err
		}
		return eventHasCookie(e, cookie)
	}
	return e
}

func eventHasIP(e fgsEvent, IP string) error {
	if ev, ok := e.(interface{ GetIp() string }); ok {
		evIP := ev.GetIp()
		if evIP == IP {
			return nil
		}
		return fmt.Errorf("Expecting IP %s but %T has %s", IP, ev, evIP)
	}
	return fmt.Errorf("type %T does not have IP", e)
}

// HasIP adds a check that the event has an IP matching the argument
func (e *eventChainChecker) HasIP(IP string) *eventChainChecker {
	oldEventCheck := e.eventCheck
	e.eventCheck = func(e fgsEvent, l Logger) error {
		if err := oldEventCheck(e, l); err != nil {
			return err
		}
		return eventHasIP(e, IP)
	}
	return e
}

func eventHasPort(e fgsEvent, port uint32) error {
	if ev, ok := e.(interface{ GetPort() *wrappers.UInt32Value }); ok {
		evPort := ev.GetPort()
		if err := checkPort(port, evPort); err == nil {
			return nil
		} else {
			return fmt.Errorf("%T port check failed: %w", ev, err)
		}
	}
	return fmt.Errorf("type %T does not have IP", e)
}

// HasPort adds a check that the event has an port matching the argument
func (e *eventChainChecker) HasPort(port uint32) *eventChainChecker {
	oldEventCheck := e.eventCheck
	e.eventCheck = func(e fgsEvent, l Logger) error {
		if err := oldEventCheck(e, l); err != nil {
			return err
		}
		return eventHasPort(e, port)
	}
	return e
}

// ProcessChecker checks a process
type ProcessChecker interface {
	// Check checks a single response.
	Check(*fgs.Process, Logger) error
}

type ProcessCheckerFn func(*fgs.Process, Logger) error

// Check implements ResponseChecker interface
func (f ProcessCheckerFn) Check(p *fgs.Process, log Logger) error {
	return f(p, log)
}

// ProcessCheckerAND can be used to build a check that is a conjuction of other checkers
type ProcessCheckerAND struct {
	checks []ProcessChecker
}

func NewProcessCheckerAND() *ProcessCheckerAND {
	return &ProcessCheckerAND{}
}

// With adds another process checker
func (o *ProcessCheckerAND) With(c ...ProcessChecker) *ProcessCheckerAND {
	o.checks = append(o.checks, c...)
	return o
}

func (o *ProcessCheckerAND) WithBinary(sm StringMatcher) *ProcessCheckerAND {
	o.checks = append(o.checks, ProcessWithBinary(sm))
	return o
}

func (o *ProcessCheckerAND) WithArguments(sm StringMatcher) *ProcessCheckerAND {
	o.checks = append(o.checks, ProcessWithArguments(sm))
	return o
}

func (o *ProcessCheckerAND) WithCWD(sm StringMatcher) *ProcessCheckerAND {
	o.checks = append(o.checks, ProcessWithCWD(sm))
	return o
}

func (o *ProcessCheckerAND) Check(p *fgs.Process, l Logger) error {
	for i := range o.checks {
		if err := o.checks[i].Check(p, l); err != nil {
			return err
		}
	}
	return nil
}

func processWithString(
	sm StringMatcher,
	getter func(p *fgs.Process) string,
	desc string, // desc is used for helpful error messages
) ProcessChecker {
	matcher := sm.GetMatcher()
	return ProcessCheckerFn(func(p *fgs.Process, log Logger) error {
		if p == nil {
			return fmt.Errorf("process is nil and cannot match %s using %v", desc, sm)
		}
		s := getter(p)
		if err := matcher(s); err != nil {
			return fmt.Errorf("failed check on %s: %w", desc, err)
		}
		return nil
	})
}

// ProcessWithCWD matches the cwd field
func ProcessWithCWD(sm StringMatcher) ProcessChecker {
	matcher := sm.GetMatcher()
	return ProcessCheckerFn(func(p *fgs.Process, log Logger) error {
		if p == nil {
			return fmt.Errorf("process is nil and cannot match cwd usnig %v", sm)
		}
		cwd := p.Cwd
		if strings.Contains(p.Flags, "nocwd") {
			log.Logf("cwd check: nocwd flag set, test considered successful", cwd)
			return nil
		}
		if len(cwd) > 1 && strings.HasSuffix(cwd, "/") {
			cwd = strings.TrimSuffix(cwd, "/")
			log.Logf("cwd check: removed trailing /: cwd=%s", cwd)
		}
		if err := matcher(cwd); err != nil {
			return fmt.Errorf("failed check on %s: %w", "cwd", err)
		}
		return nil
	})
}

// ProcessWithBinary matches the Binary field
func ProcessWithBinary(sm StringMatcher) ProcessChecker {
	return processWithString(
		sm,
		func(p *fgs.Process) string {
			return p.Binary
		},
		"binary",
	)
}

// ProcessWithBinary matches the Arguments field
func ProcessWithArguments(sm StringMatcher) ProcessChecker {
	return processWithString(
		sm,
		func(p *fgs.Process) string {
			return p.Arguments
		},
		"arguments",
	)
}

// ProcessWithCommand matches the Binary and Arguments field
func ProcessWithCommand(binary StringMatcher, args StringMatcher) ProcessChecker {
	return &ProcessCheckerAND{
		checks: []ProcessChecker{
			ProcessWithBinary(binary),
			ProcessWithArguments(args),
		},
	}
}

func (e *eventChainChecker) HasProcess(cs ...ProcessChecker) *eventChainChecker {
	oldEventCheck := e.eventCheck
	e.eventCheck = func(e fgsEvent, l Logger) error {
		if err := oldEventCheck(e, l); err != nil {
			return err
		}
		process := eventGetProcess(e)
		if process == nil {
			return fmt.Errorf("process is nil")
		}
		for i := range cs {
			if err := cs[i].Check(process, l); err != nil {
				return fmt.Errorf("process check failed: %w", err)
			}
		}
		return nil
	}
	return e
}

func (e *eventChainChecker) HasParent(cs ...ProcessChecker) *eventChainChecker {
	oldEventCheck := e.eventCheck
	e.eventCheck = func(e fgsEvent, l Logger) error {
		if err := oldEventCheck(e, l); err != nil {
			return err
		}
		process := eventGetParent(e)
		if process == nil {
			return fmt.Errorf("parent is nil")
		}
		for i := range cs {
			if err := cs[i].Check(process, l); err != nil {
				return fmt.Errorf("parent check faield: %w", err)
			}
		}
		return nil
	}
	return e
}

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

// Logger interface to be used in checkers
type Logger interface {
	Log(args ...interface{})
	Logf(format string, args ...interface{})
	Fatal(args ...interface{})
	Fatalf(format string, args ...interface{})
}

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
	switch v := e.(type) {
	case *fgs.ProcessConnect:
		if v.GetDestinationIp() == ip {
			return nil
		} else {
			return fmt.Errorf("Expecting ip %s but ProcessConnect has %s", ip, v.GetDestinationIp())
		}

	case *fgs.ProcessClose:
		if v.GetDestinationIp() == ip {
			return nil
		} else {
			return fmt.Errorf("Expecting ip %s but ProcesClose has %s", ip, v.GetDestinationIp())
		}

	case *fgs.ProcessAccept:
		if v.GetDestinationIp() == ip {
			return nil
		} else {
			return fmt.Errorf("Expecting ip %s but ProcesAccept has %s", ip, v.GetDestinationIp())
		}

	case *fgs.Tls:
		if v.GetDestinationIp() == ip {
			return nil
		} else {
			return fmt.Errorf("Expecting ip %s but Tls has %s", ip, v.GetDestinationIp())
		}

	default:
		return fmt.Errorf("type %T does not have destination IP", v)
	}
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

func eventHasDstPort(e fgsEvent, port uint32) error {

	checkPort := func(val *wrappers.UInt32Value) error {
		if val == nil {
			return fmt.Errorf("%d does not match nil value", port)
		}
		if val.Value != port {
			return fmt.Errorf("%d does not match %d value", port, val.Value)
		}
		return nil
	}

	switch v := e.(type) {
	case *fgs.ProcessConnect:
		if err := checkPort(v.GetDestinationPort()); err != nil {
			return fmt.Errorf("ProcessConnect event does not have matching port: %w", err)
		}
		return nil
	case *fgs.ProcessClose:
		if err := checkPort(v.GetDestinationPort()); err != nil {
			return fmt.Errorf("ProcessClose event does not have matching port: %w", err)
		}
		return nil

	case *fgs.ProcessAccept:
		if err := checkPort(v.GetDestinationPort()); err != nil {
			return fmt.Errorf("ProcessAccept event does not have matching port: %w", err)
		}
		return nil

	case *fgs.Tls:
		if err := checkPort(v.GetDestinationPort()); err != nil {
			return fmt.Errorf("Tls event does not have matching port: %w", err)
		}
		return nil

	default:
		return fmt.Errorf("type %T does not have destination port", v)
	}
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

// ProcessChecker checks a process
type ProcessChecker interface {
	// Check checks a single response.
	Check(*fgs.Process, Logger) error
}

type ProcessCheckerFn func(*fgs.Process, Logger) error

// check implements ResponseChecker interface
func (f ProcessCheckerFn) Check(p *fgs.Process, log Logger) error {
	return f(p, log)
}

type StrMatch int

const (
	StrFullMatch StrMatch = iota // NB: 0
	StrPrefixMatch
	StrSuffixMatch
	// StrRegexMatch?
)

type StringMatcher struct {
	s string
	m StrMatch
}

func FullStringMatch(s string) StringMatcher {
	return StringMatcher{s: s, m: StrFullMatch}
}

func PrefixStringMatch(s string) StringMatcher {
	return StringMatcher{s: s, m: StrPrefixMatch}
}

func SuffixStringMatch(s string) StringMatcher {
	return StringMatcher{s: s, m: StrSuffixMatch}
}

func (sm StringMatcher) GetMatcher() func(string) error {
	switch sm.m {
	case StrFullMatch:
		return func(x string) error {
			if x == sm.s {
				return nil
			}
			return fmt.Errorf("%s does not match %s", x, sm.s)
		}
	case StrPrefixMatch:
		return func(x string) error {
			if strings.HasPrefix(x, sm.s) {
				return nil
			}
			return fmt.Errorf("%s does not match prefix %s", x, sm.s)
		}
	case StrSuffixMatch:
		return func(x string) error {
			if strings.HasSuffix(x, sm.s) {
				return nil
			}
			return fmt.Errorf("%s does not match suffix %s", x, sm.s)
		}
	}
	return func(x string) error {
		return fmt.Errorf("internal error: Unknown matcher: %d", sm.m)
	}
}

func ProcessWithBinary(sm StringMatcher) ProcessChecker {
	matcher := sm.GetMatcher()
	return ProcessCheckerFn(func(p *fgs.Process, log Logger) error {
		if p == nil {
			return fmt.Errorf("process is nil and cannot match %v", sm)
		}
		if err := matcher(p.Binary); err != nil {
			return fmt.Errorf("process binary %s does not match:%w", p.Binary, err)
		}
		return nil
	})
}

func ProcessWithArguments(sm StringMatcher) ProcessChecker {
	matcher := sm.GetMatcher()
	return ProcessCheckerFn(func(p *fgs.Process, log Logger) error {
		if p == nil {
			return fmt.Errorf("process is nil and cannot match %+v", sm)
		}
		if err := matcher(p.Arguments); err != nil {
			return fmt.Errorf("process arguments %s do not match:%w", p.Binary, err)
		}
		return nil
	})
}

func ProcessWithCommand(binary StringMatcher, args StringMatcher) ProcessChecker {
	binMatcher := binary.GetMatcher()
	argMatcher := args.GetMatcher()
	return ProcessCheckerFn(func(p *fgs.Process, log Logger) error {
		if p == nil {
			return fmt.Errorf("process is nil annd cannot match binary (%+v)/args (%+v)", binary, args)
		}
		if err := binMatcher(p.Binary); err != nil {
			return fmt.Errorf("process binary %s does not match:%w", p.Binary, err)
		}
		if err := argMatcher(p.Arguments); err != nil {
			return fmt.Errorf("process arguments %s do not match:%w", p.Binary, err)
		}
		return nil
	})
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
				return err
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
			return fmt.Errorf("process is nil")
		}
		for i := range cs {
			if err := cs[i].Check(process, l); err != nil {
				return err
			}
		}
		return nil
	}
	return e
}

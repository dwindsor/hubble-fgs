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
	"reflect"
	"strings"

	"github.com/isovalent/hubble-fgs/api/v1/fgs"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// NB(kkourt): this package is in a somewhat unstable state since I'm
// experimenting with different approaches and tradeoffs. Once its interface
// stabilizes somewhat, I'd like to investigate generating code directly from
// the protbuf descriptions via a protoc plugin.

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
	// (false,  nil): this response check was successful, but need to check more events
	// (false, !nil): this response check not was successful, but need to check more events
	// (true,   nil): checker was successful, no need to check more responses
	// (true,  !nil): checker failed, no need to check more responses
	NextCheck(*fgs.GetEventsResponse, Logger) (bool, error)

	// FinalCheck indicates that the sequence of events has ended, and asks
	// the checker to make a final decision.
	FinalCheck(Logger) error

	// Reset resets the checker so that it can be used again
	Reset()
}

type MultiResponseCheckerFns struct {
	NextCheckFn  func(*fgs.GetEventsResponse, Logger) (bool, error)
	FinalCheckFn func(Logger) error
	ResetFn      func()
}

func (fns *MultiResponseCheckerFns) NextCheck(r *fgs.GetEventsResponse, l Logger) (bool, error) {
	return fns.NextCheckFn(r, l)
}

func (fns *MultiResponseCheckerFns) FinalCheck(l Logger) error {
	return fns.FinalCheckFn(l)
}

func (fns *MultiResponseCheckerFns) Reset() {
	fns.ResetFn()
}

// OrderedMultiResponseChecker matches a list of ResponseCheckers over a sequence of responses
type OrderedMultiResponseChecker struct {
	checkers []ResponseChecker
	idx      int
}

// NewOrderedMultiResponseChecker returns a new OrderedMultiResponseChecker
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

func (c *OrderedMultiResponseChecker) Reset() {
	c.idx = 0
}

// AllMultiResponseChecker matches all checkers for all responses
type AllMultiResponseChecker struct {
	checkers []ResponseChecker
}

// NewAllMultiResponseChecker returns a new AllMultiResponseChecker
func NewAllMultiResponseChecker(checkers ...ResponseChecker) AllMultiResponseChecker {
	return AllMultiResponseChecker{
		checkers: checkers,
	}
}

func (c *AllMultiResponseChecker) NextCheck(r *fgs.GetEventsResponse, l Logger) (bool, error) {
	for i := range c.checkers {
		if err := c.checkers[i].Check(r, l); err != nil {
			return true, err
		}
	}
	return false, nil
}

func (c *AllMultiResponseChecker) FinalCheck(l Logger) error {
	l.Logf("AllMultiResponseChecker: all %d checks succeeded for all events", len(c.checkers))
	return nil
}

func (c *AllMultiResponseChecker) Reset() {}

// UnorderedMultiResponseChecker matches a list of ResponseCheckers over a
// squence of responses. The checkers can match in any order (no
// backtracking).
type UnorderedMultiResponseChecker struct {
	pendingCheckers *list.List
	totalCheckers   int

	allCheckers *list.List
}

func NewUnorderedMultiResponseChecker(checkers ...ResponseChecker) *UnorderedMultiResponseChecker {
	allList := list.New()
	for _, c := range checkers {
		allList.PushBack(c)
	}

	pendingList := list.New()
	pendingList.PushBackList(allList)

	return &UnorderedMultiResponseChecker{
		allCheckers:     allList,
		pendingCheckers: pendingList,
		totalCheckers:   len(checkers),
	}
}

func (c *UnorderedMultiResponseChecker) Reset() {
	c.pendingCheckers = list.New()
	c.pendingCheckers.PushBackList(c.allCheckers)
	c.totalCheckers = c.pendingCheckers.Len()

}

func (c *UnorderedMultiResponseChecker) NextCheck(ev *fgs.GetEventsResponse, log Logger) (bool, error) {
	clen := c.pendingCheckers.Len()
	if clen == 0 {
		return true, nil
	}

	log.Logf("UnorderedMultiResponseChecker: %d/%d checkers remain", clen, c.totalCheckers)
	idx := 1
	for e := c.pendingCheckers.Front(); e != nil; e = e.Next() {
		checker := e.Value.(ResponseChecker)
		err := checker.Check(ev, log)
		if err == nil {
			log.Logf("UnorderedMultiResponseChecker: checking %d/%d: success", idx, clen)
			c.pendingCheckers.Remove(e)
			clen--
			if clen > 0 {
				log.Logf("UnorderedMultiResponseChecker: success: %d/%d matchers remaining", clen, c.totalCheckers)
				return false, nil
			} else {
				log.Logf("UnorderedMultiResponseChecker: success: all %d matches matched", c.totalCheckers)
				return true, nil
			}
		}
		log.Logf("UnorderedMultiResponseChecker: checking %d/%d: failure: %s", idx, clen, err)
		idx += 1
	}

	return false, fmt.Errorf("UnorderedMultiResponseChecker: all %d checks failed", c.pendingCheckers.Len())
}

func (c *UnorderedMultiResponseChecker) FinalCheck(log Logger) error {
	if l := c.pendingCheckers.Len(); l == 0 {
		return nil
	} else {
		return fmt.Errorf("UnorderedMultiResponseChecker: %d checks remain", c.pendingCheckers.Len())
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
	case *fgs.ProcessHttp:
		return ev.Process
	case *fgs.ProcessExit:
		return ev.Process
	case *fgs.ProcessClose:
		return ev.Process
	case *fgs.ProcessAccept:
		return ev.Process
	case *fgs.ProcessKprobe:
		return ev.Process
	case *fgs.ProcessTracepoint:
		return ev.Process
	default:
		panic("Unhandled type")
	}
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
	case *fgs.ProcessHttp:
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

type EventTypeError struct {
	Err error
}

func (e EventTypeError) Error() string {
	return e.Err.Error()
}

func checkEvent(r *fgs.GetEventsResponse, l Logger, types ...fgs.EventType) (error, fgsEvent) {

	checkTypes := func(ty fgs.EventType) error {
		for i := range types {
			if types[i] == ty {
				return nil
			}
		}
		return EventTypeError{
			Err: fmt.Errorf("type %s not in %+v", fgs.EventType_name[int32(ty)], types),
		}
	}

	switch ev := r.Event.(type) {
	case *fgs.GetEventsResponse_ProcessExec:
		if err := checkTypes(fgs.EventType_PROCESS_EXEC); err != nil {
			return err, nil
		}
		return nil, ev.ProcessExec

	case *fgs.GetEventsResponse_ProcessExit:
		if err := checkTypes(fgs.EventType_PROCESS_EXIT); err != nil {
			return err, nil
		}
		return nil, ev.ProcessExit

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

	case *fgs.GetEventsResponse_ProcessDns:
		if err := checkTypes(fgs.EventType_PROCESS_DNS); err != nil {
			return err, nil
		}
		return nil, ev.ProcessDns

	case *fgs.GetEventsResponse_ProcessSockstats:
		if err := checkTypes(fgs.EventType_PROCESS_SOCKSTATS); err != nil {
			return err, nil
		}
		return nil, ev.ProcessSockstats

	case *fgs.GetEventsResponse_ProcessClose:
		if err := checkTypes(fgs.EventType_PROCESS_CLOSE); err != nil {
			return err, nil
		}
		return nil, ev.ProcessClose

	case *fgs.GetEventsResponse_ProcessCred:
		if err := checkTypes(fgs.EventType_PROCESS_CRED); err != nil {
			return err, nil
		}
		return nil, ev.ProcessCred

	case *fgs.GetEventsResponse_ProcessAccept:
		if err := checkTypes(fgs.EventType_PROCESS_ACCEPT); err != nil {
			return err, nil
		}
		return nil, ev.ProcessAccept

	case *fgs.GetEventsResponse_ProcessTracepoint:
		if err := checkTypes(fgs.EventType_PROCESS_TRACEPOINT); err != nil {
			return err, nil
		}
		return nil, ev.ProcessTracepoint

	case *fgs.GetEventsResponse_ProcessKprobe:
		if err := checkTypes(fgs.EventType_PROCESS_KPROBE); err != nil {
			return err, nil
		}
		return nil, ev.ProcessKprobe

	case *fgs.GetEventsResponse_ProcessHttp:
		if err := checkTypes(fgs.EventType_PROCESS_HTTP); err != nil {
			return err, nil
		}
		return nil, ev.ProcessHttp

	case *fgs.GetEventsResponse_InterfaceStats:
		if err := checkTypes(fgs.EventType_INTERFACE_STATS); err != nil {
			return err, nil
		}
		return nil, ev.InterfaceStats

	case *fgs.GetEventsResponse_Test:
		if err := checkTypes(fgs.EventType_TEST); err != nil {
			return err, nil
		}
		return nil, ev.Test
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

// NewTestEventChecker creates a new eventChainChecker for Test events
func NewTestEventChecker() *eventChainChecker {
	return &eventChainChecker{
		responseCheck: func(r *fgs.GetEventsResponse, l Logger) (error, fgsEvent) {
			return checkEvent(r, l, fgs.EventType_TEST)
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

// NewTlsEventChecker creates a new eventChainChecker for TLS events
func NewTlsEventChecker() *eventChainChecker {
	return &eventChainChecker{
		responseCheck: func(r *fgs.GetEventsResponse, l Logger) (error, fgsEvent) {
			return checkEvent(r, l, fgs.EventType_PROCESS_TLS)
		},
		eventCheck: func(ev fgsEvent, l Logger) error {
			return nil
		},
	}
}

// NewHttpEventChecker creates a new eventChainChecker for Http events
func NewHttpEventChecker() *eventChainChecker {
	return &eventChainChecker{
		responseCheck: func(r *fgs.GetEventsResponse, l Logger) (error, fgsEvent) {
			return checkEvent(r, l, fgs.EventType_PROCESS_HTTP)
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

func eventHasSrcIP(e fgsEvent, ip string) error {
	if ev, ok := e.(interface{ GetSourceIp() string }); ok {
		evIP := ev.GetSourceIp()
		if evIP == ip {
			return nil
		}
		return fmt.Errorf("Expecting SrcIP %s but %T has %s", ip, ev, evIP)
	}
	return fmt.Errorf("type %T does not have SrcIP", e)
}

// HasSrcIP adds a check that the event has a source IP value matching to the argument
func (e *eventChainChecker) HasSrcIP(ip string) *eventChainChecker {
	oldEventCheck := e.eventCheck
	e.eventCheck = func(e fgsEvent, l Logger) error {
		if err := oldEventCheck(e, l); err != nil {
			return err
		}
		return eventHasSrcIP(e, ip)
	}
	return e
}

func eventHasProtocol(e fgsEvent, proto fgs.SocketProtocol) error {
	if ev, ok := e.(interface {
		GetProtocol() fgs.SocketProtocol
	}); ok {
		evProto := ev.GetProtocol()
		if evProto == proto {
			return nil
		}
		return fmt.Errorf("Expecting Protocol %s but %T has %s", proto, ev, evProto)
	}
	return fmt.Errorf("type %T does not have Protocol", e)
}

func (e *eventChainChecker) HasProtocol(proto fgs.SocketProtocol) *eventChainChecker {
	oldEventCheck := e.eventCheck
	e.eventCheck = func(e fgsEvent, l Logger) error {
		if err := oldEventCheck(e, l); err != nil {
			return err
		}
		return eventHasProtocol(e, proto)
	}
	return e
}

func eventHasType(e fgsEvent, proto string) error {
	if ev, ok := e.(interface {
		GetSocketType() string
	}); ok {
		evProto := ev.GetSocketType()
		if evProto == proto {
			return nil
		}
		return fmt.Errorf("Expecting Type %s but %T has %s", proto, ev, evProto)
	}
	return fmt.Errorf("type %T does not have Type", e)
}

func (e *eventChainChecker) HasType(proto string) *eventChainChecker {
	oldEventCheck := e.eventCheck
	e.eventCheck = func(e fgsEvent, l Logger) error {
		if err := oldEventCheck(e, l); err != nil {
			return err
		}
		return eventHasType(e, proto)
	}
	return e
}

func checkPort(port uint32, val *wrapperspb.UInt32Value) error {
	if val == nil {
		return fmt.Errorf("%d does not match nil value", port)
	}
	if val.Value != port {
		return fmt.Errorf("%d does not match %d value", port, val.Value)
	}
	return nil
}

func eventHasDstPort(e fgsEvent, port uint32) error {
	if ev, ok := e.(interface {
		GetDestinationPort() *wrapperspb.UInt32Value
	}); ok {
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

func eventHasSrcPort(e fgsEvent, port uint32) error {
	if ev, ok := e.(interface {
		GetSourcePort() *wrapperspb.UInt32Value
	}); ok {
		evPort := ev.GetSourcePort()
		if err := checkPort(port, evPort); err == nil {
			return nil
		} else {
			return fmt.Errorf("%T port check failed: %w", ev, err)
		}
	}
	return fmt.Errorf("type %T does not have Src Port", e)
}

// HasSrcIP adds a check that the event has a source IP value matching to the argument
func (e *eventChainChecker) HasSrcPort(port uint32) *eventChainChecker {
	oldEventCheck := e.eventCheck
	e.eventCheck = func(e fgsEvent, l Logger) error {
		if err := oldEventCheck(e, l); err != nil {
			return err
		}
		return eventHasSrcPort(e, port)
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
	if ev, ok := e.(interface {
		GetPort() *wrapperspb.UInt32Value
	}); ok {
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

func eventHasNegotiatedVersion(e fgsEvent, version string) error {
	if ev, ok := e.(interface{ GetNegotiatedVersion() string }); ok {
		evVersion := ev.GetNegotiatedVersion()
		if evVersion == version {
			return nil
		}
		return fmt.Errorf("Expecting NegotiatedVersion %s but %T has %s", version, ev, evVersion)
	}
	return fmt.Errorf("type %T does not have NegotiatedVersion", e)
}

// HasNegotiatedVersion adds a check that the event has a negotiated TLS version matching
// the argument
func (e *eventChainChecker) HasNegotiatedVersion(version string) *eventChainChecker {
	oldEventCheck := e.eventCheck
	e.eventCheck = func(e fgsEvent, l Logger) error {
		if err := oldEventCheck(e, l); err != nil {
			return err
		}
		return eventHasNegotiatedVersion(e, version)
	}
	return e
}

func eventHasSupportedVersions(e fgsEvent, versions []string) error {
	if ev, ok := e.(interface{ GetSupportedVersions() string }); ok {
		evVersionsString := ev.GetSupportedVersions()
		evVersions := strings.Split(evVersionsString, " ")
		evVersionsSet := make(map[string]bool)
		for _, version := range evVersions {
			evVersionsSet[version] = true
		}
		versionsSet := make(map[string]bool)
		for _, version := range versions {
			versionsSet[version] = true
		}
		if reflect.DeepEqual(versionsSet, evVersionsSet) {
			return nil
		}
		return fmt.Errorf("Expecting SupportedVersions %s but %T has %s", versions, ev, evVersions)
	}
	return fmt.Errorf("type %T does not have SupportedVersions", e)
}

// HasSupportedVersions adds a check that the event has a set of supported versions
// exactly matching the set of versions given as an argument
func (e *eventChainChecker) HasSupportedVersions(versions []string) *eventChainChecker {
	oldEventCheck := e.eventCheck
	e.eventCheck = func(e fgsEvent, l Logger) error {
		if err := oldEventCheck(e, l); err != nil {
			return err
		}
		return eventHasSupportedVersions(e, versions)
	}
	return e
}

func eventHasSniType(e fgsEvent, _type string) error {
	if ev, ok := e.(interface{ GetSniType() string }); ok {
		evType := ev.GetSniType()
		if evType == _type {
			return nil
		}
		return fmt.Errorf("Expecting SniType %s but %T has %s", _type, ev, evType)
	}
	return fmt.Errorf("type %T does not have SniType", e)
}

// HasSniType adds a check that the event has a negotiated TLS type matching
// the argument
func (e *eventChainChecker) HasSniType(_type string) *eventChainChecker {
	oldEventCheck := e.eventCheck
	e.eventCheck = func(e fgsEvent, l Logger) error {
		if err := oldEventCheck(e, l); err != nil {
			return err
		}
		return eventHasSniType(e, _type)
	}
	return e
}

func eventHasSniName(e fgsEvent, name string) error {
	if ev, ok := e.(interface{ GetSniName() string }); ok {
		evName := ev.GetSniName()
		if evName == name {
			return nil
		}
		return fmt.Errorf("Expecting SniName %s but %T has %s", name, ev, evName)
	}
	return fmt.Errorf("type %T does not have SniName", e)
}

// HasSniName adds a check that the event has a negotiated TLS name matching
// the argument
func (e *eventChainChecker) HasSniName(name string) *eventChainChecker {
	oldEventCheck := e.eventCheck
	e.eventCheck = func(e fgsEvent, l Logger) error {
		if err := oldEventCheck(e, l); err != nil {
			return err
		}
		return eventHasSniName(e, name)
	}
	return e
}

// ProcessChecker checks a process
type ProcessChecker interface {
	// Check checks a process.
	Check(*fgs.Process, Logger) error
}
type ProcessCheckerFn func(*fgs.Process, Logger) error

// Check implements ResponseChecker interface
func (f ProcessCheckerFn) Check(p *fgs.Process, log Logger) error {
	return f(p, log)
}

type PodChecker interface {
	// Check checks a Pod
	Check(*fgs.Pod, Logger) error
}
type PodCheckerFn func(*fgs.Pod, Logger) error

func (f PodCheckerFn) Check(p *fgs.Pod, log Logger) error {
	return f(p, log)
}

type ContainerChecker interface {
	// Check checks a Container
	Check(*fgs.Container, Logger) error
}
type ContainerCheckerFn func(*fgs.Container, Logger) error

func (f ContainerCheckerFn) Check(c *fgs.Container, log Logger) error {
	return f(c, log)
}

type ImageChecker interface {
	// Check checks a container image
	Check(*fgs.Image, Logger) error
}
type ImageCheckerFn func(*fgs.Image, Logger) error

func (f ImageCheckerFn) Check(i *fgs.Image, log Logger) error {
	return f(i, log)
}

// ProcessCheckerAND can be used to build a check that is a conjunction of other checkers
type ProcessCheckerAND struct {
	checks []ProcessChecker
}

func NewProcessChecker() *ProcessCheckerAND {
	return &ProcessCheckerAND{}
}

// With adds another process checker
func (o *ProcessCheckerAND) With(c ...ProcessChecker) *ProcessCheckerAND {
	o.checks = append(o.checks, c...)
	return o
}

func (o *ProcessCheckerAND) WithBinary(arg StringArg) *ProcessCheckerAND {
	sm := stringMatcherFromArg(arg)
	o.checks = append(o.checks, ProcessWithBinary(sm))
	return o
}

func (o *ProcessCheckerAND) WithPod(arg PodChecker) *ProcessCheckerAND {
	o.checks = append(o.checks, ProcessWithPod(arg))
	return o
}

func (o *ProcessCheckerAND) WithArguments(arg StringArg) *ProcessCheckerAND {
	sm := stringMatcherFromArg(arg)
	o.checks = append(o.checks, ProcessWithArguments(sm))
	return o
}

func (o *ProcessCheckerAND) WithCWD(arg StringArg) *ProcessCheckerAND {
	sm := stringMatcherFromArg(arg)
	o.checks = append(o.checks, ProcessWithCWD(sm))
	return o
}

func (o *ProcessCheckerAND) WithDocker(arg StringArg) *ProcessCheckerAND {
	sm := stringMatcherFromArg(arg)
	o.checks = append(o.checks, ProcessWithDocker(sm))
	return o
}

func (o *ProcessCheckerAND) WithUID(uid uint32) *ProcessCheckerAND {
	o.checks = append(o.checks, ProcessWithUID(uid))
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

// ProcessCheckerOR can be used to build a check that is a disjunction of other checkers
type ProcessCheckerOR struct {
	checks []ProcessChecker
}

func NewProcessCheckerOr() *ProcessCheckerOR {
	return &ProcessCheckerOR{}
}

// With adds another process checker
func (o *ProcessCheckerOR) With(c ...ProcessChecker) *ProcessCheckerOR {
	o.checks = append(o.checks, c...)
	return o
}

func (o *ProcessCheckerOR) WithBinary(arg StringArg) *ProcessCheckerOR {
	sm := stringMatcherFromArg(arg)
	o.checks = append(o.checks, ProcessWithBinary(sm))
	return o
}

func (o *ProcessCheckerOR) WithPod(arg PodChecker) *ProcessCheckerOR {
	o.checks = append(o.checks, ProcessWithPod(arg))
	return o
}

func (o *ProcessCheckerOR) WithArguments(arg StringArg) *ProcessCheckerOR {
	sm := stringMatcherFromArg(arg)
	o.checks = append(o.checks, ProcessWithArguments(sm))
	return o
}

func (o *ProcessCheckerOR) WithCWD(arg StringArg) *ProcessCheckerOR {
	sm := stringMatcherFromArg(arg)
	o.checks = append(o.checks, ProcessWithCWD(sm))
	return o
}

func (o *ProcessCheckerOR) WithDocker(arg StringArg) *ProcessCheckerOR {
	sm := stringMatcherFromArg(arg)
	o.checks = append(o.checks, ProcessWithDocker(sm))
	return o
}

func (o *ProcessCheckerOR) WithUID(uid uint32) *ProcessCheckerOR {
	o.checks = append(o.checks, ProcessWithUID(uid))
	return o
}

func (o *ProcessCheckerOR) Check(p *fgs.Process, l Logger) error {
	var failures []error
	for i := range o.checks {
		err := o.checks[i].Check(p, l)
		if err == nil {
			return nil
		}
		failures = append(failures, err)
	}
	return fmt.Errorf("failed to match any checks %v", failures)
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
		log.Logf("**** MATCH on %s: %s", desc, s)
		return nil
	})
}

// ProcessWithCWD matches the cwd field
func ProcessWithCWD(sm StringMatcher) ProcessChecker {
	matcher := sm.GetMatcher()
	return ProcessCheckerFn(func(p *fgs.Process, log Logger) error {
		if p == nil {
			return fmt.Errorf("process is nil and cannot match cwd using %v", sm)
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
		log.Logf("**** MATCH on %s: %s", "cwd", p.Cwd)
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

// ProcessWithArguments matches the Arguments field
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

func ProcessWithPod(pc PodChecker) ProcessChecker {
	return ProcessCheckerFn(func(p *fgs.Process, log Logger) error {
		if p == nil {
			return fmt.Errorf("process is nil and cannot match pod")
		}
		if err := pc.Check(p.Pod, log); err != nil {
			return fmt.Errorf("failed check on %s: %w", "pod", err)
		}
		return nil
	})
}

// ProcessWithDocker matches the Docker field
func ProcessWithDocker(sm StringMatcher) ProcessChecker {
	return processWithString(
		sm,
		func(p *fgs.Process) string {
			return p.Docker
		},
		"docker",
	)
}

// ProcessWithUID matches the Uid field
func ProcessWithUID(uid uint32) ProcessChecker {
	return ProcessCheckerFn(func(p *fgs.Process, log Logger) error {
		if p.Uid == nil {
			return fmt.Errorf("uid %d does not match nil value", uid)
		}
		if p.Uid.Value != uid {
			return fmt.Errorf("uid %d does not match %d value", uid, p.Uid.Value)
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
				return fmt.Errorf("parent check failed: %w", err)
			}
		}
		return nil
	}
	return e
}

func (e *eventChainChecker) HasAncestor(idx int, cs ...ProcessChecker) *eventChainChecker {
	oldEventCheck := e.eventCheck
	e.eventCheck = func(e fgsEvent, l Logger) error {
		if err := oldEventCheck(e, l); err != nil {
			return err
		}

		ev, ok := e.(interface{ GetAncestors() []*fgs.Process })
		if !ok {
			return fmt.Errorf("type %T does not have ancestors", e)
		}

		ancestors := ev.GetAncestors()
		if idx < 0 || len(ancestors) <= idx {
			return fmt.Errorf("event has %d ancestors: index %d is invalid", len(ancestors), idx)
		}

		process := ancestors[idx]
		if process == nil {
			return fmt.Errorf("ancestor idx=%d is nil", idx)
		}
		for i := range cs {
			if err := cs[i].Check(process, l); err != nil {
				return fmt.Errorf("ancestor check failed: %w", err)
			}
		}
		return nil
	}
	return e
}

// PodCheckerAND can be used to build a check that is a conjunction of other checkers
type PodCheckerAND struct {
	checks []PodChecker
}

func NewPodChecker() *PodCheckerAND {
	return &PodCheckerAND{}
}

func (o *PodCheckerAND) Check(p *fgs.Pod, l Logger) error {
	for i := range o.checks {
		if err := o.checks[i].Check(p, l); err != nil {
			return err
		}
	}
	return nil
}

func podWithString(
	sm StringMatcher,
	getter func(p *fgs.Pod) string,
	desc string, // desc is used for helpful error messages
) PodChecker {
	matcher := sm.GetMatcher()
	return PodCheckerFn(func(p *fgs.Pod, log Logger) error {
		if p == nil {
			return fmt.Errorf("pod is nil and cannot match %s using %v", desc, sm)
		}
		s := getter(p)
		if err := matcher(s); err != nil {
			return fmt.Errorf("failed check on %s: %w", desc, err)
		}
		log.Logf("**** MATCH on %s: %s", desc, s)
		return nil
	})
}

func PodWithName(sm StringMatcher) PodChecker {
	return podWithString(
		sm,
		func(p *fgs.Pod) string {
			return p.Name
		},
		"pod-name",
	)
}

func PodWithNamespace(sm StringMatcher) PodChecker {
	return podWithString(
		sm,
		func(p *fgs.Pod) string {
			return p.Namespace
		},
		"pod-namespace",
	)
}

func (o *PodCheckerAND) WithName(arg StringArg) *PodCheckerAND {
	sm := stringMatcherFromArg(arg)
	o.checks = append(o.checks, PodWithName(sm))
	return o
}

func (o *PodCheckerAND) WithNamePrefix(prefix string) *PodCheckerAND {
	sm := PrefixStringMatch(prefix)
	o.checks = append(o.checks, PodWithName(sm))
	return o
}

func (o *PodCheckerAND) WithNamespace(arg StringArg) *PodCheckerAND {
	sm := stringMatcherFromArg(arg)
	o.checks = append(o.checks, PodWithNamespace(sm))
	return o
}

func PodWithLabels(labels ...LabelMatch) PodChecker {
	labelMatchers := make(map[string]func(string) error)
	for i := range labels {
		labelMatchers[labels[i].Key] = labels[i].Val.GetMatcher()
	}

	// build a warning that we can pass to the closure below and inform the
	// user that something might be wrong
	warn := ""
	if len(labelMatchers) != len(labels) {
		warn = fmt.Sprintf("Warning: WithLabels() argument %+v has colliding keys", labels)
	}

	return PodCheckerFn(func(p *fgs.Pod, l Logger) error {
		if warn != "" {
			l.Logf(warn)
		}
		matchedLabels := map[string]struct{}{}
		for _, label := range p.Labels {
			kv := strings.SplitN(label, "=", 2)
			if len(kv) != 2 {
				l.Logf("label %s does not match key=val format. Ignoring", label)
				continue
			}
			key := kv[0]
			val := kv[1]
			if matcher, ok := labelMatchers[key]; ok {
				if err := matcher(val); err != nil {
					return fmt.Errorf("label %s mismatch: %w", key, err)
				}
			}
			matchedLabels[key] = struct{}{}
		}

		if len(matchedLabels) != len(labelMatchers) {
			unMatchedLabels := []string{}
			for k, _ := range labelMatchers {
				if _, ok := matchedLabels[k]; !ok {
					unMatchedLabels = append(unMatchedLabels, k)
				}
			}
			if len(unMatchedLabels) > 0 {
				return fmt.Errorf("unmatched labels: %+v", unMatchedLabels)
			}
		}

		l.Logf("**** MATCH on %s: %s", "labels", p.Labels)
		return nil
	})
}

// WithLabels will try and match all the given labels. Specifically, it will
// check that the argument labels are a _subset_ of the pod labels.
func (o *PodCheckerAND) WithLabels(labels ...LabelMatch) *PodCheckerAND {
	o.checks = append(o.checks, PodWithLabels(labels...))
	return o
}

type ContainerCheckerAND struct {
	checks []ContainerChecker
}

func NewContainerChecker() *ContainerCheckerAND {
	return &ContainerCheckerAND{}
}

func (o *ContainerCheckerAND) Check(p *fgs.Container, l Logger) error {
	for i := range o.checks {
		if err := o.checks[i].Check(p, l); err != nil {
			return err
		}
	}
	return nil
}

func PodWithContainer(cc ContainerChecker) PodChecker {
	return PodCheckerFn(func(p *fgs.Pod, log Logger) error {
		if p == nil {
			return fmt.Errorf("pod is nil and cannot match container")
		}
		if err := cc.Check(p.Container, log); err != nil {
			return fmt.Errorf("failed check on %s: %w", "container", err)
		}
		return nil
	})
}

func (o *PodCheckerAND) WithContainer(arg ContainerChecker) *PodCheckerAND {
	o.checks = append(o.checks, PodWithContainer(arg))
	return o
}

func containerWithString(
	sm StringMatcher,
	getter func(p *fgs.Container) string,
	desc string, // desc is used for helpful error messages
) ContainerChecker {
	matcher := sm.GetMatcher()
	return ContainerCheckerFn(func(c *fgs.Container, log Logger) error {
		if c == nil {
			return fmt.Errorf("container is nil and cannot match %s using %v", desc, sm)
		}
		s := getter(c)
		if err := matcher(s); err != nil {
			return fmt.Errorf("failed check on %s: %w", desc, err)
		}
		log.Logf("**** MATCH on %s: %s", desc, s)
		return nil
	})
}

func ContainerWithName(sm StringMatcher) ContainerChecker {
	return containerWithString(
		sm,
		func(c *fgs.Container) string {
			return c.Name
		},
		"container-name",
	)
}

func (o *ContainerCheckerAND) WithName(arg StringArg) *ContainerCheckerAND {
	sm := stringMatcherFromArg(arg)
	o.checks = append(o.checks, ContainerWithName(sm))
	return o
}

func (o *ContainerCheckerAND) WithNamePrefix(prefix string) *ContainerCheckerAND {
	sm := PrefixStringMatch(prefix)
	o.checks = append(o.checks, ContainerWithName(sm))
	return o
}

func ContainerWithID(sm StringMatcher) ContainerChecker {
	return containerWithString(
		sm,
		func(c *fgs.Container) string {
			return c.Id
		},
		"container-id",
	)
}

func ContainerWithImageName(sm StringMatcher) ContainerChecker {
	matcher := sm.GetMatcher()
	return ContainerCheckerFn(func(c *fgs.Container, log Logger) error {
		desc := "container-image-name"
		if c == nil {
			return fmt.Errorf("container is nil and cannot match %s using %v", desc, sm)
		}
		if c.Image == nil {
			return fmt.Errorf("container is nil and cannot match %s using %v", desc, sm)
		}
		s := c.Image.Name
		if err := matcher(s); err != nil {
			return fmt.Errorf("failed check on %s: %w", desc, err)
		}
		log.Logf("**** MATCH on %s: %s", desc, s)
		return nil
	})
}

func (o *ContainerCheckerAND) WithImageName(arg StringArg) *ContainerCheckerAND {
	sm := stringMatcherFromArg(arg)
	o.checks = append(o.checks, ContainerWithImageName(sm))
	return o
}

type HttpChecker interface {
	// Check checks a HTTP event
	Check(*fgs.ProcessHttp, Logger) error
}

type HttpCheckerFn func(*fgs.ProcessHttp, Logger) error

func (f HttpCheckerFn) Check(c *fgs.ProcessHttp, log Logger) error {
	return f(c, log)
}

func httpWithString(
	sm StringMatcher,
	getter func(*fgs.ProcessHttp) string,
	desc string, // desc is used for helpful error messages
) HttpChecker {
	matcher := sm.GetMatcher()
	return HttpCheckerFn(func(t *fgs.ProcessHttp, log Logger) error {
		if t == nil {
			return fmt.Errorf("Http is nil and cannot match %s using %v", desc, sm)
		}
		s := getter(t)
		if err := matcher(s); err != nil {
			return fmt.Errorf("failed http check on %s: %w", desc, err)
		}
		log.Logf("**** MATCH Http on %s: %s", desc, s)
		return nil
	})
}

func HttpWithRequestMethod(sm StringMatcher) HttpChecker {
	return httpWithString(
		sm,
		func(t *fgs.ProcessHttp) string {
			return t.Http.Request.Method
		},
		"Method",
	)
}

func HttpWithRequestUri(sm StringMatcher) HttpChecker {
	return httpWithString(
		sm,
		func(t *fgs.ProcessHttp) string {
			return t.Http.Request.Uri
		},
		"Uri",
	)
}

func HttpWithRequestVersion(sm StringMatcher) HttpChecker {
	return httpWithString(
		sm,
		func(t *fgs.ProcessHttp) string {
			return t.Http.Request.Version
		},
		"Version",
	)
}

func HttpWithRequestHost(sm StringMatcher) HttpChecker {
	return httpWithString(
		sm,
		func(t *fgs.ProcessHttp) string {
			return t.Http.Request.Host
		},
		"Host",
	)
}

func HttpWithRequestAgent(sm StringMatcher) HttpChecker {
	return httpWithString(
		sm,
		func(t *fgs.ProcessHttp) string {
			return t.Http.Request.Agent
		},
		"Agent",
	)
}

func HttpWithResponseVersion(sm StringMatcher) HttpChecker {
	return httpWithString(
		sm,
		func(t *fgs.ProcessHttp) string {
			return t.Http.Response.Version
		},
		"ResponseVersion",
	)
}

func HttpWithResponseReason(sm StringMatcher) HttpChecker {
	return httpWithString(
		sm,
		func(t *fgs.ProcessHttp) string {
			return t.Http.Response.Reason
		},
		"ResponseReason",
	)
}

func HttpWithResponseCode(code uint32) HttpChecker {
	return HttpCheckerFn(func(t *fgs.ProcessHttp, log Logger) error {
		if t == nil {
			return fmt.Errorf("Http is nil and cannot match Response.Code using %d", code)
		}
		if t.Http.Response.Code != code {
			return fmt.Errorf("expected status code to be %d but got %d", code, t.Http.Response.Code)
		}
		log.Logf("**** MATCH Http on Response.Code: %d", code)
		return nil
	})
}

type HttpCheckerAND struct {
	checks []HttpChecker
}

func NewHttpChecker() *HttpCheckerAND {
	return &HttpCheckerAND{}
}

func (o *HttpCheckerAND) Check(t *fgs.ProcessHttp, l Logger) error {
	for i := range o.checks {
		if err := o.checks[i].Check(t, l); err != nil {
			return err
		}
	}
	return nil
}

// WithRequestMethod adds a Request.Method check to a Http checker
func (o *HttpCheckerAND) WithRequestMethod(arg StringArg) *HttpCheckerAND {
	sm := stringMatcherFromArg(arg)
	o.checks = append(o.checks, HttpWithRequestMethod(sm))
	return o
}

func (o *HttpCheckerAND) WithRequestUri(arg StringArg) *HttpCheckerAND {
	sm := stringMatcherFromArg(arg)
	o.checks = append(o.checks, HttpWithRequestUri(sm))
	return o
}

func (o *HttpCheckerAND) WithRequestVersion(arg StringArg) *HttpCheckerAND {
	sm := stringMatcherFromArg(arg)
	o.checks = append(o.checks, HttpWithRequestVersion(sm))
	return o
}

func (o *HttpCheckerAND) WithRequestHost(arg StringArg) *HttpCheckerAND {
	sm := stringMatcherFromArg(arg)
	o.checks = append(o.checks, HttpWithRequestHost(sm))
	return o
}

func (o *HttpCheckerAND) WithRequestAgent(arg StringArg) *HttpCheckerAND {
	sm := stringMatcherFromArg(arg)
	o.checks = append(o.checks, HttpWithRequestAgent(sm))
	return o
}

func (o *HttpCheckerAND) WithResponseVersion(arg StringArg) *HttpCheckerAND {
	sm := stringMatcherFromArg(arg)
	o.checks = append(o.checks, HttpWithResponseVersion(sm))
	return o
}

func (o *HttpCheckerAND) WithResponseReason(arg StringArg) *HttpCheckerAND {
	sm := stringMatcherFromArg(arg)
	o.checks = append(o.checks, HttpWithResponseReason(sm))
	return o
}
func (o *HttpCheckerAND) WithResponseCode(code uint32) *HttpCheckerAND {
	o.checks = append(o.checks, HttpWithResponseCode(code))
	return o
}

func (e *eventChainChecker) HasHttp(httpcheck HttpChecker) *eventChainChecker {
	oldEventCheck := e.eventCheck
	e.eventCheck = func(e fgsEvent, l Logger) error {
		if err := oldEventCheck(e, l); err != nil {
			return err
		}

		if httpEv, ok := e.(*fgs.ProcessHttp); ok {
			return httpcheck.Check(httpEv, l)
		}
		return fmt.Errorf("event has type %T: not a http event", e)

	}
	return e
}

type TlsChecker interface {
	// Check checks a TLS event
	Check(*fgs.Tls, Logger) error
}

type TlsCheckerFn func(*fgs.Tls, Logger) error

func (f TlsCheckerFn) Check(c *fgs.Tls, log Logger) error {
	return f(c, log)
}

func tlsWithString(
	sm StringMatcher,
	getter func(*fgs.Tls) string,
	desc string, // desc is used for helpful error messages
) TlsChecker {
	matcher := sm.GetMatcher()
	return TlsCheckerFn(func(t *fgs.Tls, log Logger) error {
		if t == nil {
			return fmt.Errorf("tls is nil and cannot match %s using %v", desc, sm)
		}
		s := getter(t)
		if err := matcher(s); err != nil {
			return fmt.Errorf("failed tls check on %s: %w", desc, err)
		}
		log.Logf("**** MATCH tls on %s: %s", desc, s)
		return nil
	})
}

// TlsWithNegotiatedVersion matches the NegotiatedVersion field
func TlsWithNegotiatedVersion(sm StringMatcher) TlsChecker {
	return tlsWithString(
		sm,
		func(t *fgs.Tls) string {
			return t.NegotiatedVersion
		},
		"NegotiatedVersion",
	)
}

// TlsWithClientVersion matches the ClientVersion field
func TlsWithClientVersion(sm StringMatcher) TlsChecker {
	return tlsWithString(
		sm,
		func(t *fgs.Tls) string {
			return t.ClientVersion
		},
		"ClientVersion",
	)
}

// TlsWithServerVersion matches the ServerVersion field
func TlsWithServerVersion(sm StringMatcher) TlsChecker {
	return tlsWithString(
		sm,
		func(t *fgs.Tls) string {
			return t.ServerVersion
		},
		"ServerVersion",
	)
}

// TlsWithSniType matches the SniType field
func TlsWithSniType(sm StringMatcher) TlsChecker {
	return tlsWithString(
		sm,
		func(t *fgs.Tls) string {
			return t.SniType
		},
		"SniType",
	)
}

// TlsWithSniName matches the SniName field
func TlsWithSniName(sm StringMatcher) TlsChecker {
	return tlsWithString(
		sm,
		func(t *fgs.Tls) string {
			return t.SniName
		},
		"SniName",
	)
}

// TlsWithClientFlags matches the ClientFlags field
func TlsWithClientFlags(sm StringMatcher) TlsChecker {
	return tlsWithString(
		sm,
		func(t *fgs.Tls) string {
			return t.ClientFlags
		},
		"ClientFlags",
	)
}

// TlsWithServerFlags matches the ServerFlags field
func TlsWithServerFlags(sm StringMatcher) TlsChecker {
	return tlsWithString(
		sm,
		func(t *fgs.Tls) string {
			return t.ServerFlags
		},
		"ServerFlags",
	)
}

// TlsWithCertificates matches the Certificates field
// NB: eventually we might want other type of matches for matching a list such
// as subset checks, but for now we check that the elemnts of the lists match
// one-by-one.
func TlsWithCertificates(matchers []StringMatcher) TlsChecker {
	return TlsCheckerFn(func(t *fgs.Tls, log Logger) error {
		if t == nil {
			return fmt.Errorf("tls is nil and cannot match matchers: %+v", matchers)
		}

		if len(t.Certificates) != len(matchers) {
			return fmt.Errorf("failed to match tls certificates of length %d to matchers: %+v", len(t.Certificates), matchers)
		}

		for i := range t.Certificates {
			matcher := matchers[i].GetMatcher()
			cert := t.Certificates[i]
			if err := matcher(cert); err != nil {
				return fmt.Errorf("failed check certificate %s (idx=%d): %w", cert, i, err)
			}
		}

		log.Logf("**** MATCH tls certificates: %s", t.Certificates)
		return nil
	})
}

type TlsCheckerAND struct {
	checks []TlsChecker
}

func NewTlsChecker() *TlsCheckerAND {
	return &TlsCheckerAND{}
}

func (o *TlsCheckerAND) Check(t *fgs.Tls, l Logger) error {
	for i := range o.checks {
		if err := o.checks[i].Check(t, l); err != nil {
			return err
		}
	}
	return nil
}

// WithNegotiatedVersion adds a NegotiatedVersion check to a Tls checker
func (o *TlsCheckerAND) WithNegotiatedVersion(arg StringArg) *TlsCheckerAND {
	sm := stringMatcherFromArg(arg)
	o.checks = append(o.checks, TlsWithNegotiatedVersion(sm))
	return o
}

// WithClientVersion adds a ClientVersion check to a Tls checker
func (o *TlsCheckerAND) WithClientVersion(arg StringArg) *TlsCheckerAND {
	sm := stringMatcherFromArg(arg)
	o.checks = append(o.checks, TlsWithClientVersion(sm))
	return o
}

// WithServerVersion adds a ServerVersion check to a Tls checker
func (o *TlsCheckerAND) WithServerVersion(arg StringArg) *TlsCheckerAND {
	sm := stringMatcherFromArg(arg)
	o.checks = append(o.checks, TlsWithServerVersion(sm))
	return o
}

// WithSniType adds a SniType check to a Tls checker
func (o *TlsCheckerAND) WithSniType(arg StringArg) *TlsCheckerAND {
	sm := stringMatcherFromArg(arg)
	o.checks = append(o.checks, TlsWithSniType(sm))
	return o
}

// WithSniName adds a SniName check to a Tls checker
func (o *TlsCheckerAND) WithSniName(arg StringArg) *TlsCheckerAND {
	sm := stringMatcherFromArg(arg)
	o.checks = append(o.checks, TlsWithSniName(sm))
	return o
}

// WithClientFlags adds a ClientFlags check to a Tls checker
func (o *TlsCheckerAND) WithClientFlags(arg StringArg) *TlsCheckerAND {
	sm := stringMatcherFromArg(arg)
	o.checks = append(o.checks, TlsWithClientFlags(sm))
	return o
}

// WithServerFlags adds a ServerFlags check to a Tls checker
func (o *TlsCheckerAND) WithServerFlags(arg StringArg) *TlsCheckerAND {
	sm := stringMatcherFromArg(arg)
	o.checks = append(o.checks, TlsWithServerFlags(sm))
	return o
}

func (o *TlsCheckerAND) WithCertificates(args []StringArg) *TlsCheckerAND {
	matchers := make([]StringMatcher, len(args))
	for i := range args {
		matchers[i] = stringMatcherFromArg(args[i])
	}
	o.checks = append(o.checks, TlsWithCertificates(matchers))
	return o
}

func (e *eventChainChecker) HasTls(tlscheck TlsChecker) *eventChainChecker {
	oldEventCheck := e.eventCheck
	e.eventCheck = func(e fgsEvent, l Logger) error {
		if err := oldEventCheck(e, l); err != nil {
			return err
		}

		if tlsEv, ok := e.(*fgs.Tls); ok {
			return tlscheck.Check(tlsEv, l)
		}
		return fmt.Errorf("event has type %T: not a tls event", e)

	}
	return e
}

type TracepointChecker interface {
	// Check checks a Tracepoint event
	Check(*fgs.ProcessTracepoint, Logger) error
}

type TracepointCheckerFn func(*fgs.ProcessTracepoint, Logger) error

func (f TracepointCheckerFn) Check(c *fgs.ProcessTracepoint, log Logger) error {
	return f(c, log)
}

type TracepointCheckerAND struct {
	checks []TracepointChecker
}

func (o *TracepointCheckerAND) Check(t *fgs.ProcessTracepoint, l Logger) error {
	for i := range o.checks {
		if err := o.checks[i].Check(t, l); err != nil {
			return err
		}
	}
	return nil
}

func NewTracepointChecker() *TracepointCheckerAND {
	return &TracepointCheckerAND{}
}

// WithSubsys adds a subystem check
func (o *TracepointCheckerAND) WithSubsys(arg StringArg) *TracepointCheckerAND {
	sm := stringMatcherFromArg(arg)
	matcher := sm.GetMatcher()
	check := TracepointCheckerFn(func(t *fgs.ProcessTracepoint, log Logger) error {
		if err := matcher(t.Subsys); err != nil {
			return fmt.Errorf("failed check on subsys: %w", err)
		}
		log.Logf("**** MATCH tracepoint subsys: %s", t.Subsys)
		return nil
	})
	o.checks = append(o.checks, check)
	return o
}

// WithEvent adds an event check
func (o *TracepointCheckerAND) WithEvent(arg StringArg) *TracepointCheckerAND {
	sm := stringMatcherFromArg(arg)
	matcher := sm.GetMatcher()
	check := TracepointCheckerFn(func(t *fgs.ProcessTracepoint, log Logger) error {
		if err := matcher(t.Event); err != nil {
			return fmt.Errorf("failed check on event: %w", err)
		}
		log.Logf("**** MATCH tracepoint event: %s", t.Event)
		return nil
	})
	o.checks = append(o.checks, check)
	return o
}

// TracepointWithArgs matches the Args field
// NB: eventually we might want other type of matches for matching a list such
// as subset checks, but for now we check that the elemnts of the lists match
// one-by-one.
func TracepointWithArgs(checkers []GenericArgChecker) TracepointChecker {
	return TracepointCheckerFn(func(t *fgs.ProcessTracepoint, log Logger) error {
		if t == nil {
			return fmt.Errorf("tracepoint is nil and cannot match checkers: %+v", checkers)
		}

		if len(t.Args) != len(checkers) {
			return fmt.Errorf("failed to match tracepoint args of length %d to checkers: %+v", len(t.Args), checkers)
		}

		for i := range t.Args {
			checkArg := checkers[i]
			arg := t.Args[i]
			if err := checkArg.Check(arg, log); err != nil {
				return fmt.Errorf("failed check arg %s (idx=%d): %w", arg, i, err)
			}
		}

		log.Logf("**** MATCH tracepoint args: %s", t.Args)
		return nil
	})
}

func (o *TracepointCheckerAND) WithArgs(argCheckers []GenericArgChecker) *TracepointCheckerAND {
	o.checks = append(o.checks, TracepointWithArgs(argCheckers))
	return o
}

// NewTracepointEventChecker creates a new eventChainChecker for tracepoint events
func NewTracepointEventChecker() *eventChainChecker {
	return &eventChainChecker{
		responseCheck: func(r *fgs.GetEventsResponse, l Logger) (error, fgsEvent) {
			return checkEvent(r, l, fgs.EventType_PROCESS_TRACEPOINT)
		},
		eventCheck: func(ev fgsEvent, l Logger) error {
			return nil
		},
	}
}

func (e *eventChainChecker) HasTracepoint(tpCheck TracepointChecker) *eventChainChecker {
	oldEventCheck := e.eventCheck
	e.eventCheck = func(e fgsEvent, l Logger) error {
		if err := oldEventCheck(e, l); err != nil {
			return err
		}

		if tpEv, ok := e.(*fgs.ProcessTracepoint); ok {
			return tpCheck.Check(tpEv, l)
		}
		return fmt.Errorf("event has type %T: not a tracepoint event", e)

	}
	return e
}

type KprobeChecker interface {
	// Check checks a generic kprobe event
	Check(*fgs.ProcessKprobe, Logger) error
}

type KprobeCheckerFn func(*fgs.ProcessKprobe, Logger) error

func (f KprobeCheckerFn) Check(c *fgs.ProcessKprobe, log Logger) error {
	return f(c, log)
}

type KprobeCheckerAND struct {
	checks []KprobeChecker
}

func (o *KprobeCheckerAND) Check(t *fgs.ProcessKprobe, l Logger) error {
	for i := range o.checks {
		if err := o.checks[i].Check(t, l); err != nil {
			return err
		}
	}
	return nil
}

func NewKprobeChecker() *KprobeCheckerAND {
	return &KprobeCheckerAND{}
}

// WithFunctionName adds a function name check
func (o *KprobeCheckerAND) WithFunctionName(arg StringArg) *KprobeCheckerAND {
	sm := stringMatcherFromArg(arg)
	matcher := sm.GetMatcher()
	check := KprobeCheckerFn(func(t *fgs.ProcessKprobe, log Logger) error {
		if err := matcher(t.FunctionName); err != nil {
			return fmt.Errorf("failed check on function name: %w", err)
		}
		log.Logf("**** MATCH kprobe function name: %s", t.FunctionName)
		return nil
	})
	o.checks = append(o.checks, check)
	return o
}

// KprobeWithArgs matches the Args field
// NB: eventually we might want other type of matches for matching a list such
// as subset checks, but for now we check that the elemnts of the lists match
// one-by-one.
func KprobeWithArgs(checkers []GenericArgChecker) KprobeChecker {
	return KprobeCheckerFn(func(k *fgs.ProcessKprobe, log Logger) error {
		if k == nil {
			return fmt.Errorf("kprobe is nil and cannot match checkers: %+v", checkers)
		}

		if len(k.Args) != len(checkers) {
			return fmt.Errorf("failed to match kprobe args of length %d to checkers: %+v", len(k.Args), checkers)
		}

		for i := range k.Args {
			checkArg := checkers[i]
			arg := k.Args[i]
			if err := checkArg.Check(arg, log); err != nil {
				return fmt.Errorf("failed check arg %s (idx=%d): %w", arg, i, err)
			}
		}

		log.Logf("**** MATCH kprobe args: %s", k.Args)
		return nil
	})
}

func (o *KprobeCheckerAND) WithArgs(argCheckers []GenericArgChecker) *KprobeCheckerAND {
	o.checks = append(o.checks, KprobeWithArgs(argCheckers))
	return o
}

// NewKprobeEventChecker creates a new eventChainChecker for tracepoint events
func NewKprobeEventChecker() *eventChainChecker {
	return &eventChainChecker{
		responseCheck: func(r *fgs.GetEventsResponse, l Logger) (error, fgsEvent) {
			return checkEvent(r, l, fgs.EventType_PROCESS_KPROBE)
		},
		eventCheck: func(ev fgsEvent, l Logger) error {
			return nil
		},
	}
}

func (e *eventChainChecker) HasKprobe(kpCheck KprobeChecker) *eventChainChecker {
	oldEventCheck := e.eventCheck
	e.eventCheck = func(e fgsEvent, l Logger) error {
		if err := oldEventCheck(e, l); err != nil {
			return err
		}

		if kpEv, ok := e.(*fgs.ProcessKprobe); ok {
			return kpCheck.Check(kpEv, l)
		}
		return fmt.Errorf("event has type %T: not a kprobe event", e)

	}
	return e
}

type GenericArgChecker interface {
	// Check checks a generic argument
	Check(*fgs.KprobeArgument, Logger) error
}

type GenericArgCheckerFn func(*fgs.KprobeArgument, Logger) error

func (f GenericArgCheckerFn) Check(c *fgs.KprobeArgument, log Logger) error {
	return f(c, log)
}

func GenericArgSizeCheck(val uint64) GenericArgChecker {
	return GenericArgCheckerFn(func(arg *fgs.KprobeArgument, log Logger) error {
		if sa, ok := arg.Arg.(*fgs.KprobeArgument_SizeArg); ok {
			if sa.SizeArg != val {
				return fmt.Errorf("failed size arg check: %d does not match %d", sa.SizeArg, val)
			}
			log.Logf("**** MATCH generic size arg with value %d", val)
			return nil
		}
		return fmt.Errorf("failed arg check: %T is not a size arg", arg.Arg)
	})
}

func GenericArgIsInt() GenericArgChecker {
	return GenericArgCheckerFn(func(arg *fgs.KprobeArgument, log Logger) error {
		if _, ok := arg.Arg.(*fgs.KprobeArgument_IntArg); ok {
			log.Logf("**** MATCH generic int arg")
			return nil
		}
		return fmt.Errorf("failed arg check: %T is not an int arg", arg.Arg)
	})
}

func GenericArgIntCheck(val int32) GenericArgChecker {
	return GenericArgCheckerFn(func(arg *fgs.KprobeArgument, log Logger) error {
		if ia, ok := arg.Arg.(*fgs.KprobeArgument_IntArg); ok {
			if ia.IntArg != val {
				return fmt.Errorf("failed int arg check: %d does not match %d", ia.IntArg, val)
			}
			log.Logf("**** MATCH generic int arg with value %d", val)
			return nil
		}
		return fmt.Errorf("failed arg check: %T is not an int arg", arg.Arg)
	})
}

func GenericArgBytesCheck(val []byte) GenericArgChecker {
	return GenericArgCheckerFn(func(arg *fgs.KprobeArgument, log Logger) error {
		if ba, ok := arg.Arg.(*fgs.KprobeArgument_BytesArg); ok {
			if len(ba.BytesArg) != len(val) {
				return fmt.Errorf("failed bytes arg check: length %d does not match length %d", len(ba.BytesArg), len(val))
			}
			for xi, xb := range ba.BytesArg {
				if xb != val[xi] {
					return fmt.Errorf("failed bytes arg check: byte %d is %x and does not match %x", xi, xb, val[xi])
				}
			}
			log.Logf("**** MATCH generic bytes arg with value %s", val)
			return nil
		}
		return fmt.Errorf("failed arg check: %T is not a bytes arg", arg.Arg)
	})
}

func GenericArgStringCheck(val StringArg) GenericArgChecker {
	sm := stringMatcherFromArg(val)
	matcher := sm.GetMatcher()
	return GenericArgCheckerFn(func(arg *fgs.KprobeArgument, log Logger) error {
		if sa, ok := arg.Arg.(*fgs.KprobeArgument_StringArg); ok {
			if err := matcher(sa.StringArg); err != nil {
				return fmt.Errorf("failed string arg check: %w", err)
			}
			log.Logf("**** MATCH generic string arg with value %s", val)
			return nil
		}
		return fmt.Errorf("failed arg check: %T is not a string arg", arg.Arg)
	})
}

func GenericArgFileChecker(mount, path StringArg) GenericArgChecker {
	smMount := stringMatcherFromArg(mount)
	smPath := stringMatcherFromArg(path)
	matcherMount := smMount.GetMatcher()
	matcherPath := smPath.GetMatcher()
	return GenericArgCheckerFn(func(arg *fgs.KprobeArgument, log Logger) error {
		if fa, ok := arg.Arg.(*fgs.KprobeArgument_FileArg); ok {
			if fa.FileArg == nil {
				return fmt.Errorf("failed file arg check because FileArg is nil")
			}
			if err := matcherMount(fa.FileArg.Mount); err != nil {
				return fmt.Errorf("failed file arg check on mountpoint: %w", err)
			}
			if err := matcherPath(fa.FileArg.Path); err != nil {
				return fmt.Errorf("failed file arg check on path: %w", err)
			}
			log.Logf("**** MATCH generic file arg: %+v", fa.FileArg)
			return nil
		}
		return fmt.Errorf("failed arg check: %T is not a file arg", arg.Arg)
	})
}

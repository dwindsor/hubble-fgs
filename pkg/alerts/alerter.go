// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package alerts

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"

	"cel.dev/cel-go/cel"
	"google.golang.org/grpc/metadata"

	"github.com/cilium/tetragon/pkg/filters"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/server"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/api/v1/tetragon/codegen/helpers"

	"github.com/isovalent/hubble-fgs/pkg/metrics/alertmetrics"
	"github.com/isovalent/hubble-fgs/pkg/option"
)

type Alerter interface {
	tetragon.AlertServiceServer
	Start(*server.Server) error
}

// alertListener is a per-GetAlerts-stream sink for matched alerts.
type alertListener struct {
	alerts   chan *tetragon.Alert
	req      *tetragon.GetAlertsRequest
	celProgs []alertCELProg
}

// alertCELProg pairs a compiled CEL program with the set of event names it
// references, so the filter can skip evaluation for unrelated event types
// (matching the OSS getevents --cel-expression behaviour).
type alertCELProg struct {
	program    cel.Program
	eventNames []string
}

// alerter implements a few interfaces:
// - Alerter, including AlertServiceServer from tetragon API
// - FineGuidanceSensors_GetEventsServer from tetragon API
// - Closer
//
// The two latter are necessary to pass alerter to the server.GetEventsWG
// method. This follows a similar flow as exporter.Exporter, but the Send
// method evaluates events against alert rules. Arguably server.GetEventsWG is
// quite tied to the events stream, so reusing it for alerting might be
// sub-optimal. Refactor if needed.
type alerter struct {
	ctx         context.Context
	ruleManager *AlertRuleManager
	listeners   []*alertListener
	listenersMu sync.Mutex
	tetragon.UnimplementedAlertServiceServer
}

func NewAlerter(ctx context.Context, r RuleManager) Alerter {
	return newAlerter(ctx, r)
}

func newAlerter(ctx context.Context, r RuleManager) *alerter {
	rm := r.(*AlertRuleManager)
	return &alerter{
		ruleManager: rm,
		ctx:         ctx,
		listeners:   make([]*alertListener, 0),
	}
}

func (a *alerter) addAlertListener(l *alertListener) {
	a.listenersMu.Lock()
	defer a.listenersMu.Unlock()
	a.listeners = append(a.listeners, l)
}

func (a *alerter) removeAlertListener(l *alertListener) {
	a.listenersMu.Lock()
	defer a.listenersMu.Unlock()
	for i, existing := range a.listeners {
		if existing == l {
			a.listeners = append(a.listeners[:i], a.listeners[i+1:]...)
			return
		}
	}
}

func (a *alerter) Send(event *tetragon.GetEventsResponse) error {
	err := a.evaluateRules(a.Context(), event)
	if err != nil {
		logger.GetLogger().Warn("Errors while evaluating event against alert rules.", logfields.Error, err)
	}
	return nil
}

func (a *alerter) SetHeader(metadata.MD) error {
	return nil
}

func (a *alerter) SendHeader(metadata.MD) error {
	return nil
}

func (a *alerter) SetTrailer(metadata.MD) {
}

func (a *alerter) Context() context.Context {
	return a.ctx
}

func (a *alerter) SendMsg(any) error {
	return nil
}

func (a *alerter) RecvMsg(any) error {
	return nil
}

func (a *alerter) Close() error {
	var errs error
	a.ruleManager.mutex.RLock()
	defer a.ruleManager.mutex.RUnlock()
	for _, r := range a.ruleManager.rules {
		if r.jsonEncoder != nil {
			err := r.jsonEncoder.writer.Close()
			if err != nil {
				errs = errors.Join(errs, fmt.Errorf("failed to close JSON log file: %w", err))
			}
		}
	}
	return errs
}

// This is a very inefficient implementation, as we evaluate every single event
// against every single rule, regardless of the event type. Optimize as needed.
func (a *alerter) evaluateRules(ctx context.Context, event *tetragon.GetEventsResponse) error {
	// First we get the details about the event such as the name ("process_exec")
	// and a casted pointer (*tetragon.ProcessExec) to the actual event. The third
	// return value is always nil but casted to the appropriate type in order
	// not to cause issues with the CEL evaluation.
	evName, evData, evDefer := helpers.ProcessEventMapTuple(event)
	// Set to the empty map the appropriate value in the correct position.
	a.ruleManager.eventMap[evName] = evData
	defer func() {
		// When we are done make that nil again.
		// evDefer is nil but casted to the appropriate type (i.e. (*tetragon.ProcessExec)(nil)).
		// If we used nil here (without the cast) we were getting errors similar to:
		// "error running CEL program: unsupported field selection target: (<nil>)<nil>"
		a.ruleManager.eventMap[evName] = evDefer
	}()

	// Snapshot rules under RLock; gRPC AddAlertRule/DeleteAlertRule may race
	// with this iteration. *rule is immutable after insertion, so snapshotted
	// pointers remain safe to use after release.
	a.ruleManager.mutex.RLock()
	rules := make([]*rule, 0, len(a.ruleManager.rules))
	for _, r := range a.ruleManager.rules {
		for _, n := range r.eventNames {
			if !reflect.ValueOf(a.ruleManager.eventMap[n]).IsNil() {
				rules = append(rules, r)
				break
			}
		}
	}
	a.ruleManager.mutex.RUnlock()

	var errs error
	for _, r := range rules {
		// Evaluate the rule
		var timer time.Time
		if option.Config.EnableAlertProfiling {
			timer = time.Now()
		}
		match, err := filters.EvalCEL(ctx, r.cel, a.ruleManager.eventMap)
		if err != nil {
			// Track evaluation errors
			alertmetrics.AlertRuleEvaluationErrors.WithLabelValues(r.name).Inc()
			errs = errors.Join(errs, fmt.Errorf("failed to evaluate rule CEL expression: %w", err))
			continue
		}
		if option.Config.EnableAlertProfiling {
			alertmetrics.RecordAlertTime(r.name, float64(time.Since(timer).Microseconds()))
		}

		// If we have a match, track it and process the alert
		if match {
			// Use the helper function to record metrics for this alert match
			alertmetrics.RecordAlertMatch(r.name, r.severity)

			// Handle alert output
			alert := eventToAlert(event, r)
			if r.jsonEncoder != nil {
				err = r.jsonEncoder.encode(alert, r.rateLimiter)
				if err != nil {
					errs = errors.Join(errs, fmt.Errorf("failed to export alert to JSON log file: %w", err))
					continue
				}
			}
			a.notifyListeners(ctx, alert)
		}
	}
	return errs
}

func (a *alerter) notifyListeners(ctx context.Context, alert *tetragon.Alert) {
	a.listenersMu.Lock()
	listeners := make([]*alertListener, len(a.listeners))
	copy(listeners, a.listeners)
	a.listenersMu.Unlock()
	for _, l := range listeners {
		if !alertMatchesListener(ctx, alert, l) {
			continue
		}
		select {
		case l.alerts <- alert:
		default:
			logger.GetLogger().Warn("Alert listener channel full, dropping alert",
				"rule", alert.GetRule().GetName())
		}
	}
}

// alertMatchesListener returns true if the alert should be forwarded to a
// listener based on its request filters.
func alertMatchesListener(ctx context.Context, alert *tetragon.Alert, l *alertListener) bool {
	if len(l.req.GetAlertRuleNames()) > 0 {
		matched := false
		if slices.Contains(l.req.GetAlertRuleNames(), alert.GetRule().GetName()) {
			matched = true
		}
		if !matched {
			return false
		}
	}
	if len(l.celProgs) == 0 {
		return true
	}
	// Build a fully-populated empty event map (all keys present as typed-nil)
	// and overwrite the single key corresponding to this alert's inner event.
	// This mirrors filters.filterByCELExpression so CEL programs that reference
	// other event types evaluate without "no such attribute" errors.
	evName, evData, _ := helpers.ProcessEventMapTuple(alert.GetEvent())
	eventMap := helpers.ProcessEventMapEmpty()
	eventMap[evName] = evData
	// OR semantics across multiple --cel-expression values, matching OSS
	// getevents. Programs whose declared event names don't match the current
	// event are skipped (not treated as non-matching).
	for _, prog := range l.celProgs {
		related := false
		for _, n := range prog.eventNames {
			if !reflect.ValueOf(eventMap[n]).IsNil() {
				related = true
				break
			}
		}
		if !related {
			continue
		}
		match, err := filters.EvalCEL(ctx, prog.program, eventMap)
		if err != nil {
			logger.GetLogger().Warn("Alert listener CEL evaluation error",
				logfields.Error, err)
			continue
		}
		if match {
			return true
		}
	}
	return false
}

func (a *alerter) GetAlerts(req *tetragon.GetAlertsRequest, stream tetragon.AlertService_GetAlertsServer) error {
	var celProgs []alertCELProg
	for _, expr := range req.GetCelExpression() {
		prog, eventNames, err := cef.CompileCEL(expr)
		if err != nil {
			return fmt.Errorf("invalid CEL expression %q: %w", expr, err)
		}
		celProgs = append(celProgs, alertCELProg{program: prog, eventNames: eventNames})
	}
	l := &alertListener{
		alerts:   make(chan *tetragon.Alert, 1000),
		req:      req,
		celProgs: celProgs,
	}
	a.addAlertListener(l)
	defer a.removeAlertListener(l)
	for {
		select {
		case alert := <-l.alerts:
			if err := stream.Send(alert); err != nil {
				return err
			}
		case <-stream.Context().Done():
			return stream.Context().Err()
		case <-a.ctx.Done():
			return a.ctx.Err()
		}
	}
}

func eventToAlert(event *tetragon.GetEventsResponse, r *rule) *tetragon.Alert {
	return &tetragon.Alert{
		Event: event,
		Rule:  ruleToMeta(r),
	}
}

func ruleToMeta(r *rule) *tetragon.AlertRuleMeta {
	return &tetragon.AlertRuleMeta{
		Name:               r.name,
		Severity:           tetragon.AlertRuleMeta_Severity(tetragon.AlertRuleMeta_Severity_value[strings.ToUpper(r.severity)]),
		Message:            r.message,
		Tags:               r.tags,
		RiskScore:          int32(r.riskScore),
		RateLimitTriggered: false,
		Domain:             r.domain,
	}
}

func ruleToProto(r *rule) *tetragon.AlertRule {
	return &tetragon.AlertRule{
		Meta: ruleToMeta(r),
	}
}

func (a *alerter) AddAlertRuleFromYAML(_ context.Context, req *tetragon.AddAlertRuleFromYAMLRequest) (*tetragon.AddAlertRuleResponse, error) {
	ar, err := RuleFromYAML(req.Yaml)
	if err != nil {
		return nil, err
	}

	domain := server.GrpcDomain
	if req.Domain != "" {
		domain = req.Domain
	}
	ar.Domain = domain

	err = a.ruleManager.AddAlertRule(ar)
	if err != nil {
		return nil, err
	}
	return &tetragon.AddAlertRuleResponse{
		Rule: &tetragon.AlertRule{
			Meta: &tetragon.AlertRuleMeta{
				Name:      ar.Name,
				Severity:  tetragon.AlertRuleMeta_Severity(tetragon.AlertRuleMeta_Severity_value[strings.ToUpper(ar.Spec.Severity)]),
				Message:   ar.Spec.Message,
				Tags:      ar.Spec.Tags,
				RiskScore: int32(ar.Spec.RiskScore),
			},
		},
	}, nil
}

func (a *alerter) DeleteAlertRule(_ context.Context, req *tetragon.DeleteAlertRuleRequest) (*tetragon.DeleteAlertRuleResponse, error) {
	domain := server.GrpcDomain
	if req.Domain != "" {
		domain = req.Domain
	}
	a.ruleManager.DeleteAlertRule(req.Name, domain)
	return &tetragon.DeleteAlertRuleResponse{}, nil
}

func (a *alerter) ListAlertRules(_ context.Context, req *tetragon.ListAlertRulesRequest) (*tetragon.ListAlertRulesResponse, error) {
	rules := make([]*tetragon.AlertRule, 0, len(a.ruleManager.rules))
	a.ruleManager.mutex.RLock()
	defer a.ruleManager.mutex.RUnlock()
	for key, r := range a.ruleManager.rules {
		if req.Domain == "" || key.domain == req.Domain {
			rules = append(rules, ruleToProto(r))
		}
	}
	return &tetragon.ListAlertRulesResponse{Rules: rules}, nil
}

func (a *alerter) GetAlertRule(_ context.Context, req *tetragon.GetAlertRuleRequest) (*tetragon.GetAlertRuleResponse, error) {
	domain := server.GrpcDomain
	if req.Domain != "" {
		domain = req.Domain
	}

	key := collectionKey{
		domain: domain,
		name:   req.Name,
	}
	a.ruleManager.mutex.RLock()
	r, ok := a.ruleManager.rules[key]
	a.ruleManager.mutex.RUnlock()

	if !ok {
		return nil, fmt.Errorf("rule not found: %s", req.Name)
	}
	return &tetragon.GetAlertRuleResponse{Rule: ruleToProto(r)}, nil
}

func (a *alerter) Start(server *server.Server) error {
	run, err := server.GetEventsListener(&tetragon.GetEventsRequest{}, a, a)
	if err != nil {
		return fmt.Errorf("error starting alerter: %w", err)
	}
	go func() {
		if err = run(); err != nil {
			logger.GetLogger().Warn("JSON exporter terminated with error", logfields.Error, err)
		}
	}()
	return nil
}

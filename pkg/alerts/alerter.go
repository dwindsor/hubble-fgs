//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package alerts

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/cilium/tetragon/pkg/logger/logfields"
	"google.golang.org/grpc/metadata"

	"github.com/cilium/tetragon/pkg/filters"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/server"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/api/v1/tetragon/codegen/helpers"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"

	"github.com/isovalent/hubble-fgs/pkg/metrics/alertmetrics"
	"github.com/isovalent/hubble-fgs/pkg/option"
)

type Alerter interface {
	tetragon.AlertServiceServer
	Start(*server.Server) error
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
	ruleManager *ruleManager
	tetragon.UnimplementedAlertServiceServer
}

func NewAlerter(ctx context.Context, r RuleManager) Alerter {
	return newAlerter(ctx, r)
}

func newAlerter(ctx context.Context, r RuleManager) *alerter {
	rm := r.(*ruleManager)
	return &alerter{
		ruleManager: rm,
		ctx:         ctx,
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

	// keep only the rules that are related to that event
	rules := []*rule{}
	for _, r := range a.ruleManager.rules {
		for _, n := range r.eventNames {
			if !reflect.ValueOf(a.ruleManager.eventMap[n]).IsNil() { // is the incoming event related to that alert?
				rules = append(rules, r)
				break
			}
		}
	}

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
			if r.jsonEncoder != nil {
				alert := eventToAlert(event, r)
				err = r.jsonEncoder.encode(alert)
				if err != nil {
					errs = errors.Join(errs, fmt.Errorf("failed to export alert to JSON log file: %w", err))
					continue
				}
			}
		}
	}
	return errs
}

func eventToAlert(event *tetragon.GetEventsResponse, r *rule) *tetragon.Alert {
	return &tetragon.Alert{
		Event: event,
		Rule:  ruleToMeta(r),
	}
}

func ruleToMeta(r *rule) *tetragon.AlertRuleMeta {
	return &tetragon.AlertRuleMeta{
		Name:      r.name,
		Severity:  tetragon.AlertRuleMeta_Severity(tetragon.AlertRuleMeta_Severity_value[strings.ToUpper(r.severity)]),
		Message:   r.message,
		Tags:      r.tags,
		RiskScore: int32(r.riskScore),
	}
}

func ruleToProto(r *rule) *tetragon.AlertRule {
	return &tetragon.AlertRule{
		Meta: ruleToMeta(r),
	}
}

func (a *alerter) AddAlertRuleFromYAML(_ context.Context, req *tetragon.AddAlertRuleFromYAMLRequest) (*tetragon.AddAlertRuleResponse, error) {
	obj, err := FromYAML(req.Yaml)
	if err != nil {
		return nil, err
	}
	ar, ok := obj.(*v1alpha1.AlertRule)
	if !ok {
		return nil, fmt.Errorf("unexpected object type: %T", obj)
	}
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
	a.ruleManager.DeleteAlertRule(req.Name)
	return &tetragon.DeleteAlertRuleResponse{}, nil
}

func (a *alerter) ListAlertRules(_ context.Context, _ *tetragon.ListAlertRulesRequest) (*tetragon.ListAlertRulesResponse, error) {
	rules := make([]*tetragon.AlertRule, 0, len(a.ruleManager.rules))
	a.ruleManager.mutex.RLock()
	defer a.ruleManager.mutex.RUnlock()
	for _, r := range a.ruleManager.rules {
		rules = append(rules, ruleToProto(r))
	}
	return &tetragon.ListAlertRulesResponse{Rules: rules}, nil
}

func (a *alerter) GetAlertRule(_ context.Context, req *tetragon.GetAlertRuleRequest) (*tetragon.GetAlertRuleResponse, error) {
	r, ok := a.ruleManager.rules[req.Name]
	if !ok {
		return nil, fmt.Errorf("rule not found: %s", req.Name)
	}
	return &tetragon.GetAlertRuleResponse{Rule: ruleToProto(r)}, nil
}

func (a *alerter) Start(server *server.Server) error {
	var readyWG sync.WaitGroup
	var startErr error
	readyWG.Add(1)
	go func() {
		if err := server.GetEventsWG(&tetragon.GetEventsRequest{}, a, a, &readyWG); err != nil {
			startErr = fmt.Errorf("error starting alerter: %w", err)
		}
	}()
	readyWG.Wait()
	return startErr
}

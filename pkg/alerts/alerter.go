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
	"strings"
	"sync"

	"google.golang.org/grpc/metadata"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/filters"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/server"
)

// alerter implements FineGuidanceSensors_GetEventsServer interface from the
// tetragon API, like exporter.Exporter, with the Send method evaluating an
// event against alert rules. It also implements Closer interface. Both are
// necessary to pass it to the server.GetEventsWG method. Arguably
// server.GetEventsWG is quite tied to the events stream, so reusing it for
// alerting might be sub-optimal. Refactor if needed.
type alerter struct {
	ruleManager *ruleManager
	ctx         context.Context
}

func newAlerter(ctx context.Context) *alerter {
	return &alerter{
		ruleManager: newRuleManager(),
		ctx:         ctx,
	}
}

func (a *alerter) Send(event *tetragon.GetEventsResponse) error {
	err := a.evaluateRules(a.Context(), event)
	if err != nil {
		logger.GetLogger().WithError(err).Warning("Errors while evaluating event against alert rules.")
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
	var errs error
	for _, r := range a.ruleManager.rules {
		match, err := filters.EvalCEL(ctx, r.cel, event)
		if err != nil {
			errs = errors.Join(errs, fmt.Errorf("failed to evaluate rule CEL expression: %w", err))
			continue
		}
		if match {
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
		Rule: &tetragon.AlertRuleMeta{
			Name:     r.name,
			Severity: tetragon.AlertRuleMeta_Severity(tetragon.AlertRuleMeta_Severity_value[strings.ToUpper(r.severity)]),
			Message:  r.message,
			Tags:     r.tags,
		},
	}
}

func StartAlerting(ctx context.Context, server *server.Server) error {
	a := newAlerter(ctx)

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

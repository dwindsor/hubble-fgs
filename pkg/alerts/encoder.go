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
	"io"
	"sync/atomic"

	"golang.org/x/time/rate"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/cilium/tetragon/api/v1/tetragon"

	"github.com/isovalent/hubble-fgs/pkg/metrics/alertmetrics"
)

type jsonEncoder struct {
	writer      io.WriteCloser
	fname       string
	refCnt      atomic.Int32
	rateLimiter *rate.Limiter
	rateLimited bool
}

func newRateLimitedJsonEncoder(w io.WriteCloser, fname string, rateLimit *rate.Limiter) *jsonEncoder {
	// If passed rateLimit is nil, default at no limit
	// but, to avoid checking for nil, just limit to inf.
	if rateLimit == nil {
		rateLimit = rate.NewLimiter(rate.Inf, 0)
	}

	// Wrap the WriteCloser with our byte counter to track exported bytes
	ret := &jsonEncoder{
		writer:      alertmetrics.NewAlertExportedBytesCounterWriter(w),
		fname:       fname,
		rateLimiter: rateLimit,
	}
	ret.refCnt.Store(1)
	return ret
}

func newJsonEncoder(w io.WriteCloser, fname string) *jsonEncoder {
	return newRateLimitedJsonEncoder(w, fname, nil)
}

func (e *jsonEncoder) IncRef() {
	e.refCnt.Add(1)
}

func (e *jsonEncoder) DecRef() int32 {
	refCnt := e.refCnt.Add(-1)
	if refCnt == 0 {
		e.writer.Close()
	}
	return refCnt
}

func (e *jsonEncoder) encode(alert *tetragon.Alert) error {
	// encoder is closed, nothing to do
	if e.refCnt.Load() == 0 {
		return nil
	}

	// 3 cases:
	// * NOT ratelimited event -> update some metrics and marshal the alert event
	// * FIRST ratelimited event -> set the AlertRuleRateLimitActive metric,
	//   log a message and send an event that wraps an alert with additional `rateLimitEnabled: true`.
	// * OTHER ratelimited events -> set the AlertRuleRateLimitDropsTotal and skip the write.
	if e.rateLimiter.Allow() {
		if alert != nil && alert.Rule != nil {
			alertmetrics.AlertRuleRateLimitWindowUsage.WithLabelValues(alert.Rule.Name).Set(e.rateLimiter.Tokens())
			alertmetrics.AlertsExportedTotal.WithLabelValues(alert.Rule.Name).Inc()
		}
		if e.rateLimited {
			e.rateLimited = false
			if alert != nil && alert.Rule != nil {
				alertmetrics.AlertRuleRateLimitActive.WithLabelValues(alert.Rule.Name).Set(float64(0))
			}
		}
	} else {
		if !e.rateLimited {
			// First message rateLimited; send it anyway but wrap it to add the `rateLimitEnabled: true`
			e.rateLimited = true
			if alert != nil && alert.Rule != nil {
				alertmetrics.AlertRuleRateLimitActive.WithLabelValues(alert.Rule.Name).Set(float64(1))
				alert.Rule.RateLimitTriggered = true
			}
		} else {
			// Nothing to do. Skip encoding altogether.
			if alert != nil && alert.Rule != nil {
				alertmetrics.AlertRuleRateLimitDropsTotal.WithLabelValues(alert.Rule.Name).Inc()
			}
			return nil
		}
	}

	out, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(alert)
	if err != nil {
		return err
	}

	out = append(out, '\n')
	_, err = e.writer.Write(out)

	// only return an error if the encoder was not closed in the meantime
	if err != nil && e.refCnt.Load() > 0 {
		return err
	}
	return nil
}

// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package grpc

import (
	"context"
	"encoding/json"
	"sync/atomic"
	"time"

	"github.com/isovalent/hubble-fgs/pkg/logger"
	"golang.org/x/time/rate"
)

type RateLimiter struct {
	*rate.Limiter
	ctx            context.Context
	reportInterval time.Duration
	dropped        uint64 // accessed atomically
}

func NewRateLimiter(ctx context.Context, interval time.Duration, burst int, encoder *json.Encoder) *RateLimiter {
	if burst < 0 {
		return nil
	}
	r := &RateLimiter{
		rate.NewLimiter(rate.Every(interval), burst),
		ctx,
		interval, // TODO(tk): use a separate interval for reporting?
		0,
	}
	go r.reportRateLimitInfo(encoder)
	return r
}

type RateLimitInfo struct {
	NumberOfDroppedEvents uint64    `json:"number_of_dropped_events"`
	NodeName              string    `json:"node_name"`
	Time                  time.Time `json:"time"`
}

type RateLimitInfoEvent struct {
	*RateLimitInfo `json:"rate_limit_info"`
}

func (r *RateLimiter) reportRateLimitInfo(encoder *json.Encoder) {
	ticker := time.NewTicker(r.reportInterval)
	for {
		select {
		case <-ticker.C:
			dropped := atomic.SwapUint64(&r.dropped, 0)
			if dropped > 0 {
				err := encoder.Encode(&RateLimitInfoEvent{
					&RateLimitInfo{
						NumberOfDroppedEvents: dropped,
						NodeName:              getNodeNameForExport(),
						Time:                  time.Now(),
					},
				})
				if err != nil {
					logger.GetLogger().
						WithError(err).
						WithField("dropped", dropped).
						Warn("Failed to encode rate_limit_info event")
				}
			}
		case <-r.ctx.Done():
			return
		}
	}
}

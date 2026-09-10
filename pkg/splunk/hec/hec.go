// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

// Package hec ships the JSON records that Tetragon writes to its export
// files to a Splunk HTTP Event Collector.
package hec

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/reader/node"

	"github.com/isovalent/hubble-fgs/pkg/metrics/splunkhecmetrics"
	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"
)

const (
	// queueDepth is the number of records buffered between the export writers
	// and the sender. Records are dropped once it is full so that a slow or
	// unreachable collector never blocks a write to the export file.
	queueDepth = 8192

	// responseBodyLimit caps how much of an error response is read for logging.
	responseBodyLimit = 1024
)

type record struct {
	sourcetype string
	source     string
	payload    []byte
}

// Sink batches JSON records and POSTs them to a Splunk HTTP Event Collector.
// It is safe for concurrent use.
type Sink struct {
	config  *atomic.Pointer[Config]
	host    string
	client  *http.Client
	records chan record
	dropped atomic.Uint64
}

// NewSink returns a sink for the process-wide config. The sink does nothing
// until Start is called.
func NewSink() (*Sink, error) {
	cfg := GetConfig()
	return &Sink{
		config:  cfg,
		host:    node.GetNodeNameForExport(),
		client:  &http.Client{Timeout: cfg.Load().SplunkHECTimeout},
		records: make(chan record, queueDepth),
	}, nil
}

// Start launches the sender, which runs until ctx is cancelled.
func (s *Sink) Start(ctx context.Context) {
	go s.run(ctx)
}

// Writer returns an io.Writer that forwards the newline delimited JSON records
// written to it to the collector under the given sourcetype. Writes never fail
// and never block: records are dropped when the queue is full.
func (s *Sink) Writer(sourcetype string, source string) io.Writer {
	if s == nil {
		return nil
	}
	return &sinkWriter{sink: s, sourcetype: sourcetype, source: source}
}

// send queues one JSON record. It never blocks.
func (s *Sink) send(sourcetype string, source string, payload []byte) {
	select {
	case s.records <- record{sourcetype: sourcetype, source: source, payload: payload}:
	default:
		s.dropped.Add(1)
		splunkhecmetrics.RecordDropped(1)
	}
}

func (s *Sink) run(ctx context.Context) {
	ticker := time.NewTicker(s.config.Load().SplunkHECFlushInterval)
	defer ticker.Stop()

	var batch bytes.Buffer
	var count int
	sourcetypes := map[string]uint64{}
	lastDropped := uint64(0)

	flush := func(ctx context.Context) {
		if count == 0 {
			return
		}
		s.post(ctx, batch.Bytes(), count, sourcetypes)
		batch.Reset()
		count = 0
		sourcetypes = map[string]uint64{}
	}

	for {
		select {
		case <-ctx.Done():
			// The batch outlives ctx so that buffered records are still
			// delivered on shutdown.
			final, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.config.Load().SplunkHECTimeout)
			flush(final)
			cancel()
			return
		case <-ticker.C:
			flush(ctx)
			if dropped := s.dropped.Load(); dropped > lastDropped {
				logger.GetLogger().Warn("Dropped records destined for the Splunk HTTP Event Collector",
					"dropped", dropped-lastDropped, "total", dropped)
				lastDropped = dropped
			}
		case rec := <-s.records:
			envelope, err := s.envelope(rec)
			if enterpriseOption.Config.EnableSplunkHECDebug {
				logger.GetLogger().Debug("Sending record to the Splunk HTTP Event Collector",
					"sourcetype", rec.sourcetype, "source file", rec.source, "size", len(envelope), "payload", string(rec.payload))
			}
			if err != nil {
				logger.GetLogger().Warn("Failed to encode record for the Splunk HTTP Event Collector", logfields.Error, err)
				s.dropped.Add(1)
				splunkhecmetrics.RecordDropped(1)
				continue
			}
			if len(envelope) > s.config.Load().SplunkHECMaxContentLength {
				logger.GetLogger().Warn("Dropping record larger than the Splunk HTTP Event Collector content limit",
					"size", len(envelope), "limit", s.config.Load().SplunkHECMaxContentLength, "sourcetype", rec.sourcetype)
				s.dropped.Add(1)
				splunkhecmetrics.RecordDropped(1)
				continue
			}
			if batch.Len()+len(envelope) > s.config.Load().SplunkHECMaxContentLength {
				flush(ctx)
			}
			batch.Write(envelope)
			count++
			sourcetypes[rec.sourcetype]++
		}
	}
}

// envelope wraps a record in the HEC event envelope. The record is embedded as
// raw JSON so it is neither re-parsed nor re-serialized.
func (s *Sink) envelope(rec record) ([]byte, error) {
	if !json.Valid(rec.payload) {
		return nil, fmt.Errorf("record is not valid JSON")
	}
	return json.Marshal(struct {
		Time       float64         `json:"time"`
		Host       string          `json:"host,omitempty"`
		Sourcetype string          `json:"sourcetype,omitempty"`
		Source     string          `json:"source,omitempty"`
		Event      json.RawMessage `json:"event"`
	}{
		Time:       float64(time.Now().UnixMilli()) / 1000,
		Host:       s.host,
		Sourcetype: "cisco:isovalent", // The actual source type will be set by the TA.
		Source:     rec.source,
		Event:      rec.payload,
	})
}

func (s *Sink) post(ctx context.Context, body []byte, count int, sourcetypes map[string]uint64) {
	settings := s.config.Load()
	if settings.SplunkHECEndpoint == nil {
		return
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, settings.SplunkHECEndpoint.String(), bytes.NewReader(body))
	if err != nil {
		splunkhecmetrics.RecordFailed(uint64(count))
		logger.GetLogger().Warn("Failed to build Splunk HTTP Event Collector request", logfields.Error, err)
		return
	}
	req.Header.Set("Authorization", "Splunk "+settings.SplunkHECToken)
	req.Header.Set("Content-Type", "application/json")

	if enterpriseOption.Config.EnableSplunkHECDebug {
		logger.GetLogger().Debug("Posting batch to the Splunk HTTP Event Collector",
			"size", len(body), "events", count, "method", req.Method, "url", req.URL.String())
	}

	resp, err := s.client.Do(req)
	if err != nil {
		splunkhecmetrics.RecordFailed(uint64(count))
		// The token must never reach the logs, and err embeds the request URL
		// only, so it is safe to log as-is.
		logger.GetLogger().Warn("Failed to send events to the Splunk HTTP Event Collector",
			logfields.Error, err, "events", count)
		return
	}
	defer resp.Body.Close()

	if enterpriseOption.Config.EnableSplunkHECDebug {
		logger.GetLogger().Debug("Received response from the Splunk HTTP Event Collector",
			"status", resp.Status, "events", count)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		splunkhecmetrics.RecordFailed(uint64(count))
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, responseBodyLimit))
		logger.GetLogger().Warn("Splunk HTTP Event Collector rejected events",
			"status", resp.Status, "events", count, "response", strings.TrimSpace(string(detail)))
		return
	}

	io.Copy(io.Discard, io.LimitReader(resp.Body, responseBodyLimit))
	for sourcetype, count := range sourcetypes {
		splunkhecmetrics.RecordSent(sourcetype, count)
	}
}

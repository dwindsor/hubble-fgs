// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package hec

import (
	"bytes"
	"context"
	"io"
	"sync"
	"sync/atomic"

	"github.com/isovalent/hubble-fgs/pkg/metrics/splunkhecmetrics"
)

var defaultSink atomic.Pointer[Sink]

// Init configures the process wide sink and starts it. It is a no-op when no
// endpoint is configured.
func initSink(ctx context.Context) error {
	sink, err := NewSink()
	if err != nil {
		return err
	}
	sink.Start(ctx)
	defaultSink.Store(sink)
	return nil
}

// Writer returns an io.Writer forwarding to the process wide sink, or nil when
// no sink is configured.
func Writer(sourcetype string, source string) io.Writer {
	return defaultSink.Load().Writer(sourcetype, source)
}

func Init(ctx context.Context) error {
	once := sync.OnceValue(func() error {
		return initSink(ctx)
	})
	err := once()
	return err
}

// sinkWriter splits the byte stream written to it into newline delimited JSON
// records and queues each one. Export encoders write a whole record per call,
// but partial writes are buffered so a split record cannot corrupt the stream.
type sinkWriter struct {
	sink       *Sink
	sourcetype string
	source     string

	mu      sync.Mutex
	partial []byte
}

func (w *sinkWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if !w.sink.config.Load().shouldWrite(w.sourcetype) {
		return len(p), nil
	}

	rest := p
	for {
		i := bytes.IndexByte(rest, '\n')
		if i < 0 {
			break
		}
		line := rest[:i]
		rest = rest[i+1:]
		if len(w.partial) > 0 {
			line = append(w.partial, line...)
			w.partial = nil
		}
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		w.sink.send(w.sourcetype, w.source, bytes.Clone(line))
	}

	if len(rest) > 0 {
		// Drop an over-long partial record rather than growing without bound.
		if len(w.partial)+len(rest) > w.sink.config.Load().SplunkHECMaxContentLength {
			w.partial = nil
			w.sink.dropped.Add(1)
			splunkhecmetrics.RecordDropped(1)
		} else {
			w.partial = append(w.partial, rest...)
		}
	}

	return len(p), nil
}

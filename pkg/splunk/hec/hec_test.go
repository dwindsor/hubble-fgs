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
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/isovalent/hubble-fgs/pkg/metrics/splunkhecmetrics"
	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"
)

// collector is a stub HEC that records the requests it receives.
type collector struct {
	server *httptest.Server

	mu       sync.Mutex
	bodies   []string
	tokens   []string
	received chan struct{}

	status int
}

func newCollector(t *testing.T) *collector {
	t.Helper()
	c := &collector{received: make(chan struct{}, 16), status: http.StatusOK}
	c.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		c.mu.Lock()
		c.bodies = append(c.bodies, string(body))
		c.tokens = append(c.tokens, r.Header.Get("Authorization"))
		status := c.status
		c.mu.Unlock()
		w.WriteHeader(status)
		select {
		case c.received <- struct{}{}:
		default:
		}
	}))
	t.Cleanup(c.server.Close)
	return c
}

func (c *collector) wait(t *testing.T) {
	t.Helper()
	select {
	case <-c.received:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for the collector to receive a request")
	}
}

func (c *collector) allBodies() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.bodies...)
}

func newTestSink(t *testing.T, c *collector, maxContentLength int) *Sink {
	t.Helper()
	setTestConfig(t, c.server.URL, maxContentLength, 50*time.Millisecond, 5*time.Second)
	sink, err := NewSink()
	require.NoError(t, err)
	sink.Start(t.Context())
	return sink
}

func TestNewSinkEndpoint(t *testing.T) {
	setTestConfig(t, "https://splunk.example.com:8088", 1024, 0, 0)
	assert.Equal(t, "https://splunk.example.com:8088", GetConfig().Load().SplunkHECEndpoint.String())

	setTestConfig(t, "https://splunk.example.com:8088/custom/path", 1024, 0, 0)
	assert.Equal(t, "https://splunk.example.com:8088/custom/path", GetConfig().Load().SplunkHECEndpoint.String())
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	require.NoError(t, err)
	return u
}

func setTestConfig(t *testing.T, endpoint string, maxContentLength int, flushInterval time.Duration, timeout time.Duration) {
	t.Helper()

	orig := enterpriseOption.Config
	t.Cleanup(func() { enterpriseOption.Config = orig })

	enterpriseOption.Config.SplunkHECEndpoint = nil
	if endpoint != "" {
		enterpriseOption.Config.SplunkHECEndpoint = mustURL(t, endpoint)
	}
	enterpriseOption.Config.SplunkHECToken = "test-token"
	enterpriseOption.Config.SplunkHECMaxContentLength = maxContentLength
	enterpriseOption.Config.SplunkHECFlushInterval = flushInterval
	enterpriseOption.Config.SplunkHECTimeout = timeout
	enterpriseOption.Config.EnableSplunkHECDebug = false
	enterpriseOption.Config.SplunkHECSourcetypes = []string{"tetragon:test", "tetragon:test_a", "tetragon:test_b"}
	initConfig()
}

func TestWriterUsesConfiguredSourcetypes(t *testing.T) {
	setTestConfig(t, "https://splunk.example.com:8088", 1024, 2*time.Second, 30*time.Second)
	enterpriseOption.Config.SplunkHECSourcetypes = []string{enterpriseOption.SplunkHECSourcetypeTelemetry}
	initConfig()

	assert.True(t, GetConfig().Load().shouldWrite(enterpriseOption.SplunkHECSourcetypeTelemetry))
	assert.False(t, GetConfig().Load().shouldWrite(enterpriseOption.SplunkHECSourcetypeEvents))
}

func TestNewSinkTimings(t *testing.T) {
	setTestConfig(t, "https://splunk.example.com:8088", 1024, 2*time.Second, 30*time.Second)
	sink, err := NewSink()
	require.NoError(t, err)
	assert.Equal(t, 2*time.Second, GetConfig().Load().SplunkHECFlushInterval)
	assert.Equal(t, 30*time.Second, GetConfig().Load().SplunkHECTimeout)
	assert.Equal(t, 30*time.Second, sink.client.Timeout)

	setTestConfig(t, "https://splunk.example.com:8088", 1024, 0, 0)
	sink, err = NewSink()
	require.NoError(t, err)
	assert.Equal(t, time.Duration(0), GetConfig().Load().SplunkHECFlushInterval)
	assert.Equal(t, time.Duration(0), GetConfig().Load().SplunkHECTimeout)
	assert.Equal(t, time.Duration(0), sink.client.Timeout)

	setTestConfig(t, "https://splunk.example.com:8088", 1024, 5*time.Second, 7*time.Second)
	sink, err = NewSink()
	require.NoError(t, err)
	assert.Equal(t, 5*time.Second, GetConfig().Load().SplunkHECFlushInterval)
	assert.Equal(t, 7*time.Second, GetConfig().Load().SplunkHECTimeout)
	assert.Equal(t, 7*time.Second, sink.client.Timeout)
}

func TestSinkWriterSendsRecords(t *testing.T) {
	c := newCollector(t)
	sink := newTestSink(t, c, 1000000)

	w := sink.Writer("tetragon:test", "/tmp/test.log")
	_, err := w.Write([]byte(`{"a":1}` + "\n"))
	require.NoError(t, err)
	c.wait(t)

	bodies := c.allBodies()
	require.Len(t, bodies, 1)

	var envelope struct {
		Time       float64         `json:"time"`
		Host       string          `json:"host"`
		Sourcetype string          `json:"sourcetype"`
		Source     string          `json:"source"`
		Event      json.RawMessage `json:"event"`
	}
	require.NoError(t, json.Unmarshal([]byte(bodies[0]), &envelope))
	assert.Equal(t, "cisco:isovalent", envelope.Sourcetype)
	assert.Equal(t, "/tmp/test.log", envelope.Source)
	assert.JSONEq(t, `{"a":1}`, string(envelope.Event))
	assert.NotZero(t, envelope.Time)

	c.mu.Lock()
	defer c.mu.Unlock()
	assert.Equal(t, "Splunk test-token", c.tokens[0])
}

func TestSinkWriterBatchesRecords(t *testing.T) {
	c := newCollector(t)
	sink := newTestSink(t, c, 1000000)

	w := sink.Writer("tetragon:test", "/tmp/test.log")
	_, err := w.Write([]byte("{\"a\":1}\n{\"a\":2}\n{\"a\":3}\n"))
	require.NoError(t, err)
	c.wait(t)

	bodies := c.allBodies()
	require.Len(t, bodies, 1, "all three records belong in a single request")
	dec := json.NewDecoder(strings.NewReader(bodies[0]))
	count := 0
	for {
		var envelope map[string]any
		if err := dec.Decode(&envelope); err != nil {
			break
		}
		count++
	}
	assert.Equal(t, 3, count)
}

func TestSinkWriterRecordsSentMetricsBySourcetype(t *testing.T) {
	c := newCollector(t)
	sink := newTestSink(t, c, 1000000)

	typeA := "tetragon:test_a"
	typeB := "tetragon:test_b"
	baseA := testutil.ToFloat64(splunkhecmetrics.SentTotal.WithLabelValues(typeA))
	baseB := testutil.ToFloat64(splunkhecmetrics.SentTotal.WithLabelValues(typeB))

	_, err := sink.Writer(typeA, "/tmp/test-a.log").Write([]byte("{\"a\":1}\n{\"a\":2}\n"))
	require.NoError(t, err)
	_, err = sink.Writer(typeB, "/tmp/test-b.log").Write([]byte("{\"b\":1}\n"))
	require.NoError(t, err)
	c.wait(t)

	assert.Eventually(t, func() bool {
		return testutil.ToFloat64(splunkhecmetrics.SentTotal.WithLabelValues(typeA)) == baseA+2 &&
			testutil.ToFloat64(splunkhecmetrics.SentTotal.WithLabelValues(typeB)) == baseB+1
	}, 5*time.Second, 10*time.Millisecond)
}

func TestSinkWriterSplitsOnContentLength(t *testing.T) {
	c := newCollector(t)
	// Two envelopes are each just over 100 bytes, so they must be split across
	// requests when the batch limit is smaller than their combined size.
	sink := newTestSink(t, c, 150)

	w := sink.Writer("tetragon:test", "/tmp/test.log")
	_, err := w.Write([]byte("{\"a\":1}\n{\"a\":2}\n"))
	require.NoError(t, err)
	c.wait(t)
	c.wait(t)

	assert.Len(t, c.allBodies(), 2)
}

func TestSinkWriterDropsOversizedRecord(t *testing.T) {
	c := newCollector(t)
	sink := newTestSink(t, c, 4096)
	baseDropped := testutil.ToFloat64(splunkhecmetrics.DroppedTotal)

	big := make([]byte, 8192)
	for i := range big {
		big[i] = 'x'
	}
	w := sink.Writer("tetragon:test", "/tmp/test.log")
	_, err := w.Write(append(append([]byte(`{"a":"`), big...), []byte("\"}\n")...))
	require.NoError(t, err)

	// A well formed record afterwards must still arrive.
	_, err = w.Write([]byte(`{"a":1}` + "\n"))
	require.NoError(t, err)
	c.wait(t)

	bodies := c.allBodies()
	require.Len(t, bodies, 1)
	assert.Contains(t, bodies[0], `{"a":1}`)
	assert.NotZero(t, sink.dropped.Load())
	assert.Equal(t, baseDropped+1, testutil.ToFloat64(splunkhecmetrics.DroppedTotal))
}

func TestSinkWriterBuffersPartialRecords(t *testing.T) {
	c := newCollector(t)
	sink := newTestSink(t, c, 1000000)

	w := sink.Writer("tetragon:test", "/tmp/test.log")
	// A record split across three writes must be reassembled.
	for _, chunk := range []string{`{"a":`, `1`, "}\n"} {
		_, err := w.Write([]byte(chunk))
		require.NoError(t, err)
	}
	c.wait(t)

	bodies := c.allBodies()
	require.Len(t, bodies, 1)
	assert.Contains(t, bodies[0], `{"a":1}`)
}

func TestSinkWriterIgnoresIncompleteRecord(t *testing.T) {
	c := newCollector(t)
	sink := newTestSink(t, c, 1000000)

	w := sink.Writer("tetragon:test", "/tmp/test.log")
	_, err := w.Write([]byte(`{"a":1}`))
	require.NoError(t, err)

	// Nothing is sent until the record is terminated.
	time.Sleep(2 * GetConfig().Load().SplunkHECFlushInterval)
	assert.Empty(t, c.allBodies())
}

func TestSinkWriterNeverFails(t *testing.T) {
	c := newCollector(t)
	c.mu.Lock()
	c.status = http.StatusBadRequest
	c.mu.Unlock()
	sink := newTestSink(t, c, 1000000)
	baseFailed := testutil.ToFloat64(splunkhecmetrics.FailedTotal)

	w := sink.Writer("tetragon:test", "/tmp/test.log")
	n, err := w.Write([]byte(`{"a":1}` + "\n"))
	require.NoError(t, err, "a rejecting collector must not fail the write")
	assert.Equal(t, 8, n)
	c.wait(t)
	assert.Eventually(t, func() bool {
		return testutil.ToFloat64(splunkhecmetrics.FailedTotal) == baseFailed+1
	}, 5*time.Second, 10*time.Millisecond)
}

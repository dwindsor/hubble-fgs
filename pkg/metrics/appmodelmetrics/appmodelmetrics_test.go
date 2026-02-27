// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package appmodelmetrics

import (
	"bytes"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// resetMetrics re-creates all metric vars and registers them in a fresh
// registry so each test starts from a clean state.
func resetMetrics(t *testing.T) *prometheus.Registry {
	t.Helper()

	registry := prometheus.NewRegistry()

	ExportTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "tetragon", Name: "appmodel_export_total",
	})
	ExportNoChangesTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "tetragon", Name: "appmodel_export_no_changes_total",
	})
	DurationUsecTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "tetragon", Name: "appmodel_duration_usec_total",
	}, []string{"phase"})
	ErrorsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "tetragon", Name: "appmodel_errors_total",
	}, []string{"phase"})
	LookupErrorsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "tetragon", Name: "appmodel_lookup_errors_total",
	}, []string{"type"})
	TelemetryEntriesTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "tetragon", Name: "appmodel_telemetry_entries_total",
	}, []string{"type"})
	ExportedBytesTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "tetragon", Name: "appmodel_exported_bytes_total",
	})
	Entities = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "tetragon", Name: "appmodel_entities",
	}, []string{"kind"})

	InitMetrics(registry)
	return registry
}

func TestInitMetrics(t *testing.T) {
	registry := resetMetrics(t)

	// All 8 metrics should be registered without panicking.
	families, err := registry.Gather()
	require.NoError(t, err)

	names := make(map[string]bool)
	for _, f := range families {
		names[f.GetName()] = true
	}

	expected := []string{
		"tetragon_appmodel_export_total",
		"tetragon_appmodel_export_no_changes_total",
		"tetragon_appmodel_duration_usec_total",
		"tetragon_appmodel_errors_total",
		"tetragon_appmodel_lookup_errors_total",
		"tetragon_appmodel_telemetry_entries_total",
		"tetragon_appmodel_exported_bytes_total",
		"tetragon_appmodel_entities",
	}
	for _, name := range expected {
		assert.True(t, names[name], "metric %s should be registered", name)
	}
}

func TestLabelPreinitialization(t *testing.T) {
	resetMetrics(t)

	// All phase labels should exist on duration and errors counters.
	for _, p := range phases {
		val := testutil.ToFloat64(DurationUsecTotal.WithLabelValues(string(p)))
		assert.Equal(t, float64(0), val, "phase %s duration should be pre-initialized to 0", p)

		val = testutil.ToFloat64(ErrorsTotal.WithLabelValues(string(p)))
		assert.Equal(t, float64(0), val, "phase %s errors should be pre-initialized to 0", p)
	}

	// All lookup error types should exist.
	for _, typ := range lookupErrorTypes {
		val := testutil.ToFloat64(LookupErrorsTotal.WithLabelValues(string(typ)))
		assert.Equal(t, float64(0), val, "lookup error type %s should be pre-initialized to 0", typ)
	}

	// All telemetry types should exist.
	for _, typ := range telemetryTypes {
		val := testutil.ToFloat64(TelemetryEntriesTotal.WithLabelValues(string(typ)))
		assert.Equal(t, float64(0), val, "telemetry type %s should be pre-initialized to 0", typ)
	}

	// All entity kinds should exist.
	for _, k := range entityKinds {
		val := testutil.ToFloat64(Entities.WithLabelValues(string(k)))
		assert.Equal(t, float64(0), val, "entity kind %s should be pre-initialized to 0", k)
	}
}

func TestRecordExport(t *testing.T) {
	resetMetrics(t)

	RecordExport()
	RecordExport()
	assert.Equal(t, float64(2), testutil.ToFloat64(ExportTotal))
}

func TestRecordNoChanges(t *testing.T) {
	resetMetrics(t)

	RecordNoChanges()
	assert.Equal(t, float64(1), testutil.ToFloat64(ExportNoChangesTotal))
}

func TestRecordDuration(t *testing.T) {
	resetMetrics(t)

	RecordDuration(PhaseGetProcessModel, 1500)
	RecordDuration(PhaseGetProcessModel, 500)
	RecordDuration(PhaseDiff, 200)

	assert.Equal(t, float64(2000), testutil.ToFloat64(DurationUsecTotal.WithLabelValues(string(PhaseGetProcessModel))))
	assert.Equal(t, float64(200), testutil.ToFloat64(DurationUsecTotal.WithLabelValues(string(PhaseDiff))))
}

func TestRecordError(t *testing.T) {
	resetMetrics(t)

	RecordError(PhaseExportAppModel)
	RecordError(PhaseExportAppModel)
	RecordError(PhaseDiff)

	assert.Equal(t, float64(2), testutil.ToFloat64(ErrorsTotal.WithLabelValues(string(PhaseExportAppModel))))
	assert.Equal(t, float64(1), testutil.ToFloat64(ErrorsTotal.WithLabelValues(string(PhaseDiff))))
}

func TestRecordLookupError(t *testing.T) {
	resetMetrics(t)

	RecordLookupError(LookupDNS)
	RecordLookupError(LookupDNS)
	RecordLookupError(LookupCgroup)

	assert.Equal(t, float64(2), testutil.ToFloat64(LookupErrorsTotal.WithLabelValues(string(LookupDNS))))
	assert.Equal(t, float64(1), testutil.ToFloat64(LookupErrorsTotal.WithLabelValues(string(LookupCgroup))))
}

func TestRecordTelemetryEntries(t *testing.T) {
	resetMetrics(t)

	RecordTelemetryEntries(TelemetryProcess, 5)
	RecordTelemetryEntries(TelemetryNetwork, 3)
	RecordTelemetryEntries(TelemetryProcess, 2)

	assert.Equal(t, float64(7), testutil.ToFloat64(TelemetryEntriesTotal.WithLabelValues(string(TelemetryProcess))))
	assert.Equal(t, float64(3), testutil.ToFloat64(TelemetryEntriesTotal.WithLabelValues(string(TelemetryNetwork))))
}

func TestSetEntities(t *testing.T) {
	resetMetrics(t)

	SetEntities(EntityNamespace, 4)
	SetEntities(EntityProcess, 100)
	assert.Equal(t, float64(4), testutil.ToFloat64(Entities.WithLabelValues(string(EntityNamespace))))
	assert.Equal(t, float64(100), testutil.ToFloat64(Entities.WithLabelValues(string(EntityProcess))))

	// Gauge should be overwritten, not accumulated.
	SetEntities(EntityNamespace, 2)
	assert.Equal(t, float64(2), testutil.ToFloat64(Entities.WithLabelValues(string(EntityNamespace))))
}

type nopWriteCloser struct {
	buf bytes.Buffer
}

func (w *nopWriteCloser) Write(p []byte) (int, error) { return w.buf.Write(p) }
func (w *nopWriteCloser) Close() error                { return nil }

func TestByteCounterWriter(t *testing.T) {
	resetMetrics(t)

	inner := &nopWriteCloser{}
	wrapped := NewExportedBytesCounterWriter(inner)

	n, err := wrapped.Write([]byte("hello"))
	require.NoError(t, err)
	assert.Equal(t, 5, n)

	n, err = wrapped.Write([]byte(" world"))
	require.NoError(t, err)
	assert.Equal(t, 6, n)

	assert.Equal(t, float64(11), testutil.ToFloat64(ExportedBytesTotal))
	assert.Equal(t, "hello world", inner.buf.String())
}

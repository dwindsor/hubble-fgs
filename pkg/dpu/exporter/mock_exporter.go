package exporter

import (
	"context"

	"github.com/isovalent/ipa/l3l4networkpolicy/v1alpha"
)

func NewMockExporter() *MockExporter {
	return &MockExporter{}
}

type MockExporter struct {
	version string
	Exporter
}

func (m *MockExporter) Mode() ExporterType {
	return MOCK_EXPORTER
}

func (m *MockExporter) Version() string {
	return m.version
}

func (m *MockExporter) RefreshConfig(_ *v1alpha.ConfigObject, _ *v1alpha.ConfigObject) error {
	return nil
}

func (m *MockExporter) Init(_ context.Context) error {
	m.version = "mock"
	return nil
}

func (m *MockExporter) Connect(_ context.Context, _ bool) error {
	return nil
}

func (m *MockExporter) Close(_ context.Context) {}

func (m *MockExporter) Start(_ context.Context) error {
	return nil
}

func (m *MockExporter) Stop(_ context.Context) error {
	return nil
}

func (m *MockExporter) Restart(_ context.Context) error {
	return nil
}

func (m *MockExporter) Status() bool {
	return true
}

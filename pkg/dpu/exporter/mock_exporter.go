// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

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

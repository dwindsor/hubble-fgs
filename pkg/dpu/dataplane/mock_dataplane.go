package dataplane

import (
	"context"

	dpuPolicy "github.com/isovalent/hubble-fgs/pkg/model/server/dpu"
	"github.com/isovalent/ipa/l3l4networkpolicy/v1alpha"
)

func NewMockDataplane() *MockDataplane {
	return &MockDataplane{}
}

type MockDataplane struct {
	version string
	Dataplane
}

func (m *MockDataplane) Type() DataplaneType {
	return MOCK_DP
}

func (m *MockDataplane) Version() string {
	return m.version
}

func (m *MockDataplane) ApiPath() string {
	return ""
}

func (m *MockDataplane) PushPolicy(_ context.Context, _ []*dpuPolicy.DPUPolicyRule) error {
	return nil
}

func (m *MockDataplane) RemovePolicy(_ context.Context) error {
	return nil
}

func (m *MockDataplane) RefreshConfig(_ *v1alpha.ConfigObject, _ *v1alpha.ConfigObject) error {
	return nil
}

func (m *MockDataplane) Init(_ context.Context) error {
	m.version = "mock"
	return nil
}

func (m *MockDataplane) Connect(_ context.Context) error {
	return nil
}

func (m *MockDataplane) Close(_ context.Context) {}

func (m *MockDataplane) Start(_ context.Context) error {
	return nil
}

func (m *MockDataplane) Stop(_ context.Context) error {
	return nil
}

func (m *MockDataplane) Restart(_ context.Context) error {
	return nil
}

func (m *MockDataplane) Status() bool {
	return true
}

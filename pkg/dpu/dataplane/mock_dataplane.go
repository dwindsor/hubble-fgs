package dataplane

import (
	"context"

	"github.com/isovalent/ipa/l3l4networkpolicy/v1alpha"

	"github.com/cilium/tetragon/pkg/logger"

	dpuPolicy "github.com/isovalent/hubble-fgs/pkg/model/server/dpu"
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

func (m *MockDataplane) HardwareModel() string {
	return "mock"
}

func (m *MockDataplane) PushPolicy(_ context.Context, op v1alpha.PolicyOperation, rules []*dpuPolicy.DPUPolicyRule) error {
	logger.GetLogger().Info("pushed policy", "op", op, "rules", len(rules))
	var logStr string
	switch op {
	case v1alpha.PolicyOperation_POLICY_OPERATION_UPSERT:
		logStr = "applying policy"
	case v1alpha.PolicyOperation_POLICY_OPERATION_DELETE:
		logStr = "removing policy"
	default:
		logStr = "unknown policy"
	}
	for _, r := range rules {
		logger.GetLogger().Debug(logStr, "rule", *r.Policy)
	}
	return nil
}

func (m *MockDataplane) ClearPolicy(_ context.Context) error {
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

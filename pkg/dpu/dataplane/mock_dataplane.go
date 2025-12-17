// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package dataplane

import (
	"context"
	"encoding/json"
	"io"

	"github.com/cilium/tetragon/pkg/logger"

	dpAppPolicy "github.com/isovalent/hubble-fgs/pkg/dpu/policy"
	"github.com/isovalent/hubble-fgs/pkg/model/switchpolicy"

	"github.com/isovalent/ipa/l3l4networkpolicy/v1alpha"
)

func NewMockDataplane() *MockDataplane {

	// Creating json encoder and decoder for the connection
	return &MockDataplane{
		encode: json.NewEncoder(io.Discard),
	}
}

type MockDataplane struct {
	version string
	encode  *json.Encoder
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

var (
	ruleFwaCnt    int
	rulePolicyCnt int
)

func (m *MockDataplane) PushPolicy(_ context.Context, op v1alpha.PolicyOperation, rules []*switchpolicy.DPUPolicyRule) error {
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

	fwPolicy := dpAppPolicy.DPURuleToJSON(op, rules)

	ruleFwaCnt += len(fwPolicy)
	rulePolicyCnt += len(rules)

	if (ruleFwaCnt % 1000) == 0 {
		logger.GetLogger().Info("Applied rules\n", "PolicyCnt", rulePolicyCnt, "FWAcnt", ruleFwaCnt)
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

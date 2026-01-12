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
	logger.GetLogger().Info("[MockDataplane] Creating new mock dataplane instance")
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
	fwPolicy := dpAppPolicy.DPURuleToJSON(op, rules)

	if len(rules) != len(fwPolicy) {
		logger.GetLogger().Warn(logStr, "ruleCount", len(rules), "fwRuleCount", len(fwPolicy), "error", "rule count mismatch")
	}
	for i, r := range rules {
		var fwRuleJSON []byte
		if i < len(fwPolicy) {
			fwRuleJSON, _ = json.Marshal(fwPolicy[i])
		}
		ruleJSON, err := json.Marshal(r.Policy)
		if err == nil {
			logger.GetLogger().Debug(logStr, "rule", ruleJSON, "fwRule", fwRuleJSON)
			continue
		}
		logger.GetLogger().Debug(logStr, "rule", r.Policy, "fwRule", fwRuleJSON)
	}

	ruleFwaCnt += len(fwPolicy)
	rulePolicyCnt += len(rules)

	if (ruleFwaCnt % 1000) == 0 {
		logger.GetLogger().Info("Applied rules\n", "PolicyCnt", rulePolicyCnt, "FWAcnt", ruleFwaCnt)
	}
	return nil
}

func (m *MockDataplane) ClearPolicy(_ context.Context) error {
	logger.GetLogger().Info("[MockDataplane] ClearPolicy called", "previousPolicyCnt", rulePolicyCnt, "previousFWACnt", ruleFwaCnt)
	ruleFwaCnt = 0
	rulePolicyCnt = 0
	return nil
}

func (m *MockDataplane) RefreshConfig(oldConfig *v1alpha.ConfigObject, newConfig *v1alpha.ConfigObject) error {
	logger.GetLogger().Info("[MockDataplane] RefreshConfig called", "oldConfig", oldConfig, "newConfig", newConfig)
	return nil
}

func (m *MockDataplane) Init(_ context.Context) error {
	m.version = "mock"
	logger.GetLogger().Info("[MockDataplane] Init completed", "version", m.version)
	return nil
}

func (m *MockDataplane) Connect(_ context.Context) error {
	logger.GetLogger().Info("[MockDataplane] Connect called")
	return nil
}

func (m *MockDataplane) Close(_ context.Context) {
	logger.GetLogger().Info("[MockDataplane] Close called", "totalPolicyCnt", rulePolicyCnt, "totalFWACnt", ruleFwaCnt)
}

func (m *MockDataplane) Start(_ context.Context) error {
	logger.GetLogger().Info("[MockDataplane] Start called")
	return nil
}

func (m *MockDataplane) Stop(_ context.Context) error {
	logger.GetLogger().Info("[MockDataplane] Stop called", "totalPolicyCnt", rulePolicyCnt, "totalFWACnt", ruleFwaCnt)
	return nil
}

func (m *MockDataplane) Restart(_ context.Context) error {
	logger.GetLogger().Info("[MockDataplane] Restart called")
	return nil
}

func (m *MockDataplane) Status() bool {
	logger.GetLogger().Debug("[MockDataplane] Status called", "status", true, "policyCnt", rulePolicyCnt, "fwaCnt", ruleFwaCnt)
	return true
}

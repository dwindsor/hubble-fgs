package dpu

import (
	"testing"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/isovalent/ipa/l3l4networkpolicy/v1alpha"
	"github.com/stretchr/testify/assert"

	"github.com/isovalent/hubble-fgs/pkg/endpoint"
	"github.com/isovalent/hubble-fgs/pkg/model/record"
	"github.com/isovalent/hubble-fgs/pkg/model/types"
)

var (
	name = "testDPUPolicy"
	rule = "testDPURule"

	srcCidr = "198.1.0.1/16"
	dstCidr = "198.2.0.1/16"

	srcVrf = "vrf-red"
	//dstVrf = "vrf-blue" unsupported in initial PR
	dstVrf = ""
	noVrf  = ""

	srcVlan = 100
	//dstVlan = 200 unsupported in initial PR
	dstVlan = 0

	policy = types.TetragonPolicyUniqueID{
		PolicyName: name,
		RuleName:   rule,
	}
	dpSrcVrf = record.DatapathSource{
		Vrf: srcVrf,
		Ip:  srcCidr,
	}
	dpSrcVlan = record.DatapathSource{
		Vlan: uint32(srcVlan),
		Ip:   srcCidr,
	}
	ep = &endpoint.Endpoint{
		Type: tetragon.EndpointType_ENDPOINT_TYPE_CIDR,
		Ip:   "198.2.0.1/16",
	}
	dpEndpoint = record.DatapathEndpoint{
		EP:   ep,
		Port: 8080,
	}
	action = &record.DatapathAction{
		Action: record.PolicyAllow,
	}
	testRecordVrf = record.DatapathRecord{
		PolicyUID: policy,
		Src:       nil,
		L3Src:     dpSrcVrf,
		Endpoint:  dpEndpoint,
		Action:    action,
	}
	testRecordVlan = record.DatapathRecord{
		PolicyUID: policy,
		Src:       nil,
		L3Src:     dpSrcVlan,
		Endpoint:  dpEndpoint,
		Action:    action,
	}
)

func testSubjectNetwork(t *testing.T, l3 *v1alpha.L3L4NetworkSubject, cidr, vrf string, port, vlan int) {

	assert.Equal(t, l3.Cidr, cidr)
	assert.Equal(t, l3.MinPort, uint32(port))
	assert.Equal(t, l3.MaxPort, uint32(port))
	assert.Equal(t, l3.Vlan, uint32(vlan))
	assert.Equal(t, l3.Vrf, vrf)
	assert.Equal(t, l3.Protocol, v1alpha.PolicyProtocol_POLICY_PROTOCOL_TCP)
}

func testPolicySubject(t *testing.T, subj *v1alpha.PolicySubject, cidr, vrf string, port, vlan int) {
	testSubjectNetwork(t, subj.Network, cidr, vrf, port, vlan)
}

func TestDenyOperUpsertRecordToDPUVrf(t *testing.T) {
	record := testRecordVrf
	dpuRule := recordToDPUPolicyRule(&record, true)
	response := dpuRuleToResponse(dpuRule)
	assert.Equal(t, response.Oper, v1alpha.PolicyOperation_POLICY_OPERATION_UPSERT)
	r := response.Policy
	assert.Equal(t, r.PolicyName, name)
	assert.Equal(t, r.RuleName, rule)
	assert.Equal(t, r.Action, v1alpha.PolicyAction_POLICY_ACTION_ALLOW)
	testPolicySubject(t, r.Source, srcCidr, srcVrf, 0, 0)
	testPolicySubject(t, r.Destination, dstCidr, dstVrf, 8080, 0)
}

func TestDenyOperUpsertRecordToDPUVlan(t *testing.T) {
	record := testRecordVlan
	dpuRule := recordToDPUPolicyRule(&record, true)
	response := dpuRuleToResponse(dpuRule)
	assert.Equal(t, response.Oper, v1alpha.PolicyOperation_POLICY_OPERATION_UPSERT)
	r := response.Policy
	assert.Equal(t, r.PolicyName, name)
	assert.Equal(t, r.RuleName, rule)
	assert.Equal(t, r.Action, v1alpha.PolicyAction_POLICY_ACTION_ALLOW)
	testPolicySubject(t, r.Source, srcCidr, noVrf, 0, srcVlan)
	testPolicySubject(t, r.Destination, dstCidr, noVrf, 8080, dstVlan)
}

func TestDenyOperDeleteRecordToDPUVrf(t *testing.T) {
	record := testRecordVrf
	dpuRule := recordToDPUPolicyRule(&record, false)
	response := dpuRuleToResponse(dpuRule)
	assert.Equal(t, response.Oper, v1alpha.PolicyOperation_POLICY_OPERATION_DELETE)
	r := response.Policy
	assert.Equal(t, r.PolicyName, name)
	assert.Equal(t, r.RuleName, rule)
	assert.Equal(t, r.Action, v1alpha.PolicyAction_POLICY_ACTION_ALLOW)
	testPolicySubject(t, r.Source, srcCidr, srcVrf, 0, 0)
	testPolicySubject(t, r.Destination, dstCidr, dstVrf, 8080, 0)
}

func TestDenyOperDeleteRecordToDPUVlan(t *testing.T) {
	record := testRecordVlan
	dpuRule := recordToDPUPolicyRule(&record, false)
	response := dpuRuleToResponse(dpuRule)
	assert.Equal(t, response.Oper, v1alpha.PolicyOperation_POLICY_OPERATION_DELETE)
	r := response.Policy
	assert.Equal(t, r.PolicyName, name)
	assert.Equal(t, r.RuleName, rule)
	assert.Equal(t, r.Action, v1alpha.PolicyAction_POLICY_ACTION_ALLOW)
	testPolicySubject(t, r.Source, srcCidr, noVrf, 0, srcVlan)
	testPolicySubject(t, r.Destination, dstCidr, noVrf, 8080, dstVlan)
}

func TestDpuRuleToResponseHashes(t *testing.T) {
	rule := &DPURule{
		K8SResourceVersion: "",
		K8SUid:             "",
		PolicyName:         name,
		RuleName:           rule,
		Action:             v1alpha.PolicyAction_POLICY_ACTION_ALLOW,
		Source: DPUSubject{
			Cidr:     srcCidr,
			MinPort:  0,
			MaxPort:  0,
			Vlan:     0,
			Vrf:      srcVrf,
			VrfId:    0,
			Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_TCP,
		},
		Destination: DPUSubject{
			Cidr:     dstCidr,
			MinPort:  8080,
			MaxPort:  8080,
			Vlan:     0,
			Vrf:      dstVrf,
			VrfId:    0,
			Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_TCP,
		},
	}
	firstHash, err := HashRule(rule)
	if err != nil {
		t.Errorf("failed to hash rule")
	}
	response := dpuRuleToResponse(&DPUPolicyRule{Oper: v1alpha.PolicyOperation_POLICY_OPERATION_UPSERT, Policy: rule})
	testRule := ResponseToDPURule(response)
	secondHash, err := HashRule(testRule.Policy)
	if err != nil {
		t.Errorf("failed to hash rule")
	}
	assert.Equal(t, firstHash, secondHash)
}

func TestGetPerDpuConfig(t *testing.T) {
	tests := []struct {
		name        string
		fullCfg     *v1alpha.DpuConfig
		id          string
		expectError bool
		expectedCfg *v1alpha.DpuConfig
	}{
		{
			name: "Valid DPU1 config",
			fullCfg: &v1alpha.DpuConfig{
				ServiceMac: "aa:bb:cc:dd:ee:ff",
				ServiceIp:  "192.168.1.1",
				PortLow:    1000,
				PortHigh:   1999,
			},
			id:          AgentIdDpu1,
			expectError: false,
			expectedCfg: &v1alpha.DpuConfig{
				ServiceMac: "aa:bb:cc:dd:ee:ff",
				ServiceIp:  "192.168.1.1",
				PortLow:    1000,
				PortHigh:   1249,
			},
		},
		{
			name: "Valid DPU2 config",
			fullCfg: &v1alpha.DpuConfig{
				ServiceMac: "aa:bb:cc:dd:ee:ff",
				ServiceIp:  "192.168.1.1",
				PortLow:    1000,
				PortHigh:   1999,
			},
			id:          AgentIdDpu2,
			expectError: false,
			expectedCfg: &v1alpha.DpuConfig{
				ServiceMac: "aa:bb:cc:dd:ee:ff",
				ServiceIp:  "192.168.1.1",
				PortLow:    1250,
				PortHigh:   1499,
			},
		},
		{
			name: "Valid DPU3 config",
			fullCfg: &v1alpha.DpuConfig{
				ServiceMac: "aa:bb:cc:dd:ee:ff",
				ServiceIp:  "192.168.1.1",
				PortLow:    1000,
				PortHigh:   1999,
			},
			id:          AgentIdDpu3,
			expectError: false,
			expectedCfg: &v1alpha.DpuConfig{
				ServiceMac: "aa:bb:cc:dd:ee:ff",
				ServiceIp:  "192.168.1.1",
				PortLow:    1500,
				PortHigh:   1749,
			},
		},
		{
			name: "Valid DPU4 config",
			fullCfg: &v1alpha.DpuConfig{
				ServiceMac: "aa:bb:cc:dd:ee:ff",
				ServiceIp:  "192.168.1.1",
				PortLow:    1000,
				PortHigh:   1999,
			},
			id:          AgentIdDpu4,
			expectError: false,
			expectedCfg: &v1alpha.DpuConfig{
				ServiceMac: "aa:bb:cc:dd:ee:ff",
				ServiceIp:  "192.168.1.1",
				PortLow:    1750,
				PortHigh:   1999,
			},
		},
		{
			name:        "Nil fullCfg",
			fullCfg:     nil,
			id:          AgentIdDpu1,
			expectError: true,
			expectedCfg: nil,
		},
		{
			name: "Empty ID string treated as DPU1",
			fullCfg: &v1alpha.DpuConfig{
				ServiceMac: "aa:bb:cc:dd:ee:ff",
				ServiceIp:  "192.168.1.1",
				PortLow:    1000,
				PortHigh:   1999,
			},
			id:          "",
			expectError: false,
			expectedCfg: &v1alpha.DpuConfig{
				ServiceMac: "aa:bb:cc:dd:ee:ff",
				ServiceIp:  "192.168.1.1",
				PortLow:    1000,
				PortHigh:   1249,
			},
		},
		{
			name: "Invalid ID string treated as DPU1",
			fullCfg: &v1alpha.DpuConfig{
				ServiceMac: "aa:bb:cc:dd:ee:ff",
				ServiceIp:  "192.168.1.1",
				PortLow:    1000,
				PortHigh:   1999,
			},
			id:          "invalid-dpu-id",
			expectError: false,
			expectedCfg: &v1alpha.DpuConfig{
				ServiceMac: "aa:bb:cc:dd:ee:ff",
				ServiceIp:  "192.168.1.1",
				PortLow:    1000,
				PortHigh:   1249,
			},
		},
		{
			name: "Empty ServiceMac and ServiceIp",
			fullCfg: &v1alpha.DpuConfig{
				ServiceMac: "",
				ServiceIp:  "",
				PortLow:    1000,
				PortHigh:   1999,
			},
			id:          AgentIdDpu1,
			expectError: false,
			expectedCfg: &v1alpha.DpuConfig{
				ServiceMac: "",
				ServiceIp:  "",
				PortLow:    1000,
				PortHigh:   1249,
			},
		},
		{
			name: "Single port range",
			fullCfg: &v1alpha.DpuConfig{
				ServiceMac: "aa:bb:cc:dd:ee:ff",
				ServiceIp:  "192.168.1.1",
				PortLow:    8080,
				PortHigh:   8083,
			},
			id:          AgentIdDpu1,
			expectError: false,
			expectedCfg: &v1alpha.DpuConfig{
				ServiceMac: "aa:bb:cc:dd:ee:ff",
				ServiceIp:  "192.168.1.1",
				PortLow:    8080,
				PortHigh:   8080,
			},
		},
		{
			name: "Zero port range (PortHigh < PortLow)",
			fullCfg: &v1alpha.DpuConfig{
				ServiceMac: "aa:bb:cc:dd:ee:ff",
				ServiceIp:  "192.168.1.1",
				PortLow:    1000,
				PortHigh:   999,
			},
			id:          AgentIdDpu1,
			expectError: true,
		},
		{
			name: "Large port range",
			fullCfg: &v1alpha.DpuConfig{
				ServiceMac: "aa:bb:cc:dd:ee:ff",
				ServiceIp:  "192.168.1.1",
				PortLow:    0,
				PortHigh:   65535,
			},
			id:          AgentIdDpu2,
			expectError: false,
			expectedCfg: &v1alpha.DpuConfig{
				ServiceMac: "aa:bb:cc:dd:ee:ff",
				ServiceIp:  "192.168.1.1",
				PortLow:    16384,
				PortHigh:   32767,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Handle nil fullCfg case separately to avoid panic
			if tt.fullCfg == nil {
				assert.Panics(t, func() {
					getPerDpuConfig(tt.fullCfg, tt.id)
				}, "Expected panic when fullCfg is nil")
				return
			}

			result, err := getPerDpuConfig(tt.fullCfg, tt.id)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
				if tt.expectedCfg != nil {
					assert.Equal(t, tt.expectedCfg.ServiceMac, result.ServiceMac)
					assert.Equal(t, tt.expectedCfg.ServiceIp, result.ServiceIp)
					assert.Equal(t, tt.expectedCfg.PortLow, result.PortLow)
					assert.Equal(t, tt.expectedCfg.PortHigh, result.PortHigh)
				}
			}
		})
	}
}

func TestGetPerDpuConfig_DpuCountVariants(t *testing.T) {
	original := dpuCount
	defer func() { dpuCount = original }()

	fullCfg := &v1alpha.DpuConfig{
		ServiceMac: "aa:bb:cc:dd:ee:ff",
		ServiceIp:  "192.168.1.1",
		PortLow:    1000,
		PortHigh:   1999,
	}

	t.Run("2-DPUs mapping and out-of-range", func(t *testing.T) {
		dpuCount = 2

		// DPU1 slice
		cfg, err := getPerDpuConfig(fullCfg, AgentIdDpu1)
		assert.NoError(t, err)
		assert.NotNil(t, cfg)
		assert.Equal(t, uint32(1000), cfg.PortLow)
		assert.Equal(t, uint32(1499), cfg.PortHigh)
		assert.Equal(t, fullCfg.ServiceMac, cfg.ServiceMac)
		assert.Equal(t, fullCfg.ServiceIp, cfg.ServiceIp)

		// DPU2 slice
		cfg, err = getPerDpuConfig(fullCfg, AgentIdDpu2)
		assert.NoError(t, err)
		assert.NotNil(t, cfg)
		assert.Equal(t, uint32(1500), cfg.PortLow)
		assert.Equal(t, uint32(1999), cfg.PortHigh)

		// Unknown ID maps to index 0 (treated as DPU1)
		cfg, err = getPerDpuConfig(fullCfg, "unknown-id")
		assert.NoError(t, err)
		assert.NotNil(t, cfg)
		assert.Equal(t, uint32(1000), cfg.PortLow)
		assert.Equal(t, uint32(1499), cfg.PortHigh)

		// Out-of-range IDs for 2 DPUs
		cfg, err = getPerDpuConfig(fullCfg, AgentIdDpu3)
		assert.Error(t, err)
		assert.Nil(t, cfg)

		cfg, err = getPerDpuConfig(fullCfg, AgentIdDpu4)
		assert.Error(t, err)
		assert.Nil(t, cfg)
	})

	t.Run("4-DPUs mapping check DPU4", func(t *testing.T) {
		dpuCount = 4
		cfg, err := getPerDpuConfig(fullCfg, AgentIdDpu4)
		assert.NoError(t, err)
		assert.NotNil(t, cfg)
		assert.Equal(t, uint32(1750), cfg.PortLow)
		assert.Equal(t, uint32(1999), cfg.PortHigh)
	})
}

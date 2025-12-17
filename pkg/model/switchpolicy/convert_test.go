// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package switchpolicy

import (
	"testing"

	"github.com/isovalent/ipa/l3l4networkpolicy/v1alpha"
	"github.com/stretchr/testify/assert"
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

	testVrfRule = &DPUPolicyRule{
		Oper: v1alpha.PolicyOperation_POLICY_OPERATION_UPSERT,
		Policy: &DPURule{
			PolicyName: name,
			RuleName:   rule,
			Action:     v1alpha.PolicyAction_POLICY_ACTION_ALLOW,
			Source: DPUSubject{
				Cidr: srcCidr,
				Ports: &[]SmartSwitchNetworkProtocolPorts{
					{
						Port:     0,
						EndPort:  0,
						Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_TCP,
					},
				},
				Vlan:  0,
				Vrf:   srcVrf,
				VrfId: 0,
			},
			Destination: DPUSubject{
				Cidr: dstCidr,
				Ports: &[]SmartSwitchNetworkProtocolPorts{
					{
						Port:     8080,
						EndPort:  8080,
						Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_TCP,
					},
				},
				Vlan:  0,
				Vrf:   dstVrf,
				VrfId: 0,
			},
		},
	}
	testVlanRule = &DPUPolicyRule{
		Oper: v1alpha.PolicyOperation_POLICY_OPERATION_UPSERT,
		Policy: &DPURule{
			PolicyName: name,
			RuleName:   rule,
			Action:     v1alpha.PolicyAction_POLICY_ACTION_ALLOW,
			Source: DPUSubject{
				Cidr: srcCidr,
				Ports: &[]SmartSwitchNetworkProtocolPorts{
					{
						Port:     0,
						EndPort:  0,
						Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_TCP,
					},
				},
				Vlan:  uint32(srcVlan),
				Vrf:   noVrf,
				VrfId: 0,
			},
			Destination: DPUSubject{
				Cidr: dstCidr,
				Ports: &[]SmartSwitchNetworkProtocolPorts{
					{
						Port:     8080,
						EndPort:  8080,
						Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_TCP,
					},
				},
				Vlan:  uint32(dstVlan),
				Vrf:   noVrf,
				VrfId: 0,
			},
		},
	}
)

func testSubjectNetwork(t *testing.T, l3 *v1alpha.L3L4NetworkSubject, cidr, vrf string, port, vlan int) {
	assert.Equal(t, l3.Cidr, cidr)
	assert.Equal(t, l3.Ports[0].MinPort, uint32(port))
	assert.Equal(t, l3.Ports[0].MaxPort, uint32(port))
	assert.Equal(t, l3.Vlan, uint32(vlan))
	assert.Equal(t, l3.Vrf, vrf)
	assert.Equal(t, l3.Ports[0].Protocol, v1alpha.PolicyProtocol_POLICY_PROTOCOL_TCP)
}

func testPolicySubject(t *testing.T, subj *v1alpha.PolicySubject, cidr, vrf string, port, vlan int) {
	testSubjectNetwork(t, subj.Network, cidr, vrf, port, vlan)
}

func TestDenyOperUpsertRecordToDPUVrf(t *testing.T) {
	response := dpuRuleToResponse(testVrfRule)
	assert.Equal(t, response.Oper, v1alpha.PolicyOperation_POLICY_OPERATION_UPSERT)
	r := response.Policy
	assert.Equal(t, r.PolicyName, name)
	assert.Equal(t, r.RuleName, rule)
	assert.Equal(t, r.Action, v1alpha.PolicyAction_POLICY_ACTION_ALLOW)
	testPolicySubject(t, r.Source, srcCidr, srcVrf, 0, 0)
	testPolicySubject(t, r.Destination, dstCidr, dstVrf, 8080, 0)
}

func TestDenyOperUpsertRecordToDPUVlan(t *testing.T) {
	response := dpuRuleToResponse(testVlanRule)
	assert.Equal(t, response.Oper, v1alpha.PolicyOperation_POLICY_OPERATION_UPSERT)
	r := response.Policy
	assert.Equal(t, r.PolicyName, name)
	assert.Equal(t, r.RuleName, rule)
	assert.Equal(t, r.Action, v1alpha.PolicyAction_POLICY_ACTION_ALLOW)
	testPolicySubject(t, r.Source, srcCidr, noVrf, 0, srcVlan)
	testPolicySubject(t, r.Destination, dstCidr, noVrf, 8080, dstVlan)
}

func TestDenyOperDeleteRecordToDPUVrf(t *testing.T) {
	dpuRule := &DPUPolicyRule{
		Oper:   v1alpha.PolicyOperation_POLICY_OPERATION_DELETE,
		Policy: testVrfRule.Policy,
	}
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
	dpuRule := &DPUPolicyRule{
		Oper:   v1alpha.PolicyOperation_POLICY_OPERATION_DELETE,
		Policy: testVlanRule.Policy,
	}
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
			Cidr: srcCidr,
			Ports: &[]SmartSwitchNetworkProtocolPorts{
				{
					Port:     0,
					EndPort:  0,
					Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_TCP,
				},
			},
			Vlan:  0,
			Vrf:   srcVrf,
			VrfId: 0,
		},
		Destination: DPUSubject{
			Cidr: dstCidr,
			Ports: &[]SmartSwitchNetworkProtocolPorts{
				{
					Port:     8080,
					EndPort:  8080,
					Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_TCP,
				},
			},
			Vlan:  0,
			Vrf:   dstVrf,
			VrfId: 0,
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
		dpuCount    uint16
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
			id:          "169.254.28.1",
			dpuCount:    4,
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
			id:          "169.254.24.1",
			dpuCount:    4,
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
			id:          "169.254.36.1",
			dpuCount:    4,
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
			id:          "169.254.32.1",
			dpuCount:    4,
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
			id:          "169.254.28.1",
			dpuCount:    4,
			expectError: true,
			expectedCfg: nil,
		},
		{
			name: "Empty ID",
			fullCfg: &v1alpha.DpuConfig{
				ServiceMac: "aa:bb:cc:dd:ee:ff",
				ServiceIp:  "192.168.1.1",
				PortLow:    1000,
				PortHigh:   1999,
			},
			id:          "",
			dpuCount:    4,
			expectError: true,
			expectedCfg: nil,
		},
		{
			name: "Invalid ID",
			fullCfg: &v1alpha.DpuConfig{
				ServiceMac: "aa:bb:cc:dd:ee:ff",
				ServiceIp:  "192.168.1.1",
				PortLow:    1000,
				PortHigh:   1999,
			},
			id:          "invalid-dpu-id",
			dpuCount:    4,
			expectError: true,
			expectedCfg: nil,
		},
		{
			name: "Empty ServiceMac and ServiceIp",
			fullCfg: &v1alpha.DpuConfig{
				ServiceMac: "",
				ServiceIp:  "",
				PortLow:    1000,
				PortHigh:   1999,
			},
			id:          "169.254.28.1",
			dpuCount:    4,
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
			id:          "169.254.28.1",
			dpuCount:    4,
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
			id:          "169.254.28.1",
			dpuCount:    4,
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
			id:          "169.254.24.1",
			dpuCount:    4,
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
					getPerDpuConfig(tt.fullCfg, tt.id, tt.dpuCount)
				}, "Expected panic when fullCfg is nil")
				return
			}

			result, err := getPerDpuConfig(tt.fullCfg, tt.id, tt.dpuCount)

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
	fullCfg := &v1alpha.DpuConfig{
		ServiceMac: "aa:bb:cc:dd:ee:ff",
		ServiceIp:  "192.168.1.1",
		PortLow:    1000,
		PortHigh:   1999,
	}

	t.Run("2-DPUs mapping and out-of-range", func(t *testing.T) {
		// DPU1 slice
		cfg, err := getPerDpuConfig(fullCfg, "169.254.151.1", 2)
		assert.NoError(t, err)
		assert.NotNil(t, cfg)
		assert.Equal(t, uint32(1000), cfg.PortLow)
		assert.Equal(t, uint32(1499), cfg.PortHigh)
		assert.Equal(t, fullCfg.ServiceMac, cfg.ServiceMac)
		assert.Equal(t, fullCfg.ServiceIp, cfg.ServiceIp)

		// DPU2 slice
		cfg, err = getPerDpuConfig(fullCfg, "169.254.159.1", 2)
		assert.NoError(t, err)
		assert.NotNil(t, cfg)
		assert.Equal(t, uint32(1500), cfg.PortLow)
		assert.Equal(t, uint32(1999), cfg.PortHigh)

		// Unknown ID fails
		cfg, err = getPerDpuConfig(fullCfg, "unknown-id", 2)
		assert.Error(t, err)
		assert.Nil(t, cfg)

		// Out-of-range IDs for 2 DPUs
		cfg, err = getPerDpuConfig(fullCfg, "169.254.36.1", 2)
		assert.Error(t, err)
		assert.Nil(t, cfg)

		cfg, err = getPerDpuConfig(fullCfg, "169.254.32.1", 2)
		assert.Error(t, err)
		assert.Nil(t, cfg)
	})

	t.Run("4-DPUs mapping check DPU4", func(t *testing.T) {
		cfg, err := getPerDpuConfig(fullCfg, "169.254.32.1", 4)
		assert.NoError(t, err)
		assert.NotNil(t, cfg)
		assert.Equal(t, uint32(1750), cfg.PortLow)
		assert.Equal(t, uint32(1999), cfg.PortHigh)
	})
}

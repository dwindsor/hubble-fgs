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
	"context"
	"encoding/hex"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/isovalent/ipa/l3l4networkpolicy/v1alpha"
)

var (
	t1 = "testPeerA"
	t2 = "testPeerB"
	t3 = "testPeerC"
	t4 = "testPeerD"

	p1Hostname = "hostnameB"
	p1Serial   = "offloadEngineSerialNumber-0B"
	p1Status   = v1alpha.ReportStatus{
		AgentUid:       t1,
		DpVersion:      "dpVersion-0.99.99",
		AgentVersion:   "agentVersion-0.99.99",
		PolicyChecksum: "",
		Hostname:       p1Hostname,
		Architecture:   "offloadEngineArch",
		Type:           v1alpha.AgentType_AGENT_TYPE_DPU_AGW,
		SerialNumber:   p1Serial,
	}
	p1StatusRequest = v1alpha.ReportStatusRequest{
		Status: &p1Status,
	}

	p2Hostname = "hostnameB"
	p2Serial   = "offloadEngineSerialNumber-0B"
	p2Status   = v1alpha.ReportStatus{
		AgentUid:       t2,
		DpVersion:      "dpVersion-0.99.99",
		AgentVersion:   "agentVersion-0.99.99",
		PolicyChecksum: "",
		Hostname:       p2Hostname,
		Architecture:   "offloadEngineArch",
		Type:           v1alpha.AgentType_AGENT_TYPE_DPU_AGW,
		SerialNumber:   p2Serial,
	}
	p2StatusRequest = v1alpha.ReportStatusRequest{
		Status: &p2Status,
	}

	p3Hostname = "hostnameC"
	p3Serial   = "offloadEngineSerialNumber-0C"
	p3Status   = v1alpha.ReportStatus{
		AgentUid:       t3,
		DpVersion:      "dpVersion-0.99.99",
		AgentVersion:   "agentVersion-0.99.99",
		PolicyChecksum: "",
		Hostname:       p3Hostname,
		Architecture:   "offloadEngineArch",
		Type:           v1alpha.AgentType_AGENT_TYPE_DPU_AGW,
		SerialNumber:   p3Serial,
	}
	p3StatusRequest = v1alpha.ReportStatusRequest{
		Status: &p3Status,
	}

	p4Hostname = "hostnameD"
	p4Serial   = "offloadEngineSerialNumber-0D"
	p4Status   = v1alpha.ReportStatus{
		AgentUid:       t4,
		DpVersion:      "dpVersion-0.99.99",
		AgentVersion:   "agentVersion-0.99.99",
		PolicyChecksum: "",
		Hostname:       p4Hostname,
		Architecture:   "offloadEngineArch",
		Type:           v1alpha.AgentType_AGENT_TYPE_DPU_AGW,
		SerialNumber:   p4Serial,
	}
	p4StatusRequest = v1alpha.ReportStatusRequest{
		Status: &p4Status,
	}

	rule1 = &DPUPolicyRule{
		Oper: v1alpha.PolicyOperation_POLICY_OPERATION_UPSERT,
		Policy: &DPURule{
			PolicyName: "record1",
			RuleName:   "rule1",
			Action:     v1alpha.PolicyAction_POLICY_ACTION_ALLOW,
			Source: DPUSubject{
				Cidr: "192.1.0.1/16",
				Ports: &[]SmartSwitchNetworkProtocolPorts{
					{
						Port:     0,
						EndPort:  0,
						Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_TCP,
					},
				},
				Vlan:  0,
				Vrf:   "vrf-a",
				VrfId: 0,
			},
			Destination: DPUSubject{
				Cidr: "192.2.0.1/16",
				Ports: &[]SmartSwitchNetworkProtocolPorts{
					{
						Port:     8080,
						EndPort:  8080,
						Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_TCP,
					},
				},
				Vlan:  0,
				Vrf:   "",
				VrfId: 0,
			},
		},
	}
	rule2 = &DPUPolicyRule{
		Oper: v1alpha.PolicyOperation_POLICY_OPERATION_UPSERT,
		Policy: &DPURule{
			PolicyName: "record2",
			RuleName:   "rule2",
			Action:     v1alpha.PolicyAction_POLICY_ACTION_DENY,
			Source: DPUSubject{
				Cidr: "192.3.0.1/16",
				Ports: &[]SmartSwitchNetworkProtocolPorts{
					{
						Port:     0,
						EndPort:  0,
						Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_TCP,
					},
				},
				Vlan:  0,
				Vrf:   "vrf-b",
				VrfId: 0,
			},
			Destination: DPUSubject{
				Cidr: "192.4.0.1/16",
				Ports: &[]SmartSwitchNetworkProtocolPorts{
					{
						Port:     9090,
						EndPort:  9090,
						Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_TCP,
					},
				},
				Vlan:  0,
				Vrf:   "",
				VrfId: 0,
			},
		},
	}
	rule3 = &DPUPolicyRule{
		Oper: v1alpha.PolicyOperation_POLICY_OPERATION_UPSERT,
		Policy: &DPURule{
			PolicyName: "record3",
			RuleName:   "rule2",
			Action:     v1alpha.PolicyAction_POLICY_ACTION_DENY,
			Source: DPUSubject{
				Cidr: "192.5.0.1/16",
				Ports: &[]SmartSwitchNetworkProtocolPorts{
					{
						Port:     0,
						EndPort:  0,
						Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_TCP,
					},
				},
				Vlan:  0,
				Vrf:   "vrf-b",
				VrfId: 0,
			},
			Destination: DPUSubject{
				Cidr: "192.6.0.1/16",
				Ports: &[]SmartSwitchNetworkProtocolPorts{
					{
						Port:     9090,
						EndPort:  9090,
						Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_TCP,
					},
				},
				Vlan:  0,
				Vrf:   "",
				VrfId: 0,
			},
		},
	}
)

func checkStatus(t *testing.T, checksum string, expected, saved DPUReportStatus) {
	assert.Equal(t, expected.AgentUid, saved.AgentUid)
	assert.Equal(t, expected.DpVersion, saved.DpVersion)
	assert.Equal(t, expected.AgentVersion, saved.AgentVersion)
	assert.Equal(t, checksum, saved.PolicyChecksum)
	assert.Equal(t, expected.Hostname, saved.Hostname)
	assert.Equal(t, expected.Architecture, saved.Architecture)
	assert.Equal(t, expected.Type, saved.Type)
	assert.Equal(t, expected.SerialNumber, saved.SerialNumber)
}

func TestBasicWorkflow(t *testing.T) {
	dpu := NewDPUListener(context.Background(), "127.0.0.1:8080")

	// Add some peers and assert we create some unique objects
	p1 := dpu.addPeer(t1)
	p2 := dpu.addPeer(t2)
	p3 := dpu.addPeer(t3)
	p4 := dpu.addPeer(t4)
	assert.Equal(t, len(dpu.peerGroup), 4)
	assert.Equal(t, p1.uid, t1)
	assert.Equal(t, p2.uid, t2)
	assert.Equal(t, p3.uid, t3)
	assert.Equal(t, p4.uid, t4)
	assert.NotNil(t, p1.polCh)
	assert.NotNil(t, p2.polCh)
	assert.NotNil(t, p3.polCh)
	assert.NotNil(t, p4.polCh)
	// polReconnectCh is no longer created by addPeer; it is created fresh
	// by Streaml3L4NetworkPolicy when the stream handler starts.
	assert.Nil(t, p1.polReconnectCh)
	assert.Nil(t, p2.polReconnectCh)
	assert.Nil(t, p3.polReconnectCh)
	assert.Nil(t, p4.polReconnectCh)

	// Report some status with no Policy

	p1StatusDPU := reportRequestToDPU(&p1StatusRequest)
	p2StatusDPU := reportRequestToDPU(&p2StatusRequest)
	p3StatusDPU := reportRequestToDPU(&p3StatusRequest)
	p4StatusDPU := reportRequestToDPU(&p4StatusRequest)

	dpu.ReportStatus(p1StatusDPU)
	dpu.ReportStatus(p2StatusDPU)
	dpu.ReportStatus(p3StatusDPU)
	dpu.ReportStatus(p4StatusDPU)
	checkStatus(t, "", *p1StatusDPU, dpu.peerGroup[p1.uid].lastStatus)
	checkStatus(t, "", *p2StatusDPU, dpu.peerGroup[p2.uid].lastStatus)
	checkStatus(t, "", *p3StatusDPU, dpu.peerGroup[p3.uid].lastStatus)
	checkStatus(t, "", *p4StatusDPU, dpu.peerGroup[p4.uid].lastStatus)

	// dev null the channel
	for _, pg := range dpu.peerGroup {
		go func() {
			<-pg.polCh
		}()
	}

	dpu.SubmitDPURuleToDPU(rule1)
	assert.Equal(t, len(dpu.ruleSet), 1)

	// checksum state is out of sync because no status reports yet
	invalid := dpu.StateCheck()
	assert.Equal(t, false, invalid)

	// requests for 3:4 dpus and ensure still out of sync
	csumB := dpu.Checksum()
	csum := hex.EncodeToString(csumB[:])

	p1StatusRequest.Status.PolicyChecksum = csum
	p1S := reportRequestToDPU(&p1StatusRequest)
	p1StatusRequest.Status.PolicyChecksum = ""
	dpu.ReportStatus(p1S)
	invalid = dpu.StateCheck()
	assert.Equal(t, false, invalid)

	p2StatusRequest.Status.PolicyChecksum = csum
	p2S := reportRequestToDPU(&p2StatusRequest)
	p2StatusRequest.Status.PolicyChecksum = ""
	dpu.ReportStatus(p2S)
	invalid = dpu.StateCheck()
	assert.Equal(t, false, invalid)

	p3StatusRequest.Status.PolicyChecksum = csum
	p3S := reportRequestToDPU(&p3StatusRequest)
	p3StatusRequest.Status.PolicyChecksum = ""
	dpu.ReportStatus(p3S)
	invalid = dpu.StateCheck()
	assert.Equal(t, false, invalid)

	// finally everything is in sync report true
	p4StatusRequest.Status.PolicyChecksum = csum
	p4S := reportRequestToDPU(&p4StatusRequest)
	dpu.ReportStatus(p4S)
	invalid = dpu.StateCheck()
	assert.Equal(t, true, invalid)

	// Drive out of sync and verify
	p4StatusRequest.Status.PolicyChecksum = "foobar"
	p4S = reportRequestToDPU(&p4StatusRequest)
	dpu.ReportStatus(p4S)
	invalid = dpu.StateCheck()
	assert.Equal(t, false, invalid)
}

func TestReportBeforeAdd(t *testing.T) {
	dpu := NewDPUListener(context.Background(), "127.0.0.1:8080")
	p1SR := reportRequestToDPU(&p1StatusRequest)
	dpu.ReportStatus(p1SR)
	checkStatus(t, "", *p1SR, dpu.peerGroup[t1].lastStatus)
	p1 := dpu.addPeer(t1)
	checkStatus(t, "", *p1SR, dpu.peerGroup[p1.uid].lastStatus)
}

// Add/Remove Policy in different orders and ensure we get the same hash
func TestHashLogic(t *testing.T) {
	dpu1 := NewDPUListener(context.Background(), "127.0.0.1:8080")
	dpu1.SubmitDPURuleToDPU(rule1)
	dpu1.SubmitDPURuleToDPU(rule2)
	dpu1.SubmitDPURuleToDPU(rule3)
	assert.Equal(t, len(dpu1.ruleSet), 3)
	csum1 := dpu1.Checksum()
	hexCsum1 := hex.EncodeToString(csum1[:])

	dpu2 := NewDPUListener(context.Background(), "127.0.0.1:8080")
	dpu2.SubmitDPURuleToDPU(rule3)
	dpu2.SubmitDPURuleToDPU(rule2)
	dpu2.SubmitDPURuleToDPU(rule1)
	assert.Equal(t, len(dpu2.ruleSet), 3)
	csum2 := dpu2.Checksum()
	hexCsum2 := hex.EncodeToString(csum2[:])

	dpu3 := NewDPUListener(context.Background(), "127.0.0.1:8080")
	dpu3.SubmitDPURuleToDPU(rule3)
	dpu3.SubmitDPURuleToDPU(rule2)
	dpu3.SubmitDPURuleToDPU(rule1)
	record1Delete := &DPUPolicyRule{
		Oper:   v1alpha.PolicyOperation_POLICY_OPERATION_DELETE,
		Policy: rule1.Policy,
	}
	dpu3.SubmitDPURuleToDPU(record1Delete)
	dpu3.SubmitDPURuleToDPU(rule1)
	assert.Equal(t, len(dpu3.ruleSet), 3)
	csum3 := dpu3.Checksum()
	hexCsum3 := hex.EncodeToString(csum3[:])

	assert.Equal(t, hexCsum1, hexCsum2)
	assert.Equal(t, hexCsum2, hexCsum3)
}

// Attempt to delete policy that doesn't exist.
func TestOOOPolicy(t *testing.T) {
	dpu1 := NewDPUListener(context.Background(), "127.0.0.1:8080")
	record1Delete := &DPUPolicyRule{
		Oper:   v1alpha.PolicyOperation_POLICY_OPERATION_DELETE,
		Policy: rule1.Policy,
	}
	dpu1.SubmitDPURuleToDPU(record1Delete)
	dpu1.SubmitDPURuleToDPU(rule1)
	assert.Equal(t, len(dpu1.ruleSet), 1)

	dpu2 := NewDPUListener(context.Background(), "127.0.0.1:8080")
	dpu1.SubmitDPURuleToDPU(record1Delete)
	dpu1.SubmitDPURuleToDPU(rule1)
	dpu1.SubmitDPURuleToDPU(record1Delete)
	dpu1.SubmitDPURuleToDPU(record1Delete)
	assert.Equal(t, len(dpu2.ruleSet), 0)
}

func TestSubmitDPURuleToDPU_VRFIDChange(t *testing.T) {
	dpu := NewDPUListener(context.Background(), "127.0.0.1:8080")

	// UPSERT a rule with VrfId=100
	ruleOld := &DPUPolicyRule{
		Oper: v1alpha.PolicyOperation_POLICY_OPERATION_UPSERT,
		Policy: &DPURule{
			K8SResourceVersion: "1",
			K8SUid:             "uid-1",
			PolicyName:         "test-policy",
			RuleName:           "rule-1",
			Action:             v1alpha.PolicyAction_POLICY_ACTION_ALLOW,
			Source:             DPUSubject{Cidr: "10.0.0.0/8", Ports: &[]SmartSwitchNetworkProtocolPorts{}, Vrf: "red", VrfId: 100},
			Destination:        DPUSubject{Cidr: "192.168.0.0/16", Ports: &[]SmartSwitchNetworkProtocolPorts{}, Vrf: "red", VrfId: 100},
		},
	}
	dpu.SubmitDPURuleToDPU(ruleOld)
	assert.Equal(t, 1, len(dpu.ruleSet), "should have one rule after initial UPSERT")
	csumBefore := dpu.Checksum()

	// UPSERT the same logical rule with VrfId=200 (GID change)
	ruleNew := &DPUPolicyRule{
		Oper: v1alpha.PolicyOperation_POLICY_OPERATION_UPSERT,
		Policy: &DPURule{
			K8SResourceVersion: "1",
			K8SUid:             "uid-1",
			PolicyName:         "test-policy",
			RuleName:           "rule-1",
			Action:             v1alpha.PolicyAction_POLICY_ACTION_ALLOW,
			Source:             DPUSubject{Cidr: "10.0.0.0/8", Ports: &[]SmartSwitchNetworkProtocolPorts{}, Vrf: "red", VrfId: 200},
			Destination:        DPUSubject{Cidr: "192.168.0.0/16", Ports: &[]SmartSwitchNetworkProtocolPorts{}, Vrf: "red", VrfId: 200},
		},
	}
	dpu.SubmitDPURuleToDPU(ruleNew)
	assert.Equal(t, 1, len(dpu.ruleSet), "ruleSet should still have one rule after VRF ID change UPSERT")
	csumAfter := dpu.Checksum()
	assert.NotEqual(t, csumBefore, csumAfter, "checksum should change after VRF ID update")

	// Verify checksum matches a fresh listener that only has the new version
	dpuFresh := NewDPUListener(context.Background(), "127.0.0.1:8080")
	dpuFresh.SubmitDPURuleToDPU(ruleNew)
	assert.Equal(t, csumAfter, dpuFresh.Checksum(), "checksum should match fresh listener with only new rule")
}

func TestSubmitDPURuleToDPU_VRFIDChange_MultipleRules(t *testing.T) {
	dpu := NewDPUListener(context.Background(), "127.0.0.1:8080")

	// UPSERT two rules
	ruleA := &DPUPolicyRule{
		Oper: v1alpha.PolicyOperation_POLICY_OPERATION_UPSERT,
		Policy: &DPURule{
			K8SResourceVersion: "1",
			K8SUid:             "uid-a",
			PolicyName:         "policy-a",
			RuleName:           "rule-1",
			Action:             v1alpha.PolicyAction_POLICY_ACTION_ALLOW,
			Source:             DPUSubject{Cidr: "10.0.0.0/8", Ports: &[]SmartSwitchNetworkProtocolPorts{}, Vrf: "red", VrfId: 100},
			Destination:        DPUSubject{Cidr: "10.1.0.0/16", Ports: &[]SmartSwitchNetworkProtocolPorts{}, Vrf: "red", VrfId: 100},
		},
	}
	ruleB := &DPUPolicyRule{
		Oper: v1alpha.PolicyOperation_POLICY_OPERATION_UPSERT,
		Policy: &DPURule{
			K8SResourceVersion: "1",
			K8SUid:             "uid-b",
			PolicyName:         "policy-b",
			RuleName:           "rule-1",
			Action:             v1alpha.PolicyAction_POLICY_ACTION_DENY,
			Source:             DPUSubject{Cidr: "172.16.0.0/12", Ports: &[]SmartSwitchNetworkProtocolPorts{}, Vrf: "blue", VrfId: 200},
			Destination:        DPUSubject{Cidr: "172.17.0.0/16", Ports: &[]SmartSwitchNetworkProtocolPorts{}, Vrf: "blue", VrfId: 200},
		},
	}
	dpu.SubmitDPURuleToDPU(ruleA)
	dpu.SubmitDPURuleToDPU(ruleB)
	assert.Equal(t, 2, len(dpu.ruleSet))

	// Change VRF ID for rule A only
	ruleAUpdated := &DPUPolicyRule{
		Oper: v1alpha.PolicyOperation_POLICY_OPERATION_UPSERT,
		Policy: &DPURule{
			K8SResourceVersion: "1",
			K8SUid:             "uid-a",
			PolicyName:         "policy-a",
			RuleName:           "rule-1",
			Action:             v1alpha.PolicyAction_POLICY_ACTION_ALLOW,
			Source:             DPUSubject{Cidr: "10.0.0.0/8", Ports: &[]SmartSwitchNetworkProtocolPorts{}, Vrf: "red", VrfId: 300},
			Destination:        DPUSubject{Cidr: "10.1.0.0/16", Ports: &[]SmartSwitchNetworkProtocolPorts{}, Vrf: "red", VrfId: 300},
		},
	}
	dpu.SubmitDPURuleToDPU(ruleAUpdated)
	assert.Equal(t, 2, len(dpu.ruleSet), "ruleSet should still have two rules after VRF ID change")

	// Verify against fresh listener
	dpuFresh := NewDPUListener(context.Background(), "127.0.0.1:8080")
	dpuFresh.SubmitDPURuleToDPU(ruleAUpdated)
	dpuFresh.SubmitDPURuleToDPU(ruleB)
	assert.Equal(t, dpu.Checksum(), dpuFresh.Checksum(), "checksums should match fresh listener")
}

func TestSubmitDPURuleToDPU_VRFIDSwap(t *testing.T) {
	dpu := NewDPUListener(context.Background(), "127.0.0.1:8080")

	// Two rules in different VRFs
	ruleRed := &DPUPolicyRule{
		Oper: v1alpha.PolicyOperation_POLICY_OPERATION_UPSERT,
		Policy: &DPURule{
			K8SResourceVersion: "1",
			K8SUid:             "uid-red",
			PolicyName:         "red-policy",
			RuleName:           "rule-1",
			Action:             v1alpha.PolicyAction_POLICY_ACTION_ALLOW,
			Source:             DPUSubject{Cidr: "10.0.0.0/8", Ports: &[]SmartSwitchNetworkProtocolPorts{}, Vrf: "red", VrfId: 100},
			Destination:        DPUSubject{Cidr: "10.1.0.0/16", Ports: &[]SmartSwitchNetworkProtocolPorts{}, Vrf: "red", VrfId: 100},
		},
	}
	ruleBlue := &DPUPolicyRule{
		Oper: v1alpha.PolicyOperation_POLICY_OPERATION_UPSERT,
		Policy: &DPURule{
			K8SResourceVersion: "1",
			K8SUid:             "uid-blue",
			PolicyName:         "blue-policy",
			RuleName:           "rule-1",
			Action:             v1alpha.PolicyAction_POLICY_ACTION_DENY,
			Source:             DPUSubject{Cidr: "172.16.0.0/12", Ports: &[]SmartSwitchNetworkProtocolPorts{}, Vrf: "blue", VrfId: 200},
			Destination:        DPUSubject{Cidr: "172.17.0.0/16", Ports: &[]SmartSwitchNetworkProtocolPorts{}, Vrf: "blue", VrfId: 200},
		},
	}
	dpu.SubmitDPURuleToDPU(ruleRed)
	dpu.SubmitDPURuleToDPU(ruleBlue)
	assert.Equal(t, 2, len(dpu.ruleSet))

	// Swap GIDs: red:100→200, blue:200→100
	ruleRedSwapped := &DPUPolicyRule{
		Oper: v1alpha.PolicyOperation_POLICY_OPERATION_UPSERT,
		Policy: &DPURule{
			K8SResourceVersion: "1",
			K8SUid:             "uid-red",
			PolicyName:         "red-policy",
			RuleName:           "rule-1",
			Action:             v1alpha.PolicyAction_POLICY_ACTION_ALLOW,
			Source:             DPUSubject{Cidr: "10.0.0.0/8", Ports: &[]SmartSwitchNetworkProtocolPorts{}, Vrf: "red", VrfId: 200},
			Destination:        DPUSubject{Cidr: "10.1.0.0/16", Ports: &[]SmartSwitchNetworkProtocolPorts{}, Vrf: "red", VrfId: 200},
		},
	}
	ruleBlueSwapped := &DPUPolicyRule{
		Oper: v1alpha.PolicyOperation_POLICY_OPERATION_UPSERT,
		Policy: &DPURule{
			K8SResourceVersion: "1",
			K8SUid:             "uid-blue",
			PolicyName:         "blue-policy",
			RuleName:           "rule-1",
			Action:             v1alpha.PolicyAction_POLICY_ACTION_DENY,
			Source:             DPUSubject{Cidr: "172.16.0.0/12", Ports: &[]SmartSwitchNetworkProtocolPorts{}, Vrf: "blue", VrfId: 100},
			Destination:        DPUSubject{Cidr: "172.17.0.0/16", Ports: &[]SmartSwitchNetworkProtocolPorts{}, Vrf: "blue", VrfId: 100},
		},
	}
	dpu.SubmitDPURuleToDPU(ruleRedSwapped)
	dpu.SubmitDPURuleToDPU(ruleBlueSwapped)
	assert.Equal(t, 2, len(dpu.ruleSet), "ruleSet should still have two rules after GID swap")

	// Verify against fresh listener
	dpuFresh := NewDPUListener(context.Background(), "127.0.0.1:8080")
	dpuFresh.SubmitDPURuleToDPU(ruleRedSwapped)
	dpuFresh.SubmitDPURuleToDPU(ruleBlueSwapped)
	assert.Equal(t, dpu.Checksum(), dpuFresh.Checksum(), "checksums should match fresh listener after GID swap")
}

func TestSendConfigTimeoutForcesReconnect(t *testing.T) {
	p := &peer{
		uid:            "test-peer",
		cfgCh:          make(chan *v1alpha.StreamDatapathConfigResponse),
		cfgReconnectCh: make(chan struct{}, 1),
	}

	start := time.Now()
	err := p.SendConfig(&v1alpha.StreamDatapathConfigResponse{})
	elapsed := time.Since(start)

	assert.Error(t, err)
	assert.GreaterOrEqual(t, elapsed, 2*time.Second)
	assert.Less(t, elapsed, 4*time.Second)

	select {
	case <-p.cfgReconnectCh:
	default:
		t.Fatal("expected reconnect signal after config send timeout")
	}
}

func TestSendConfigTimeoutReconnectSignalNonBlocking(t *testing.T) {
	p := &peer{
		uid:            "test-peer",
		cfgCh:          make(chan *v1alpha.StreamDatapathConfigResponse),
		cfgReconnectCh: make(chan struct{}, 1),
	}
	p.cfgReconnectCh <- struct{}{}

	start := time.Now()
	err := p.SendConfig(&v1alpha.StreamDatapathConfigResponse{})
	elapsed := time.Since(start)

	assert.Error(t, err)
	assert.GreaterOrEqual(t, elapsed, 2*time.Second)
	assert.Less(t, elapsed, 4*time.Second)

	select {
	case <-p.cfgReconnectCh:
	default:
		t.Fatal("expected reconnect signal channel to remain readable")
	}
	select {
	case <-p.cfgReconnectCh:
		t.Fatal("expected only one reconnect signal in buffered channel")
	default:
	}
}

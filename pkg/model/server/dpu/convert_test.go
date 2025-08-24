package dpu

import (
	"testing"

	"github.com/cilium/tetragon/api/v1/tetragon"

	"github.com/isovalent/hubble-fgs/pkg/endpoint"
	"github.com/isovalent/hubble-fgs/pkg/model/record"

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

	policy = record.Policy{
		Name: name,
		Rule: rule,
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
		Policy:   policy,
		Src:      nil,
		L3Src:    dpSrcVrf,
		Endpoint: dpEndpoint,
		Action:   action,
	}
	testRecordVlan = record.DatapathRecord{
		Policy:   policy,
		Src:      nil,
		L3Src:    dpSrcVlan,
		Endpoint: dpEndpoint,
		Action:   action,
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

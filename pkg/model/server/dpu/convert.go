package dpu

import (
	"fmt"

	"github.com/isovalent/ipa/l3l4networkpolicy/v1alpha"

	"github.com/isovalent/hubble-fgs/pkg/model/record"
)

// This converts the datapath record to the stream response that is sent
// to the peer DPUs. We should merge DatapathRecords into these objects
// so at some point we can remove this unnecessary translation.
func recordToDPUPolicyRule(r *record.DatapathRecord, update bool) *DPUPolicyRule {
	act := v1alpha.PolicyAction_POLICY_ACTION_UNSPECIFIED
	if r.Action != nil {
		switch r.Action.Action {
		case record.PolicyNone:
			act = v1alpha.PolicyAction_POLICY_ACTION_UNSPECIFIED
		case record.PolicyAllow:
			act = v1alpha.PolicyAction_POLICY_ACTION_ALLOW
		case record.PolicyDeny:
			act = v1alpha.PolicyAction_POLICY_ACTION_DENY
		}
	} else {
		act = v1alpha.PolicyAction_POLICY_ACTION_UNSPECIFIED
	}

	var operation v1alpha.PolicyOperation
	if update {
		operation = v1alpha.PolicyOperation_POLICY_OPERATION_UPSERT
	} else {
		operation = v1alpha.PolicyOperation_POLICY_OPERATION_DELETE
	}

	return &DPUPolicyRule{
		Oper: operation,
		Policy: &DPURule{
			PolicyName: r.Policy.Name,
			RuleName:   r.Policy.Rule,
			Action:     act,
			Source: DPUSubject{
				Cidr:     r.L3Src.Ip,
				MinPort:  r.L3Src.Port,
				MaxPort:  r.L3Src.Port,
				Vlan:     r.L3Src.Vlan,
				Vrf:      r.L3Src.Vrf,
				VrfId:    r.L3Src.VrfId,
				Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_TCP,
			},
			// The current policy resolution does not include destinatoin
			// Vlan and VRF this will be added soon.
			Destination: DPUSubject{
				Cidr:     r.Endpoint.EP.Ip,
				MinPort:  r.Endpoint.Port,
				MaxPort:  r.Endpoint.Port,
				Vlan:     0,
				Vrf:      "",
				VrfId:    0,
				Protocol: v1alpha.PolicyProtocol_POLICY_PROTOCOL_TCP,
			},
		},
	}
}

func ResponseToDPURule(resp *v1alpha.Streaml3L4NetworkPolicyResponse) *DPUPolicyRule {
	p := resp.Policy
	rule := &DPURule{
		PolicyName: p.PolicyName,
		RuleName:   p.RuleName,
		Action:     p.Action,
		Source: DPUSubject{
			Cidr:     p.Source.Network.Cidr,
			MinPort:  p.Source.Network.MinPort,
			MaxPort:  p.Source.Network.MaxPort,
			Vlan:     p.Source.Network.Vlan,
			Vrf:      p.Source.Network.Vrf,
			VrfId:    p.Source.Network.VrfId,
			Protocol: p.Source.Network.Protocol,
		},
		Destination: DPUSubject{
			Cidr:     p.Destination.Network.Cidr,
			MinPort:  p.Destination.Network.MinPort,
			MaxPort:  p.Destination.Network.MaxPort,
			Vlan:     p.Destination.Network.Vlan,
			Vrf:      p.Destination.Network.Vrf,
			VrfId:    p.Destination.Network.VrfId,
			Protocol: p.Destination.Network.Protocol,
		},
	}

	return &DPUPolicyRule{
		Oper:   resp.Oper,
		Policy: rule,
	}
}

func dpuRuleToResponse(rule *DPUPolicyRule) *v1alpha.Streaml3L4NetworkPolicyResponse {
	r := rule.Policy

	source := &v1alpha.PolicySubject{
		Network: &v1alpha.L3L4NetworkSubject{
			Cidr:     r.Source.Cidr,
			MinPort:  r.Source.MinPort,
			MaxPort:  r.Source.MaxPort,
			Vlan:     r.Source.Vlan,
			Vrf:      r.Source.Vrf,
			VrfId:    r.Source.VrfId,
			Protocol: r.Source.Protocol,
		},
	}
	dest := &v1alpha.PolicySubject{
		Network: &v1alpha.L3L4NetworkSubject{
			Cidr:     r.Destination.Cidr,
			MinPort:  r.Destination.MinPort,
			MaxPort:  r.Destination.MaxPort,
			Vlan:     r.Destination.Vlan,
			Vrf:      r.Destination.Vrf,
			VrfId:    r.Source.VrfId,
			Protocol: r.Destination.Protocol,
		},
	}
	policy := &v1alpha.PolicyRule{
		PolicyName:  r.PolicyName,
		RuleName:    r.RuleName,
		Action:      r.Action,
		Source:      source,
		Destination: dest,
	}
	return &v1alpha.Streaml3L4NetworkPolicyResponse{
		Oper:   rule.Oper,
		Policy: policy,
	}
}

func reportRequestToDPU(req *v1alpha.ReportStatusRequest) *DPUReportStatus {
	return &DPUReportStatus{
		AgentUid:       req.Status.AgentUid,
		DpVersion:      req.Status.DpVersion,
		AgentVersion:   req.Status.AgentVersion,
		PolicyChecksum: req.Status.PolicyChecksum,
		Hostname:       req.Status.Hostname,
		Architecture:   req.Status.Architecture,
		OS:             req.Status.Os,
		Type:           req.Status.Type,
		SerialNumber:   req.Status.SerialNumber,
	}
}

// Passes the full DpuConfig from the agw and returns the port mapped DPU specific
// DpuConfig object.
func getPerDpuConfig(fullCfg *v1alpha.DpuConfig, id string) (*v1alpha.DpuConfig, error) {
	// Divides the port range into equal parts mapped to each DPU by IP
	dpuCfg := v1alpha.DpuConfig{
		ServiceMac: fullCfg.ServiceMac,
		ServiceIp:  fullCfg.ServiceIp,
	}
	portCount := int(fullCfg.PortHigh-fullCfg.PortLow+1) / dpuCount
	if portCount < 1 {
		return nil, fmt.Errorf("dpu config creation failed, unable to assign each dpu a port")
	}
	index := 0
	switch id {
	case AgentIdDpu1:
		index = 0
	case AgentIdDpu2:
		index = 1
	case AgentIdDpu3:
		index = 2
	case AgentIdDpu4:
		index = 3
	}
	if index >= dpuCount {
		return nil, fmt.Errorf("incompatible port range for dpu %s with a total dpu count of %d", id, dpuCount)
	}
	dpuCfg.PortLow = fullCfg.PortLow + uint32(portCount*index)
	dpuCfg.PortHigh = fullCfg.PortLow + uint32(portCount*(index+1)) - 1
	return &dpuCfg, nil
}

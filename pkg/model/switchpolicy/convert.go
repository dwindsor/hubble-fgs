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
	"fmt"
	"time"

	"github.com/isovalent/ipa/l3l4networkpolicy/v1alpha"
)

func ResponseToDPURule(resp *v1alpha.Streaml3L4NetworkPolicyResponse) *DPUPolicyRule {
	p := resp.Policy
	srcPorts := []SmartSwitchNetworkProtocolPorts{}
	dstPorts := []SmartSwitchNetworkProtocolPorts{}

	for _, p := range p.Source.Network.Ports {
		srcPorts = append(srcPorts, SmartSwitchNetworkProtocolPorts{
			Port:     p.MinPort,
			EndPort:  p.MaxPort,
			Protocol: p.Protocol,
		})
	}
	for _, p := range p.Destination.Network.Ports {
		dstPorts = append(dstPorts, SmartSwitchNetworkProtocolPorts{
			Port:     p.MinPort,
			EndPort:  p.MaxPort,
			Protocol: p.Protocol,
		})
	}

	rule := &DPURule{
		K8SResourceVersion: p.K8SResourceVersion,
		K8SUid:             p.K8SUid,
		PolicyName:         p.PolicyName,
		RuleName:           p.RuleName,
		Action:             p.Action,
		Source: DPUSubject{
			Cidr:  p.Source.Network.Cidr,
			Ports: &srcPorts,
			Vlan:  p.Source.Network.Vlan,
			Vrf:   p.Source.Network.Vrf,
			VrfId: p.Source.Network.VrfId,
		},
		Destination: DPUSubject{
			Cidr:  p.Destination.Network.Cidr,
			Ports: &dstPorts,
			Vlan:  p.Destination.Network.Vlan,
			Vrf:   p.Destination.Network.Vrf,
			VrfId: p.Destination.Network.VrfId,
		},
	}

	return &DPUPolicyRule{
		Oper:      resp.Oper,
		Timestamp: time.Now(),
		Policy:    rule,
	}
}

func dpuRuleToResponse(rule *DPUPolicyRule) *v1alpha.Streaml3L4NetworkPolicyResponse {
	r := rule.Policy

	srcPorts := []*v1alpha.PolicyPorts{}
	dstPorts := []*v1alpha.PolicyPorts{}

	for _, p := range *r.Destination.Ports {
		dstPorts = append(dstPorts, &v1alpha.PolicyPorts{
			MinPort:  p.Port,
			MaxPort:  p.EndPort,
			Protocol: p.Protocol,
		})
	}

	if r.Source.Ports != nil {
		for _, p := range *r.Source.Ports {
			srcPorts = append(srcPorts, &v1alpha.PolicyPorts{
				MinPort:  p.Port,
				MaxPort:  p.EndPort,
				Protocol: p.Protocol,
			})
		}
	}

	source := &v1alpha.PolicySubject{
		Network: &v1alpha.L3L4NetworkSubject{
			Cidr:  r.Source.Cidr,
			Ports: srcPorts,
			Vlan:  r.Source.Vlan,
			Vrf:   r.Source.Vrf,
			VrfId: r.Source.VrfId,
		},
	}
	dest := &v1alpha.PolicySubject{
		Network: &v1alpha.L3L4NetworkSubject{
			Cidr:  r.Destination.Cidr,
			Ports: dstPorts,
			Vlan:  uint32(r.Destination.Vlan),
			Vrf:   r.Destination.Vrf,
			VrfId: r.Destination.VrfId,
		},
	}
	policy := &v1alpha.PolicyRule{
		K8SResourceVersion: r.K8SResourceVersion,
		K8SUid:             r.K8SUid,
		PolicyName:         r.PolicyName,
		RuleName:           r.RuleName,
		Action:             r.Action,
		Source:             source,
		Destination:        dest,
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
		HardwareModel:  req.Status.HardwareModel,
		DpuReboot:      req.Status.DpuRestarts,
		LastDpuReboot:  req.Status.LastDpuRestart,
		DpRestart:      req.Status.DataplaneRestarts,
		LastDpCrash:    req.Status.LastDataplaneRestart,
		LastFwaCrash:   req.Status.LastFwaCrashTime,
		PortLow:        req.Status.PortLow,
		PortHigh:       req.Status.PortHigh,
	}
}

// calculateDpuPortRange calculates the port range for a specific DPU based on the full port range
// and the DPU's position in the cluster. Returns portLow, portHigh, dpuNum, and any error.
func calculateDpuPortRange(portLow, portHigh uint32, id string, dpuCount uint16) (uint32, uint32, int, error) {
	portCount := int(portHigh-portLow+1) / int(dpuCount)
	if portCount < 1 {
		return 0, 0, 0, fmt.Errorf("dpu config creation failed, unable to assign each dpu a port")
	}
	dpuNum, ok := DPUMap[id]
	if !ok {
		if dpuCount == 1 {
			// Dev DSC testbed case
			dpuNum = 1
		} else {
			return 0, 0, 0, fmt.Errorf("dpu config creation failed, unable to map id to dpu")
		}
	}

	index := dpuNum - 1
	if index >= int(dpuCount) {
		return 0, 0, 0, fmt.Errorf("incompatible port range for dpu %s with a total dpu count of %d", id, dpuCount)
	}
	dpuPortLow := portLow + uint32(portCount*index)
	dpuPortHigh := portLow + uint32(portCount*(index+1)) - 1
	return dpuPortLow, dpuPortHigh, dpuNum, nil
}

// Passes the full DpuConfig from the agw and returns the port mapped DPU specific
// DpuConfig object.
func getPerDpuConfig(fullCfg *v1alpha.DpuConfig, id string, dpuCount uint16) (*v1alpha.DpuConfig, error) {
	// Divides the port range into equal parts mapped to each DPU by IP
	dpuCfg := v1alpha.DpuConfig{
		ServiceMac:   fullCfg.ServiceMac,
		ServiceIp:    fullCfg.ServiceIp,
		HaIp:         fullCfg.HaIp,
		SerialNumber: fullCfg.SerialNumber,
		SwitchName:   fullCfg.SwitchName,
	}
	portLow, portHigh, dpuNum, err := calculateDpuPortRange(fullCfg.PortLow, fullCfg.PortHigh, id, dpuCount)
	if err != nil {
		return nil, err
	}
	dpuCfg.PortLow = portLow
	dpuCfg.PortHigh = portHigh
	dpuCfg.DpuId = uint32(dpuNum)
	return &dpuCfg, nil
}

// Passes the full HaConfig from the agw and returns the port mapped DPU specific
// HaConfig object with peer port ranges calculated for this DPU.
func getPerDpuHaConfig(fullCfg *v1alpha.HaConfig, id string, dpuCount uint16) (*v1alpha.HaConfig, error) {
	haCfg := v1alpha.HaConfig{
		Enabled:  fullCfg.Enabled,
		FlowSync: fullCfg.FlowSync,
	}

	for _, peer := range fullCfg.Peers {
		portLow, portHigh, _, err := calculateDpuPortRange(peer.MinPort, peer.MaxPort, id, dpuCount)
		if err != nil {
			return nil, err
		}
		haCfg.Peers = append(haCfg.Peers, &v1alpha.HaPeer{
			Ip:      peer.Ip,
			MinPort: portLow,
			MaxPort: portHigh,
		})
	}

	return &haCfg, nil
}

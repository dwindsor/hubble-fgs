// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package vrf

import (
	"context"
	"fmt"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/openconfig/ygot/ygot"

	"github.com/isovalent/hubble-fgs/pkg/nxos/gnmi"
	"github.com/isovalent/hubble-fgs/pkg/nxos/gnmi/paths"
	"github.com/isovalent/hubble-fgs/pkg/nxos/types"
	model "github.com/isovalent/hubble-fgs/pkg/nxosmodel"
)

const (
	// seqNum is the default sequence number for redirect match entries.
	seqNum = 10
)

// programRedirects programs all redirect components for a single VRF.
// Called when a VRF transitions to active. Each sub-call sets the individual
// list entry path so that sibling VRF entries are not overwritten.
func (s *vrfStore) programRedirects(ctx context.Context, vrf types.VRF) {
	s.mu.RLock()
	handler := s.gnmiHandler
	ready := s.redirectsReady
	s.mu.RUnlock()
	if handler == nil || !ready {
		return
	}
	s.programFwPolicyState(ctx, handler, vrf)
	s.programServiceEndpoints(ctx, handler, vrf)
	s.programPolicyMap(ctx, handler, vrf)
	s.programEnforcement(ctx, handler, vrf)
}

// programFwPolicyState programs the firewall policy state for a single VRF.
func (s *vrfStore) programFwPolicyState(ctx context.Context, handler gnmi.GnmiHandler, vrf types.VRF) {
	reason := ""
	affinity := model.Cisco_NX_OSDevice_Sas_SvcModulePinning_all
	if vrf.DPUPinned > 0 && s.isPinningActive() {
		affinity = dpuToModulePinning(vrf.DPUPinned)
	}
	extItems := model.Cisco_NX_OSDevice_System_SasItems_SvcItems_SvcinstItems_SvcInstanceList_FwpolicystateItems_IpvrfstateItems_DomItems_DomStateList_ExtItems{
		PolicyStatus:       model.Cisco_NX_OSDevice_Sas_PolicyStatusE_success,
		PolicyStatusReason: &reason,
		Affinity:           affinity,
	}
	name := vrf.Name
	dsList := model.Cisco_NX_OSDevice_System_SasItems_SvcItems_SvcinstItems_SvcInstanceList_FwpolicystateItems_IpvrfstateItems_DomItems_DomStateList{
		Name:     &name,
		ExtItems: &extItems,
	}

	domItems := model.Cisco_NX_OSDevice_System_SasItems_SvcItems_SvcinstItems_SvcInstanceList_FwpolicystateItems_IpvrfstateItems_DomItems{
		DomStateList: map[string]*model.Cisco_NX_OSDevice_System_SasItems_SvcItems_SvcinstItems_SvcInstanceList_FwpolicystateItems_IpvrfstateItems_DomItems_DomStateList{
			vrf.Name: &dsList,
		},
	}

	jstr, err := ygot.EmitJSON(&domItems, &ygot.EmitJSONConfig{
		Format:        ygot.RFC7951,
		Indent:        "  ",
		RFC7951Config: &ygot.RFC7951JSONConfig{},
	})
	if err != nil {
		logger.GetLogger().Error("Failed to emit JSON for VRF fwPolicyState", logfields.Error, err)
		return
	}

	if err := handler.Set(ctx, paths.FwPolicyStateVrf, jstr); err != nil {
		logger.GetLogger().Error("Failed to program VRF fwPolicyState via gNMI", logfields.Error, err)
		return
	}

	logger.GetLogger().Debug("VRF fwPolicyState programmed", "vrf", vrf.Name)
}

// programPolicyMap programs the policy map for a single VRF.
func (s *vrfStore) programPolicyMap(ctx context.Context, handler gnmi.GnmiHandler, vrf types.VRF) {
	name := fmt.Sprintf("__%s_dpu_redir", vrf.Name)
	policyMap := s.buildPolicyMap(name)

	pmapItems := model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_PmapItems{
		PolicyMapList: map[string]*model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_PmapItems_PolicyMapList{
			name: policyMap,
		},
	}

	jstr, err := ygot.EmitJSON(&pmapItems, &ygot.EmitJSONConfig{
		Format:        ygot.RFC7951,
		Indent:        "  ",
		RFC7951Config: &ygot.RFC7951JSONConfig{},
	})
	if err != nil {
		logger.GetLogger().Error("Failed to emit JSON for VRF policy map", logfields.Error, err)
		return
	}

	if err := handler.Set(ctx, paths.ServiceRedirPmapItems, jstr); err != nil {
		logger.GetLogger().Error("Failed to program VRF policy map via gNMI", logfields.Error, err)
		return
	}

	logger.GetLogger().Debug("VRF policy map programmed", "vrf", vrf.Name)
}

// programServiceEndpoints programs the DPU service endpoint for a single VRF.
func (s *vrfStore) programServiceEndpoints(ctx context.Context, handler gnmi.GnmiHandler, vrf types.VRF) {
	if vrf.GID == 0 {
		logger.GetLogger().Warn("VRF has no GID allocated, skipping service endpoint", "vrf", vrf.Name)
		return
	}

	gid := vrf.GID
	dpuNum := model.Cisco_NX_OSDevice_Sas_SvcModulePinning_all
	if vrf.DPUPinned > 0 && s.isPinningActive() {
		dpuNum = dpuToModulePinning(vrf.DPUPinned)
	}

	svcEndPointDpuList := model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_ServiceItems_ServiceList_DpuepItems_SvcEndPointDpuList{
		Vlan:   &gid,
		DpuNum: dpuNum,
	}

	dpuepItems := model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_ServiceItems_ServiceList_DpuepItems{
		SvcEndPointDpuList: map[model.E_Cisco_NX_OSDevice_Sas_SvcModulePinning]*model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_ServiceItems_ServiceList_DpuepItems_SvcEndPointDpuList{
			dpuNum: &svcEndPointDpuList,
		},
	}

	name := fmt.Sprintf("__%s_dpu_redir", vrf.Name)
	vrfName := vrf.Name
	serviceList := model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_ServiceItems_ServiceList{
		Name:       &name,
		Type:       model.Cisco_NX_OSDevice_Epbr_EpbrType_dpu,
		Vrf:        &vrfName,
		DpuepItems: &dpuepItems,
	}

	serviceItems := model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_ServiceItems{
		ServiceList: map[string]*model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_ServiceItems_ServiceList{
			name: &serviceList,
		},
	}

	jstr, err := ygot.EmitJSON(&serviceItems, &ygot.EmitJSONConfig{
		Format:        ygot.RFC7951,
		Indent:        "  ",
		RFC7951Config: &ygot.RFC7951JSONConfig{},
	})
	if err != nil {
		logger.GetLogger().Error("Failed to emit JSON for VRF service endpoint", logfields.Error, err)
		return
	}

	if err := handler.Set(ctx, paths.ServiceRedirServiceItems, jstr); err != nil {
		logger.GetLogger().Error("Failed to program VRF service endpoint via gNMI", logfields.Error, err)
		return
	}

	logger.GetLogger().Debug("VRF service endpoint programmed", "vrf", vrf.Name)
}

// programEnforcement programs the VRF-to-policy enforcement binding for a single VRF.
func (s *vrfStore) programEnforcement(ctx context.Context, handler gnmi.GnmiHandler, vrf types.VRF) {
	name := vrf.Name
	policy := fmt.Sprintf("__%s_dpu_redir", name)
	domList := model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_DomItems_DomList{
		Name:   &name,
		Policy: &policy,
	}

	domItems := model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_DomItems{
		DomList: map[string]*model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_DomItems_DomList{
			name: &domList,
		},
	}

	jstr, err := ygot.EmitJSON(&domItems, &ygot.EmitJSONConfig{
		Format:        ygot.RFC7951,
		Indent:        "  ",
		RFC7951Config: &ygot.RFC7951JSONConfig{},
	})
	if err != nil {
		logger.GetLogger().Error("Failed to emit JSON for VRF enforcement", logfields.Error, err)
		return
	}

	if err := handler.Set(ctx, paths.ServiceRedirDomItems, jstr); err != nil {
		logger.GetLogger().Error("Failed to program VRF enforcement via gNMI", logfields.Error, err)
		return
	}

	logger.GetLogger().Debug("VRF enforcement programmed", "vrf", vrf.Name)
}

// dpuToEndpointKey returns the gNMI key string for a DPU number in SvcEndPointDpu-list.
// Maps DPU numbers (1-4) to their enum string names, and 0 to "all".
func dpuToEndpointKey(dpu uint16) string {
	if dpu >= 1 && dpu <= 4 {
		return fmt.Sprintf("%d", dpu)
	}
	return "all"
}

// deleteDpuEndpoint deletes the old DPU endpoint for a VRF during repinning.
// gNMI MERGE on SvcEndPointDpuList adds the new DPU key but doesn't remove the old one,
// so we must explicitly DELETE the stale endpoint.
func (s *vrfStore) deleteDpuEndpoint(ctx context.Context, handler gnmi.GnmiHandler, vrfName string, oldDPU uint16) {
	key := dpuToEndpointKey(oldDPU)
	path := fmt.Sprintf("%s/Service-list[name=__%s_dpu_redir]/dpuep-items/SvcEndPointDpu-list[dpuNum=%s]",
		paths.ServiceRedirServiceItems, vrfName, key)
	if err := handler.Delete(ctx, path); err != nil {
		logger.GetLogger().Warn("Failed to delete old DPU endpoint during repinning",
			"vrf", vrfName, "oldDPU", oldDPU, logfields.Error, err)
	}
}

// deleteDpuEndpointForRepin acquires the gNMI handler and deletes an old DPU endpoint.
// Called during repinning before programming the new endpoint.
func (s *vrfStore) deleteDpuEndpointForRepin(ctx context.Context, vrfName string, oldDPU uint16) {
	s.mu.RLock()
	handler := s.gnmiHandler
	ready := s.redirectsReady
	s.mu.RUnlock()
	if handler == nil || !ready {
		return
	}
	s.deleteDpuEndpoint(ctx, handler, vrfName, oldDPU)
}

// cleanupRedirects performs targeted gNMI DELETE for all redirect components
// of a specific VRF. Called when a VRF is removed or becomes inactive.
func (s *vrfStore) cleanupRedirects(ctx context.Context, name string) {
	s.mu.RLock()
	handler := s.gnmiHandler
	s.mu.RUnlock()

	if handler == nil {
		return
	}

	// Delete enforcement binding
	path := fmt.Sprintf("%s/Dom-list[name=%s]", paths.ServiceRedirDomItems, name)
	if err := handler.Delete(ctx, path); err != nil {
		logger.GetLogger().Warn("Failed to delete VRF enforcement binding", "vrf", name, logfields.Error, err)
	}

	// Delete policy map
	path = fmt.Sprintf("%s/PolicyMap-list[name=__%s_dpu_redir]", paths.ServiceRedirPmapItems, name)
	if err := handler.Delete(ctx, path); err != nil {
		logger.GetLogger().Warn("Failed to delete VRF policy map", "vrf", name, logfields.Error, err)
	}

	// Delete service endpoint
	path = fmt.Sprintf("%s/Service-list[name=__%s_dpu_redir]", paths.ServiceRedirServiceItems, name)
	if err := handler.Delete(ctx, path); err != nil {
		logger.GetLogger().Warn("Failed to delete VRF service endpoint", "vrf", name, logfields.Error, err)
	}

	// Delete fwPolicyState entry
	path = fmt.Sprintf("%s/DomState-list[name=%s]/ext-items", paths.FwPolicyStateVrf, name)
	if err := handler.Delete(ctx, path); err != nil {
		logger.GetLogger().Warn("Failed to delete VRF fwPolicyState", "vrf", name, logfields.Error, err)
	}

	logger.GetLogger().Debug("VRF redirect cleanup completed", "vrf", name)
}

// ReconcileRedirects reprograms redirects for all active VRFs.
// Called during startup after shared infrastructure is in place,
// bypassing the redirectsReady gate.
func (s *vrfStore) ReconcileRedirects(ctx context.Context) {
	s.mu.RLock()
	handler := s.gnmiHandler
	s.mu.RUnlock()
	if handler == nil {
		return
	}

	activeVRFs := s.ListActive()
	for _, v := range activeVRFs {
		s.programFwPolicyState(ctx, handler, v)
		s.programServiceEndpoints(ctx, handler, v)
		s.programPolicyMap(ctx, handler, v)
		s.programEnforcement(ctx, handler, v)
	}
	logger.GetLogger().Info("VRF redirects reconciled", "count", len(activeVRFs))
}

// CleanupAllFwPolicyState deletes fwPolicyState for all active VRFs.
// Called during Close() to clean up stale state on the switch.
func (s *vrfStore) CleanupAllFwPolicyState(ctx context.Context) {
	s.mu.RLock()
	handler := s.gnmiHandler
	s.mu.RUnlock()
	if handler == nil {
		return
	}

	for _, v := range s.ListActive() {
		path := fmt.Sprintf("%s/DomState-list[name=%s]/ext-items", paths.FwPolicyStateVrf, v.Name)
		if err := handler.Delete(ctx, path); err != nil {
			logger.GetLogger().Warn("Failed to delete VRF fwPolicyState during cleanup", "vrf", v.Name, "error", err)
		}
	}
}

// dpuToModulePinning converts a DPU number to the corresponding SvcModulePinning enum.
func dpuToModulePinning(dpu uint16) model.E_Cisco_NX_OSDevice_Sas_SvcModulePinning {
	switch dpu {
	case 1:
		return model.Cisco_NX_OSDevice_Sas_SvcModulePinning_1
	case 2:
		return model.Cisco_NX_OSDevice_Sas_SvcModulePinning_2
	case 3:
		return model.Cisco_NX_OSDevice_Sas_SvcModulePinning_3
	case 4:
		return model.Cisco_NX_OSDevice_Sas_SvcModulePinning_4
	default:
		return model.Cisco_NX_OSDevice_Sas_SvcModulePinning_all
	}
}

// buildPolicyMap builds a policy map with the given name.
func (s *vrfStore) buildPolicyMap(name string) *model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_PmapItems_PolicyMapList {
	sn := uint32(seqNum)

	// Build sequence item for the redirect match
	epbrMatchSeqList := model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_PmapItems_PolicyMapList_MatchItems_EpbrMatchList_SeqItems_EpbrMatchSeqList{
		Failaction: model.Cisco_NX_OSDevice_Epbr_FailactionType_drop,
		Name:       &name,
		Seqno:      &sn,
	}

	seqItems := model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_PmapItems_PolicyMapList_MatchItems_EpbrMatchList_SeqItems{
		EpbrMatchSeqList: map[uint32]*model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_PmapItems_PolicyMapList_MatchItems_EpbrMatchList_SeqItems_EpbrMatchSeqList{
			sn: &epbrMatchSeqList,
		},
	}

	// Build IPv4 redirect match
	aclNameV4 := paths.AclNameIPv4
	isIPv6V4 := false
	epbrMatchListV4 := model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_PmapItems_PolicyMapList_MatchItems_EpbrMatchList{
		AclType:       model.Cisco_NX_OSDevice_Epbr_IpType_ipv4,
		IsIPv6:        &isIPv6V4,
		Name:          &aclNameV4,
		TrafficAction: model.Cisco_NX_OSDevice_Epbr_TrafficActionType_redirect,
		SeqItems:      &seqItems,
	}

	// Build IPv6 redirect match
	aclNameV6 := paths.AclNameIPv6
	isIPv6V6 := true
	epbrMatchListV6 := model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_PmapItems_PolicyMapList_MatchItems_EpbrMatchList{
		AclType:       model.Cisco_NX_OSDevice_Epbr_IpType_ipv6,
		IsIPv6:        &isIPv6V6,
		Name:          &aclNameV6,
		TrafficAction: model.Cisco_NX_OSDevice_Epbr_TrafficActionType_redirect,
		SeqItems:      &seqItems,
	}

	// Build match items containing both IPv4 and IPv6
	matchItems := model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_PmapItems_PolicyMapList_MatchItems{
		EpbrMatchList: map[string]*model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_PmapItems_PolicyMapList_MatchItems_EpbrMatchList{
			aclNameV4: &epbrMatchListV4,
			aclNameV6: &epbrMatchListV6,
		},
	}

	// Build the policy map
	stats := true
	policyMapList := model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_PmapItems_PolicyMapList{
		Name:       &name,
		Statistics: &stats,
		MatchItems: &matchItems,
	}

	return &policyMapList
}

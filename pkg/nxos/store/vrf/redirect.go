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
	inService := s.inService
	s.mu.RUnlock()
	if handler == nil || !inService {
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
	if vrf.DPUPinned > 0 && s.isPinningActiveLocked() {
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
	if vrf.DPUPinned > 0 && s.isPinningActiveLocked() {
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
	inService := s.inService
	s.mu.RUnlock()
	if handler == nil || !inService {
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

	s.deleteRedirectsWithHandler(ctx, handler, name)
}

// cleanupRedirectsLocked performs targeted gNMI DELETE for all redirect components
// of a specific VRF. Must be called with at least a read lock held (or write lock).
func (s *vrfStore) cleanupRedirectsLocked(ctx context.Context, name string) {
	handler := s.gnmiHandler
	if handler == nil {
		return
	}
	s.deleteRedirectsWithHandler(ctx, handler, name)
}

// deleteRedirectsWithHandler issues gNMI DELETEs for all redirect components of a VRF.
func (s *vrfStore) deleteRedirectsWithHandler(ctx context.Context, handler gnmi.GnmiHandler, name string) {
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

// programFwPolicyStateBatch programs fwPolicyState for all VRFs in a single gNMI SET.
func (s *vrfStore) programFwPolicyStateBatch(ctx context.Context, handler gnmi.GnmiHandler, vrfs []types.VRF) {
	domItems := model.Cisco_NX_OSDevice_System_SasItems_SvcItems_SvcinstItems_SvcInstanceList_FwpolicystateItems_IpvrfstateItems_DomItems{
		DomStateList: make(map[string]*model.Cisco_NX_OSDevice_System_SasItems_SvcItems_SvcinstItems_SvcInstanceList_FwpolicystateItems_IpvrfstateItems_DomItems_DomStateList),
	}

	for _, vrf := range vrfs {
		reason := ""
		affinity := model.Cisco_NX_OSDevice_Sas_SvcModulePinning_all
		if vrf.DPUPinned > 0 && s.isPinningActiveLocked() {
			affinity = dpuToModulePinning(vrf.DPUPinned)
		}
		name := vrf.Name
		domItems.DomStateList[vrf.Name] = &model.Cisco_NX_OSDevice_System_SasItems_SvcItems_SvcinstItems_SvcInstanceList_FwpolicystateItems_IpvrfstateItems_DomItems_DomStateList{
			Name: &name,
			ExtItems: &model.Cisco_NX_OSDevice_System_SasItems_SvcItems_SvcinstItems_SvcInstanceList_FwpolicystateItems_IpvrfstateItems_DomItems_DomStateList_ExtItems{
				PolicyStatus:       model.Cisco_NX_OSDevice_Sas_PolicyStatusE_success,
				PolicyStatusReason: &reason,
				Affinity:           affinity,
			},
		}
	}

	jstr, err := ygot.EmitJSON(&domItems, &ygot.EmitJSONConfig{
		Format:        ygot.RFC7951,
		Indent:        "  ",
		RFC7951Config: &ygot.RFC7951JSONConfig{},
	})
	if err != nil {
		logger.GetLogger().Error("Failed to emit JSON for batch VRF fwPolicyState", logfields.Error, err)
		return
	}
	if err := handler.Set(ctx, paths.FwPolicyStateVrf, jstr); err != nil {
		logger.GetLogger().Error("Failed to batch program VRF fwPolicyState via gNMI", logfields.Error, err)
	}
}

// programServiceEndpointsBatch programs service endpoints for all VRFs in a single gNMI SET.
func (s *vrfStore) programServiceEndpointsBatch(ctx context.Context, handler gnmi.GnmiHandler, vrfs []types.VRF) {
	serviceItems := model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_ServiceItems{
		ServiceList: make(map[string]*model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_ServiceItems_ServiceList),
	}

	for _, vrf := range vrfs {
		if vrf.GID == 0 {
			logger.GetLogger().Warn("VRF has no GID allocated, skipping batch service endpoint", "vrf", vrf.Name)
			continue
		}
		gid := vrf.GID
		dpuNum := model.Cisco_NX_OSDevice_Sas_SvcModulePinning_all
		if vrf.DPUPinned > 0 && s.isPinningActiveLocked() {
			dpuNum = dpuToModulePinning(vrf.DPUPinned)
		}
		name := fmt.Sprintf("__%s_dpu_redir", vrf.Name)
		vrfName := vrf.Name
		serviceItems.ServiceList[name] = &model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_ServiceItems_ServiceList{
			Name: &name,
			Type: model.Cisco_NX_OSDevice_Epbr_EpbrType_dpu,
			Vrf:  &vrfName,
			DpuepItems: &model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_ServiceItems_ServiceList_DpuepItems{
				SvcEndPointDpuList: map[model.E_Cisco_NX_OSDevice_Sas_SvcModulePinning]*model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_ServiceItems_ServiceList_DpuepItems_SvcEndPointDpuList{
					dpuNum: {Vlan: &gid, DpuNum: dpuNum},
				},
			},
		}
	}

	jstr, err := ygot.EmitJSON(&serviceItems, &ygot.EmitJSONConfig{
		Format:        ygot.RFC7951,
		Indent:        "  ",
		RFC7951Config: &ygot.RFC7951JSONConfig{},
	})
	if err != nil {
		logger.GetLogger().Error("Failed to emit JSON for batch VRF service endpoints", logfields.Error, err)
		return
	}
	if err := handler.Set(ctx, paths.ServiceRedirServiceItems, jstr); err != nil {
		logger.GetLogger().Error("Failed to batch program VRF service endpoints via gNMI", logfields.Error, err)
	}
}

// programPolicyMapBatch programs policy maps for all VRFs in a single gNMI SET.
func (s *vrfStore) programPolicyMapBatch(ctx context.Context, handler gnmi.GnmiHandler, vrfs []types.VRF) {
	pmapItems := model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_PmapItems{
		PolicyMapList: make(map[string]*model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_PmapItems_PolicyMapList),
	}

	for _, vrf := range vrfs {
		name := fmt.Sprintf("__%s_dpu_redir", vrf.Name)
		pmapItems.PolicyMapList[name] = s.buildPolicyMap(name)
	}

	jstr, err := ygot.EmitJSON(&pmapItems, &ygot.EmitJSONConfig{
		Format:        ygot.RFC7951,
		Indent:        "  ",
		RFC7951Config: &ygot.RFC7951JSONConfig{},
	})
	if err != nil {
		logger.GetLogger().Error("Failed to emit JSON for batch VRF policy maps", logfields.Error, err)
		return
	}
	if err := handler.Set(ctx, paths.ServiceRedirPmapItems, jstr); err != nil {
		logger.GetLogger().Error("Failed to batch program VRF policy maps via gNMI", logfields.Error, err)
	}
}

// programEnforcementBatch programs enforcement bindings for all VRFs in a single gNMI SET.
func (s *vrfStore) programEnforcementBatch(ctx context.Context, handler gnmi.GnmiHandler, vrfs []types.VRF) {
	domItems := model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_DomItems{
		DomList: make(map[string]*model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_DomItems_DomList),
	}

	for _, vrf := range vrfs {
		name := vrf.Name
		policy := fmt.Sprintf("__%s_dpu_redir", name)
		domItems.DomList[name] = &model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_DomItems_DomList{
			Name:   &name,
			Policy: &policy,
		}
	}

	jstr, err := ygot.EmitJSON(&domItems, &ygot.EmitJSONConfig{
		Format:        ygot.RFC7951,
		Indent:        "  ",
		RFC7951Config: &ygot.RFC7951JSONConfig{},
	})
	if err != nil {
		logger.GetLogger().Error("Failed to emit JSON for batch VRF enforcement", logfields.Error, err)
		return
	}
	if err := handler.Set(ctx, paths.ServiceRedirDomItems, jstr); err != nil {
		logger.GetLogger().Error("Failed to batch program VRF enforcement via gNMI", logfields.Error, err)
	}
}

// ProgramAllRedirects programs redirects for all active VRFs using batched gNMI SETs.
// Used during in-service transition. Bypasses the inService gate.
func (s *vrfStore) ProgramAllRedirects(ctx context.Context) int {
	s.mu.RLock()
	handler := s.gnmiHandler
	s.mu.RUnlock()
	if handler == nil {
		return 0
	}
	active := s.ListActive()
	if len(active) == 0 {
		return 0
	}
	// Program in order: fwPolicyState → endpoints → policyMaps → enforcement
	s.programFwPolicyStateBatch(ctx, handler, active)
	s.programServiceEndpointsBatch(ctx, handler, active)
	s.programPolicyMapBatch(ctx, handler, active)
	s.programEnforcementBatch(ctx, handler, active)
	return len(active)
}

// repinRedirects updates only the fwPolicyState and DPU endpoint for a VRF
// when DPU pinning changes. Policy map and enforcement are not touched since
// they reference the service by name (unchanged during repin).
func (s *vrfStore) repinRedirects(ctx context.Context, vrf types.VRF) {
	s.mu.RLock()
	handler := s.gnmiHandler
	inService := s.inService
	s.mu.RUnlock()

	if handler == nil || !inService {
		return
	}

	s.programFwPolicyState(ctx, handler, vrf)
	if err := s.setDpuEndpoint(ctx, handler, vrf); err != nil {
		logger.GetLogger().Error("Failed to set DPU endpoint during repin", "vrf", vrf.Name, logfields.Error, err)
	}
}

// setDpuEndpoint creates/updates only the DPU endpoint entry for a VRF service.
// Unlike programServiceEndpoints(), this does NOT set the Type or Vrf fields —
// relying on gNMI MERGE semantics to preserve existing fields.
func (s *vrfStore) setDpuEndpoint(ctx context.Context, handler gnmi.GnmiHandler, vrf types.VRF) error {
	svcName := fmt.Sprintf("__%s_dpu_redir", vrf.Name)
	gid := vrf.GID
	dpuNum := model.Cisco_NX_OSDevice_Sas_SvcModulePinning_all
	if vrf.DPUPinned > 0 && s.isPinningActiveLocked() {
		dpuNum = dpuToModulePinning(vrf.DPUPinned)
	}

	serviceItems := model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_ServiceItems{
		ServiceList: map[string]*model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_ServiceItems_ServiceList{
			svcName: {
				Name: &svcName,
				DpuepItems: &model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_ServiceItems_ServiceList_DpuepItems{
					SvcEndPointDpuList: map[model.E_Cisco_NX_OSDevice_Sas_SvcModulePinning]*model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_ServiceItems_ServiceList_DpuepItems_SvcEndPointDpuList{
						dpuNum: {Vlan: &gid, DpuNum: dpuNum},
					},
				},
			},
		},
	}

	jstr, err := ygot.EmitJSON(&serviceItems, &ygot.EmitJSONConfig{
		Format:        ygot.RFC7951,
		Indent:        "  ",
		RFC7951Config: &ygot.RFC7951JSONConfig{},
	})
	if err != nil {
		return fmt.Errorf("failed to marshal DPU endpoint: %w", err)
	}
	return handler.Set(ctx, paths.ServiceRedirServiceItems, jstr)
}

// CleanupAllRedirects removes redirects for all active VRFs.
// Used during out-of-service transition.
func (s *vrfStore) CleanupAllRedirects(ctx context.Context) {
	for _, v := range s.ListActive() {
		s.cleanupRedirects(ctx, v.Name)
	}
}

// ReconcileRedirects reprograms redirects for all active VRFs.
// Called during startup after shared infrastructure is in place.
// Unconditional — bypasses the inService gate.
func (s *vrfStore) ReconcileRedirects(ctx context.Context) {
	n := s.ProgramAllRedirects(ctx)
	logger.GetLogger().Info("VRF redirects reconciled", "count", n)
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

// modulePinningToDPU converts a SvcModulePinning enum to the corresponding DPU number.
// Returns 0 for the "all" enum value.
func modulePinningToDPU(pin model.E_Cisco_NX_OSDevice_Sas_SvcModulePinning) uint16 {
	switch pin {
	case model.Cisco_NX_OSDevice_Sas_SvcModulePinning_1:
		return 1
	case model.Cisco_NX_OSDevice_Sas_SvcModulePinning_2:
		return 2
	case model.Cisco_NX_OSDevice_Sas_SvcModulePinning_3:
		return 3
	case model.Cisco_NX_OSDevice_Sas_SvcModulePinning_4:
		return 4
	default:
		return 0 // "all"
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

// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package vlan

import (
	"context"
	"fmt"
	"hash/fnv"
	"strconv"
	"strings"
	"sync"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/openconfig/ygot/ygot"
	"github.com/openconfig/ygot/ytypes"

	"github.com/isovalent/hubble-fgs/pkg/nxos/gnmi"
	"github.com/isovalent/hubble-fgs/pkg/nxos/gnmi/paths"
	"github.com/isovalent/hubble-fgs/pkg/nxos/storage"
	"github.com/isovalent/hubble-fgs/pkg/nxos/types"
	model "github.com/isovalent/hubble-fgs/pkg/nxosmodel"
)

// vlanStore implements Store with integrated persistence.
//
// Persistence contract: fields in this struct are NOT persisted by default.
// To persist a new field on types.VLAN, you must ensure it is included in the
// types.VLAN struct (storage/file.go serializes the whole VLAN map). Struct-level
// fields of vlanStore (dpuCount, etc.) are NOT persisted — they are recomputed
// from gNMI state and device store configuration on startup.
type vlanStore struct {
	mu          sync.RWMutex
	vlans       map[string]types.VLAN
	callbacks   map[int]func(Event)
	nextCbID    int
	storage     storage.Storage
	gnmiHandler gnmi.GnmiHandler
	// DPU pinning configuration
	dpuCount        uint16 // number of DPUs for hash-based pinning
	isLbModePinning bool   // true when per-DPU pinning is active
	// In-service gate: when false, reactive programRedirects no-ops.
	// Set to true when the device transitions to in-service.
	inService bool
}

// Option configures Store.
type Option func(*vlanStore)

// WithStorage sets the storage backend for the VLAN store.
func WithStorage(s storage.Storage) Option {
	return func(vs *vlanStore) {
		vs.storage = s
	}
}

// WithDPUCount sets the number of DPUs for hash-based dynamic pinning.
func WithDPUCount(count uint16) Option {
	return func(vs *vlanStore) {
		vs.dpuCount = count
	}
}

// WithLbModePinning sets the initial per-DPU pinning mode.
// When false, all redirects use "all" DPUs regardless of the computed DPUPinned value.
func WithLbModePinning(active bool) Option {
	return func(vs *vlanStore) {
		vs.isLbModePinning = active
	}
}

// NewStore creates a new VLAN store with optional storage backend.
// If storage is provided, it loads initial state and persists changes automatically.
func NewStore(ctx context.Context, opts ...Option) Store {
	s := &vlanStore{
		vlans:     make(map[string]types.VLAN),
		callbacks: make(map[int]func(Event)),
	}

	for _, opt := range opts {
		opt(s)
	}

	// Load initial state from storage if available
	if s.storage != nil {
		vlans, err := s.storage.LoadVLANs(ctx)
		if err != nil && !storage.IsNotFound(err) {
			logger.GetLogger().Warn("Failed to load VLANs from storage", "error", err)
		}
		if vlans != nil {
			s.vlans = vlans
			logger.GetLogger().Info("Loaded VLANs from storage", "count", len(vlans))
		}
	}

	return s
}

func (s *vlanStore) Get(name string) (types.VLAN, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	vlan, ok := s.vlans[name]
	return vlan, ok
}

func (s *vlanStore) List() []types.VLAN {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]types.VLAN, 0, len(s.vlans))
	for _, vlan := range s.vlans {
		result = append(result, vlan)
	}
	return result
}

func (s *vlanStore) ListActive() []types.VLAN {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []types.VLAN
	for _, vlan := range s.vlans {
		if vlan.Active {
			result = append(result, vlan)
		}
	}
	return result
}

func (s *vlanStore) GetID(name string) (uint16, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if vlan, ok := s.vlans[name]; ok && vlan.ID > 0 {
		return vlan.ID, true
	}
	return 0, false
}

func (s *vlanStore) GetPinning(name string) (uint16, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if vlan, ok := s.vlans[name]; ok && vlan.DPUPinned > 0 {
		return vlan.DPUPinned, true
	}
	return 0, false
}

func (s *vlanStore) Watch(callback func(Event)) func() {
	s.mu.Lock()
	id := s.nextCbID
	s.nextCbID++
	s.callbacks[id] = callback
	s.mu.Unlock()

	return func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		delete(s.callbacks, id)
	}
}

func (s *vlanStore) notify(event Event) {
	s.mu.RLock()
	callbacks := make([]func(Event), 0, len(s.callbacks))
	for _, cb := range s.callbacks {
		callbacks = append(callbacks, cb)
	}
	s.mu.RUnlock()

	for _, cb := range callbacks {
		cb(event)
	}
}

// persist saves the current state to storage if available.
func (s *vlanStore) persist(ctx context.Context) {
	if s.storage == nil {
		return
	}

	// Make a copy of vlans while holding the lock
	s.mu.RLock()
	vlansCopy := make(map[string]types.VLAN, len(s.vlans))
	for k, v := range s.vlans {
		vlansCopy[k] = v
	}
	s.mu.RUnlock()

	// Persist synchronously
	if err := s.storage.SaveVLANs(ctx, vlansCopy); err != nil {
		logger.GetLogger().Warn("Failed to persist VLANs", "error", err)
	}
}

// programRedirects triggers service redirect programming for all active VLANs.
// It programs fwPolicyState and BD enforcement bindings. BD policy maps are
// per-DPU (shared) and not managed here.
// Gated on inService — no-ops when the device is out-of-service.
func (s *vlanStore) programRedirects(ctx context.Context) {
	s.mu.RLock()
	handler := s.gnmiHandler
	inService := s.inService
	s.mu.RUnlock()

	if handler == nil || !inService {
		return
	}

	vlans := s.ListActive()
	if len(vlans) == 0 {
		logger.GetLogger().Debug("No active VLANs to program for service redirect")
		return
	}

	s.programFwPolicyState(ctx, handler, vlans)
	s.programEnforcement(ctx, handler, vlans)
}

// programFwPolicyState programs the firewall policy state for active VLANs (BDs).
func (s *vlanStore) programFwPolicyState(ctx context.Context, handler gnmi.GnmiHandler, vlans []types.VLAN) {
	vlanItems := model.Cisco_NX_OSDevice_System_SasItems_SvcItems_SvcinstItems_SvcInstanceList_FwpolicystateItems_BdstateItems_VlanItems{
		VlanStateList: map[string]*model.Cisco_NX_OSDevice_System_SasItems_SvcItems_SvcinstItems_SvcInstanceList_FwpolicystateItems_BdstateItems_VlanItems_VlanStateList{},
	}

	for _, vlan := range vlans {
		reason := ""
		affinity := model.Cisco_NX_OSDevice_Sas_SvcModulePinning_all
		if vlan.DPUPinned > 0 && s.isPinningActiveLocked() {
			affinity = dpuToModulePinning(vlan.DPUPinned)
		}
		extItems := model.Cisco_NX_OSDevice_System_SasItems_SvcItems_SvcinstItems_SvcInstanceList_FwpolicystateItems_BdstateItems_VlanItems_VlanStateList_ExtItems{
			PolicyStatus:       model.Cisco_NX_OSDevice_Sas_PolicyStatusE_success,
			PolicyStatusReason: &reason,
			Affinity:           affinity,
		}
		name := vlan.Name
		vsList := model.Cisco_NX_OSDevice_System_SasItems_SvcItems_SvcinstItems_SvcInstanceList_FwpolicystateItems_BdstateItems_VlanItems_VlanStateList{
			VlanId:   &name,
			ExtItems: &extItems,
		}
		vlanItems.VlanStateList[vlan.Name] = &vsList
	}

	jstr, err := ygot.EmitJSON(&vlanItems, &ygot.EmitJSONConfig{
		Format:        ygot.RFC7951,
		Indent:        "  ",
		RFC7951Config: &ygot.RFC7951JSONConfig{},
	})
	if err != nil {
		logger.GetLogger().Error("Failed to emit JSON for VLAN fwPolicyState", logfields.Error, err)
		return
	}

	if err := handler.Set(ctx, paths.FwPolicyStateVlan, jstr); err != nil {
		logger.GetLogger().Error("Failed to program VLAN fwPolicyState via gNMI", logfields.Error, err)
		return
	}

	logger.GetLogger().Debug("VLAN fwPolicyState programmed", "count", len(vlans))
}

// programEnforcement programs the BD-to-policy enforcement bindings.
// Each BD is bound to its DPU-specific (or shared) policy map.
func (s *vlanStore) programEnforcement(ctx context.Context, handler gnmi.GnmiHandler, vlans []types.VLAN) {
	bdItems := model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_BdItems{
		BDList: map[string]*model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_BdItems_BDList{},
	}

	for _, vlan := range vlans {
		id := vlan.Name
		pinned := vlan.DPUPinned
		if !s.isPinningActiveLocked() {
			pinned = 0
		}
		pol := dpuToPolicyName(pinned)
		bdList := model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_BdItems_BDList{
			Id:     &id,
			Policy: &pol,
		}
		bdItems.BDList[id] = &bdList
	}

	jstr, err := ygot.EmitJSON(&bdItems, &ygot.EmitJSONConfig{
		Format:        ygot.RFC7951,
		Indent:        "  ",
		RFC7951Config: &ygot.RFC7951JSONConfig{},
	})
	if err != nil {
		logger.GetLogger().Error("Failed to emit JSON for VLAN enforcement", logfields.Error, err)
		return
	}

	if err := handler.Set(ctx, paths.ServiceRedirBdItems, jstr); err != nil {
		logger.GetLogger().Error("Failed to program VLAN enforcement via gNMI", logfields.Error, err)
		return
	}

	logger.GetLogger().Debug("VLAN enforcement programmed", "count", len(vlans))
}

// cleanupRedirects performs targeted gNMI DELETE for all redirect components
// of a specific VLAN. Called when a VLAN is removed or becomes inactive.
func (s *vlanStore) cleanupRedirects(ctx context.Context, name string) {
	s.mu.RLock()
	handler := s.gnmiHandler
	s.mu.RUnlock()

	if handler == nil {
		return
	}

	s.deleteRedirectsWithHandler(ctx, handler, name)
}

// cleanupRedirectsLocked performs targeted gNMI DELETE for all redirect components
// of a specific VLAN. Must be called with at least a read lock held (or write lock).
func (s *vlanStore) cleanupRedirectsLocked(ctx context.Context, name string) {
	handler := s.gnmiHandler
	if handler == nil {
		return
	}
	s.deleteRedirectsWithHandler(ctx, handler, name)
}

// deleteRedirectsWithHandler issues gNMI DELETEs for all redirect components of a VLAN.
func (s *vlanStore) deleteRedirectsWithHandler(ctx context.Context, handler gnmi.GnmiHandler, name string) {
	// Delete BD enforcement binding
	path := fmt.Sprintf("%s/BD-list[id=%s]", paths.ServiceRedirBdItems, name)
	if err := handler.Delete(ctx, path); err != nil {
		logger.GetLogger().Warn("Failed to delete VLAN enforcement binding", "vlan", name, logfields.Error, err)
	}

	// Delete fwPolicyState entry
	path = fmt.Sprintf("%s/VlanState-list[vlanId=%s]/ext-items", paths.FwPolicyStateVlan, name)
	if err := handler.Delete(ctx, path); err != nil {
		logger.GetLogger().Warn("Failed to delete VLAN fwPolicyState", "vlan", name, logfields.Error, err)
	}

	logger.GetLogger().Debug("VLAN redirect cleanup completed", "vlan", name)
}

// policyNameToDPU extracts the DPU number from a policy name.
// "__dpu1_dpu_vlan_redir" → 1, "__dpu_all_dpu_vlan_redir" → allDpu
func policyNameToDPU(name string) uint16 {
	if strings.Contains(name, "_all_") {
		return allDpu
	}
	// Extract number after "__dpu"
	trimmed := strings.TrimPrefix(name, "__dpu")
	idx := strings.Index(trimmed, "_")
	if idx > 0 {
		if n, err := strconv.ParseUint(trimmed[:idx], 10, 16); err == nil {
			return uint16(n)
		}
	}
	return 0
}

// RestorePinningFromGnmi reads existing BD enforcement from the switch and
// performs selective cleanup of stale or repinned VLANs. Called during Setup()
// before ReconcileRedirects so we avoid unnecessary bulk DELETE of unchanged state.
func (s *vlanStore) RestorePinningFromGnmi(ctx context.Context) error {
	s.mu.RLock()
	handler := s.gnmiHandler
	s.mu.RUnlock()
	if handler == nil {
		return nil
	}

	jstrs, err := handler.Get(ctx, paths.ServiceRedirBdItems)
	if err != nil {
		return fmt.Errorf("failed to get bd-items: %w", err)
	}
	if len(jstrs) == 0 || len(jstrs[0]) == 0 {
		logger.GetLogger().Debug("No existing BD enforcement configuration found")
		return nil
	}

	items := &model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_BdItems{}
	opts := []ytypes.UnmarshalOpt{&ytypes.IgnoreExtraFields{}}
	if err := model.Unmarshal([]byte(jstrs[0]), items, opts...); err != nil {
		return fmt.Errorf("failed to unmarshal bd-items: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Build map of what's on the switch: vlanName → dpuPinned
	switchBDs := make(map[string]uint16)
	for id, bd := range items.BDList {
		if bd == nil || bd.Policy == nil {
			continue
		}
		switchBDs[id] = policyNameToDPU(*bd.Policy)
	}

	staleCount, repinCount := 0, 0
	for bdName, oldDPU := range switchBDs {
		vlan, exists := s.vlans[bdName]
		if !exists || !vlan.Active {
			// VLAN deleted — clean up BD enforcement
			logger.GetLogger().Warn("Cleaning up stale BD redirect", "vlan", bdName)
			s.cleanupRedirectsLocked(ctx, bdName)
			staleCount++
		} else if vlan.DPUPinned != oldDPU {
			// DPU pinning changed — delete enforcement (will be reprogrammed by ReconcileRedirects)
			logger.GetLogger().Info("BD DPU pinning changed, cleaning enforcement",
				"vlan", bdName, "oldDPU", oldDPU, "newDPU", vlan.DPUPinned)
			s.cleanupRedirectsLocked(ctx, bdName)
			repinCount++
		}
	}

	if staleCount > 0 || repinCount > 0 {
		logger.GetLogger().Info("Restored VLAN pinning from gNMI",
			"stale", staleCount, "repinned", repinCount)
	}
	return nil
}

// SetLbModePinning updates whether per-DPU pinning is active.
func (s *vlanStore) SetLbModePinning(active bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.isLbModePinning = active
}

// isPinningActiveLocked returns true when per-DPU pinning is active.
func (s *vlanStore) isPinningActiveLocked() bool {
	return s.isLbModePinning
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

// dpuToPolicyName converts a DPU number to the corresponding per-DPU VLAN policy map name.
// When dpu == 0, returns the "all DPUs" shared policy name.
func dpuToPolicyName(dpu uint16) string {
	switch dpu {
	case 1:
		return "__dpu1_dpu_vlan_redir"
	case 2:
		return "__dpu2_dpu_vlan_redir"
	case 3:
		return "__dpu3_dpu_vlan_redir"
	case 4:
		return "__dpu4_dpu_vlan_redir"
	default:
		return "__dpu_all_dpu_vlan_redir"
	}
}

// GetAll returns all VLANs for external use.
func (s *vlanStore) GetAll() map[string]types.VLAN {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make(map[string]types.VLAN, len(s.vlans))
	for k, v := range s.vlans {
		result[k] = v
	}
	return result
}

// SetGnmiHandler sets the gNMI handler for state synchronization.
// When set, service redirects are automatically programmed when VLANs change.
func (s *vlanStore) SetGnmiHandler(handler gnmi.GnmiHandler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gnmiHandler = handler
}

const (
	// allDpu is the special constant representing all DPUs.
	allDpu = 65535

	// seqNum is the default sequence number for redirect match entries.
	seqNum = 10
)

// ProgramBDServiceEndpoints creates per-DPU service endpoints for BD redirect.
// It creates one endpoint per DPU plus one "all" endpoint, each with
// Type=dpu_bridge (distinct from VRF's Type=dpu).
func (s *vlanStore) ProgramBDServiceEndpoints(ctx context.Context, dpuCount uint16) error {
	s.mu.RLock()
	handler := s.gnmiHandler
	s.mu.RUnlock()
	if handler == nil {
		return fmt.Errorf("gNMI handler not set")
	}

	serviceItems := model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_ServiceItems{
		ServiceList: map[string]*model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_ServiceItems_ServiceList{},
	}

	for dpu := uint16(1); dpu <= dpuCount+1; dpu++ {
		var pinned model.E_Cisco_NX_OSDevice_Sas_SvcModulePinning
		var name string

		if dpu <= dpuCount {
			pinned = dpuToModulePinning(dpu)
			name = dpuToPolicyName(dpu)
		} else {
			pinned = model.Cisco_NX_OSDevice_Sas_SvcModulePinning_all
			name = dpuToPolicyName(0)
		}

		svcEndPointDpuList := model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_ServiceItems_ServiceList_DpuepItems_SvcEndPointDpuList{
			DpuNum: pinned,
		}

		dpuepItems := model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_ServiceItems_ServiceList_DpuepItems{
			SvcEndPointDpuList: map[model.E_Cisco_NX_OSDevice_Sas_SvcModulePinning]*model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_ServiceItems_ServiceList_DpuepItems_SvcEndPointDpuList{
				pinned: &svcEndPointDpuList,
			},
		}

		serviceList := model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_ServiceItems_ServiceList{
			Name:       &name,
			Type:       model.Cisco_NX_OSDevice_Epbr_EpbrType_dpu_bridge,
			DpuepItems: &dpuepItems,
		}

		serviceItems.ServiceList[name] = &serviceList
	}

	jstr, err := ygot.EmitJSON(&serviceItems, &ygot.EmitJSONConfig{
		Format:        ygot.RFC7951,
		Indent:        "  ",
		RFC7951Config: &ygot.RFC7951JSONConfig{},
	})
	if err != nil {
		logger.GetLogger().Error("Failed to emit JSON for BD service endpoints", logfields.Error, err)
		return err
	}

	if err := handler.Set(ctx, paths.ServiceRedirServiceItems, jstr); err != nil {
		logger.GetLogger().Error("Failed to program BD service endpoints via gNMI", logfields.Error, err)
		return err
	}

	logger.GetLogger().Info("BD service endpoints programmed", "dpuCount", dpuCount)
	return nil
}

// ProgramBDPolicyMaps creates per-DPU policy maps for BD redirect.
// It creates one policy map per DPU plus one "all" policy map, each containing
// IPv4 and IPv6 redirect match entries.
func (s *vlanStore) ProgramBDPolicyMaps(ctx context.Context, dpuCount uint16) error {
	s.mu.RLock()
	handler := s.gnmiHandler
	s.mu.RUnlock()
	if handler == nil {
		return fmt.Errorf("gNMI handler not set")
	}

	pmapItems := model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_PmapItems{
		PolicyMapList: map[string]*model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_PmapItems_PolicyMapList{},
	}

	for dpu := uint16(1); dpu <= dpuCount+1; dpu++ {
		var name string
		if dpu <= dpuCount {
			name = dpuToPolicyName(dpu)
		} else {
			name = dpuToPolicyName(0)
		}

		pmapItems.PolicyMapList[name] = buildBDPolicyMap(name)
	}

	jstr, err := ygot.EmitJSON(&pmapItems, &ygot.EmitJSONConfig{
		Format:        ygot.RFC7951,
		Indent:        "  ",
		RFC7951Config: &ygot.RFC7951JSONConfig{},
	})
	if err != nil {
		logger.GetLogger().Error("Failed to emit JSON for BD policy maps", logfields.Error, err)
		return err
	}

	if err := handler.Set(ctx, paths.ServiceRedirPmapItems, jstr); err != nil {
		logger.GetLogger().Error("Failed to program BD policy maps via gNMI", logfields.Error, err)
		return err
	}

	logger.GetLogger().Info("BD policy maps programmed", "dpuCount", dpuCount)
	return nil
}

// CleanupBDServiceEndpoints removes per-DPU BD service endpoints via targeted
// gNMI DELETEs. Counterpart to ProgramBDServiceEndpoints.
func (s *vlanStore) CleanupBDServiceEndpoints(ctx context.Context, dpuCount uint16) {
	s.mu.RLock()
	handler := s.gnmiHandler
	s.mu.RUnlock()
	if handler == nil {
		return
	}

	for dpu := uint16(1); dpu <= dpuCount+1; dpu++ {
		var name string
		if dpu <= dpuCount {
			name = dpuToPolicyName(dpu)
		} else {
			name = dpuToPolicyName(0)
		}
		path := fmt.Sprintf("%s/Service-list[name=%s]", paths.ServiceRedirServiceItems, name)
		if err := handler.Delete(ctx, path); err != nil {
			logger.GetLogger().Warn("Failed to delete BD service endpoint", "name", name, logfields.Error, err)
		}
	}
	logger.GetLogger().Debug("BD service endpoints cleaned up", "dpuCount", dpuCount)
}

// CleanupBDPolicyMaps removes per-DPU BD policy maps via targeted gNMI DELETEs.
// Counterpart to ProgramBDPolicyMaps.
func (s *vlanStore) CleanupBDPolicyMaps(ctx context.Context, dpuCount uint16) {
	s.mu.RLock()
	handler := s.gnmiHandler
	s.mu.RUnlock()
	if handler == nil {
		return
	}

	for dpu := uint16(1); dpu <= dpuCount+1; dpu++ {
		var name string
		if dpu <= dpuCount {
			name = dpuToPolicyName(dpu)
		} else {
			name = dpuToPolicyName(0)
		}
		path := fmt.Sprintf("%s/PolicyMap-list[name=%s]", paths.ServiceRedirPmapItems, name)
		if err := handler.Delete(ctx, path); err != nil {
			logger.GetLogger().Warn("Failed to delete BD policy map", "name", name, logfields.Error, err)
		}
	}
	logger.GetLogger().Debug("BD policy maps cleaned up", "dpuCount", dpuCount)
}

// buildBDPolicyMap builds a policy map with the given name.
// The structure is identical to VRF policy maps: IPv4 + IPv6 redirect matches
// with failaction=drop and statistics enabled.
func buildBDPolicyMap(name string) *model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_PmapItems_PolicyMapList {
	sn := uint32(seqNum)

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

	aclNameV4 := paths.AclNameIPv4
	isIPv6V4 := false
	epbrMatchListV4 := model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_PmapItems_PolicyMapList_MatchItems_EpbrMatchList{
		AclType:       model.Cisco_NX_OSDevice_Epbr_IpType_ipv4,
		IsIPv6:        &isIPv6V4,
		Name:          &aclNameV4,
		TrafficAction: model.Cisco_NX_OSDevice_Epbr_TrafficActionType_redirect,
		SeqItems:      &seqItems,
	}

	aclNameV6 := paths.AclNameIPv6
	isIPv6V6 := true
	epbrMatchListV6 := model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_PmapItems_PolicyMapList_MatchItems_EpbrMatchList{
		AclType:       model.Cisco_NX_OSDevice_Epbr_IpType_ipv6,
		IsIPv6:        &isIPv6V6,
		Name:          &aclNameV6,
		TrafficAction: model.Cisco_NX_OSDevice_Epbr_TrafficActionType_redirect,
		SeqItems:      &seqItems,
	}

	matchItems := model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_PmapItems_PolicyMapList_MatchItems{
		EpbrMatchList: map[string]*model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_PmapItems_PolicyMapList_MatchItems_EpbrMatchList{
			aclNameV4: &epbrMatchListV4,
			aclNameV6: &epbrMatchListV6,
		},
	}

	stats := true
	policyMapList := model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_PmapItems_PolicyMapList{
		Name:       &name,
		Statistics: &stats,
		MatchItems: &matchItems,
	}

	return &policyMapList
}

// SetDPUCount updates the number of DPUs for hash-based dynamic pinning.
func (s *vlanStore) SetDPUCount(count uint16) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dpuCount = count
}

// assignPinningLocked sets DPUPinned based on lb mode and VLAN affinity.
//
// Symmetric hash mode (!isPinningActiveLocked):
//   - DPUPinned is always set to 65535 (all DPUs)
//   - Logs an error if affinity is non-zero (misconfiguration)
//
// Pinning mode (isPinningActiveLocked):
//   - Affinity 1..dpuCount → direct DPU assignment
//   - Affinity > dpuCount → invalid, log warning, fall back to FNV-1a
//   - Affinity 0 → FNV-1a hash to distribute across DPUs
//
// Must be called with write lock held.
func (s *vlanStore) assignPinningLocked(vlan types.VLAN) types.VLAN {
	if !s.isPinningActiveLocked() {
		// Symmetric hash mode: all VLANs use dpu_all redirect
		if vlan.Affinity != 0 {
			logger.GetLogger().Error("VLAN has non-zero affinity in symmetric hash mode",
				"vlan", vlan.Name, "affinity", vlan.Affinity)
		}
		vlan.DPUPinned = allDpu
		return vlan
	}
	// Pinning mode
	if vlan.Affinity >= 1 {
		if s.dpuCount > 0 && vlan.Affinity > s.dpuCount {
			logger.GetLogger().Warn("VLAN affinity exceeds DPU count, using FNV-1a",
				"vlan", vlan.Name, "affinity", vlan.Affinity, "dpuCount", s.dpuCount)
		} else {
			vlan.DPUPinned = vlan.Affinity
			return vlan
		}
	}
	// Affinity 0 or out-of-range fallback: FNV-1a hash
	if s.dpuCount > 0 {
		vlan.DPUPinned = 1 + uint16(fnv1a([]byte(vlan.Name))%uint64(s.dpuCount))
	} else {
		vlan.DPUPinned = 0
	}
	return vlan
}

// RepinAll re-evaluates DPU pinning for all active VLANs.
// Called when the load balancing mode changes so that existing VLANs
// pick up the new pinning mode (e.g. switching from symmetric hash
// to per-DPU pinning or vice versa).
//
// Data-layer updates (DPUPinned in memory + persist) happen unconditionally
// so pinning is correct when the device later goes in-service and
// ProgramAllRedirects is called. gNMI redirect programming is gated by
// inService inside programRedirects.
func (s *vlanStore) RepinAll(ctx context.Context) {
	s.mu.Lock()
	changed := false
	for name, vlan := range s.vlans {
		if !vlan.Active {
			continue
		}
		oldDPU := vlan.DPUPinned
		vlan = s.assignPinningLocked(vlan)
		if vlan.DPUPinned != oldDPU {
			s.vlans[name] = vlan
			changed = true
		}
	}
	s.mu.Unlock()

	if !changed {
		return
	}

	logger.GetLogger().Info("VLAN RepinAll: re-pinning active VLANs after LB mode change")
	s.persist(ctx)
	s.programRedirects(ctx)
}

// fnv1a computes an FNV-1a 64-bit hash. Used to distribute dynamic VLANs
// across DPUs deterministically.
func fnv1a(buf []byte) uint64 {
	h := fnv.New64a()
	h.Write(buf)
	return h.Sum64()
}

// SetInService controls the in-service gate for reactive redirect programming.
func (s *vlanStore) SetInService(inService bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.inService = inService
}

// ProgramAllRedirects programs redirects for all active VLANs.
// Used during in-service transition. Bypasses the inService gate.
func (s *vlanStore) ProgramAllRedirects(ctx context.Context) {
	s.mu.RLock()
	handler := s.gnmiHandler
	s.mu.RUnlock()
	if handler == nil {
		return
	}

	vlans := s.ListActive()
	if len(vlans) == 0 {
		return
	}

	s.programFwPolicyState(ctx, handler, vlans)
	s.programEnforcement(ctx, handler, vlans)
}

// CleanupAllRedirects removes redirects for all active VLANs.
// Used during out-of-service transition.
func (s *vlanStore) CleanupAllRedirects(ctx context.Context) {
	for _, v := range s.ListActive() {
		s.cleanupRedirects(ctx, v.Name)
	}
}

// ReconcileRedirects reprograms redirects for all active VLANs.
// Called during startup after shared infrastructure is in place.
// Stale cleanup is handled by RestorePinningFromGnmi before this is called.
// Unconditional — bypasses the inService gate.
func (s *vlanStore) ReconcileRedirects(ctx context.Context) {
	s.ProgramAllRedirects(ctx)
	logger.GetLogger().Info("VLAN redirects reconciled")
}

// CleanupAllFwPolicyState deletes fwPolicyState for all active VLANs (BDs).
// Called during Close() to clean up stale state on the switch.
func (s *vlanStore) CleanupAllFwPolicyState(ctx context.Context) {
	s.mu.RLock()
	handler := s.gnmiHandler
	s.mu.RUnlock()

	if handler == nil {
		return
	}

	if err := handler.Delete(ctx, paths.FwPolicyStateVlan); err != nil {
		logger.GetLogger().Warn("Failed to delete VLAN fwPolicyState", "error", err)
	}
}

// Ensure vlanStore implements Store interface
var _ Store = (*vlanStore)(nil)

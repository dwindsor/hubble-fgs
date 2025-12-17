// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package nxos

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/tetragon/pkg/logger"

	model "github.com/isovalent/hubble-fgs/pkg/nxosmodel"
	hav1 "github.com/isovalent/hubble-fgs/pkg/proto/ha/v1"

	"github.com/openconfig/ygot/ygot"
	"github.com/openconfig/ygot/ytypes"
)

const (
	allDpu = 65535
)

// provide HS controller status
func (n *Nxos) setControllerStatus(ctx context.Context, isAdmission bool, status model.E_Cisco_NX_OSDevice_Sas_CommonStateE, reason, version string) error {
	// System/sas-items/scontroller-items/ext-items
	var items model.Cisco_NX_OSDevice_System_SasItems_SvcItems_SvcinstItems_SvcInstanceList_ScontrollerItems_ExtItems
	if isAdmission {
		n.Ctrlr.AdmissionStatus = status
		n.Ctrlr.RejectReason = reason
		n.Ctrlr.Version = version
		items = model.Cisco_NX_OSDevice_System_SasItems_SvcItems_SvcinstItems_SvcInstanceList_ScontrollerItems_ExtItems{
			AdmissionStatus:  status,
			RejectReason:     &reason,
			Version:          &version,
			ConnectionStatus: n.Ctrlr.ConnectionStatus,
		}
	} else {
		n.Ctrlr.ConnectionStatus = status
		if status == model.Cisco_NX_OSDevice_Sas_CommonStateE_success {
			n.Agent.SystemState &^= SysStConnPending
		} else if status == model.Cisco_NX_OSDevice_Sas_CommonStateE_failure || status == model.Cisco_NX_OSDevice_Sas_CommonStateE_unknown {
			n.Agent.SystemState |= SysStConnPending
		}
		n.setSystemState(ctx)
		items = model.Cisco_NX_OSDevice_System_SasItems_SvcItems_SvcinstItems_SvcInstanceList_ScontrollerItems_ExtItems{
			AdmissionStatus:  n.Ctrlr.AdmissionStatus,
			RejectReason:     &n.Ctrlr.RejectReason,
			Version:          &n.Ctrlr.Version,
			ConnectionStatus: status,
		}
	}
	jstr, err := ygot.EmitJSON(&items, &ygot.EmitJSONConfig{
		Format:        ygot.RFC7951,
		Indent:        "  ",
		RFC7951Config: &ygot.RFC7951JSONConfig{},
	})
	if err != nil {
		logger.GetLogger().Error("Fail to emit json", logfields.Error, err)
		return err
	}

	err = n.gnmiSet(ctx, svcInst+"/scontroller-items/ext-items", jstr)
	if err != nil {
		logger.GetLogger().Error("", logfields.Error, err)
		return err
	}
	return nil
}

// provide firewall policy state, including VRF pinning
func (n *Nxos) setFwPolicyStateVrf(ctx context.Context, vrfs []VrfBd) error {
	logger.GetLogger().Debug("setFwPolicyStateVrf")

	domItems := model.Cisco_NX_OSDevice_System_SasItems_SvcItems_SvcinstItems_SvcInstanceList_FwpolicystateItems_IpvrfstateItems_DomItems{
		DomStateList: map[string]*model.Cisco_NX_OSDevice_System_SasItems_SvcItems_SvcinstItems_SvcInstanceList_FwpolicystateItems_IpvrfstateItems_DomItems_DomStateList{},
	}

	for _, vrf := range vrfs {
		reason := ""
		extItems := model.Cisco_NX_OSDevice_System_SasItems_SvcItems_SvcinstItems_SvcInstanceList_FwpolicystateItems_IpvrfstateItems_DomItems_DomStateList_ExtItems{
			PolicyStatus:       model.Cisco_NX_OSDevice_Sas_PolicyStatusE_success,
			PolicyStatusReason: &reason,
		}
		if n.IsLbModePinning(ctx) {
			extItems.Affinity = dpu2mod(ctx, vrf.DpuPinned)
		} else {
			extItems.Affinity = model.Cisco_NX_OSDevice_Sas_SvcModulePinning_all
		}

		name := vrf.Name
		dsList := model.Cisco_NX_OSDevice_System_SasItems_SvcItems_SvcinstItems_SvcInstanceList_FwpolicystateItems_IpvrfstateItems_DomItems_DomStateList{
			Name:     &name,
			ExtItems: &extItems,
		}
		domItems.DomStateList[vrf.Name] = &dsList
	}

	jstr, err := ygot.EmitJSON(&domItems, &ygot.EmitJSONConfig{
		Format:        ygot.RFC7951,
		Indent:        "  ",
		RFC7951Config: &ygot.RFC7951JSONConfig{},
	})
	if err != nil {
		logger.GetLogger().Error("Fail to emit json", logfields.Error, err)
		return err
	}

	path := fmt.Sprintf("%s/fwpolicystate-items/ipvrfstate-items/dom-items", svcInst)
	err = n.gnmiSet(ctx, path, jstr)
	if err != nil {
		logger.GetLogger().Error("", logfields.Error, err)
		return err
	}
	return nil
}

func (n *Nxos) setFwPolicyStateBd(ctx context.Context, bds []VrfBd) error {
	logger.GetLogger().Debug("setFwPolicyStateBd")

	vlanItems := model.Cisco_NX_OSDevice_System_SasItems_SvcItems_SvcinstItems_SvcInstanceList_FwpolicystateItems_BdstateItems_VlanItems{
		VlanStateList: map[string]*model.Cisco_NX_OSDevice_System_SasItems_SvcItems_SvcinstItems_SvcInstanceList_FwpolicystateItems_BdstateItems_VlanItems_VlanStateList{},
	}

	for _, bd := range bds {
		reason := ""
		extItems := model.Cisco_NX_OSDevice_System_SasItems_SvcItems_SvcinstItems_SvcInstanceList_FwpolicystateItems_BdstateItems_VlanItems_VlanStateList_ExtItems{
			PolicyStatus:       model.Cisco_NX_OSDevice_Sas_PolicyStatusE_success,
			PolicyStatusReason: &reason,
		}
		if n.IsLbModePinning(ctx) {
			extItems.Affinity = dpu2mod(ctx, bd.DpuPinned)
		} else {
			extItems.Affinity = model.Cisco_NX_OSDevice_Sas_SvcModulePinning_all
		}

		name := bd.Name
		vsList := model.Cisco_NX_OSDevice_System_SasItems_SvcItems_SvcinstItems_SvcInstanceList_FwpolicystateItems_BdstateItems_VlanItems_VlanStateList{
			VlanId:   &name,
			ExtItems: &extItems,
		}
		vlanItems.VlanStateList[bd.Name] = &vsList
	}

	jstr, err := ygot.EmitJSON(&vlanItems, &ygot.EmitJSONConfig{
		Format:        ygot.RFC7951,
		Indent:        "  ",
		RFC7951Config: &ygot.RFC7951JSONConfig{},
	})
	if err != nil {
		logger.GetLogger().Error("Fail to emit json", logfields.Error, err)
		return err
	}

	path := fmt.Sprintf("%s/fwpolicystate-items/bdstate-items/vlan-items", svcInst)
	err = n.gnmiSet(ctx, path, jstr)
	if err != nil {
		logger.GetLogger().Error("", logfields.Error, err)
		return err
	}
	return nil
}

func (n *Nxos) setFwPolicyState(ctx context.Context, isBd bool, vbs []VrfBd) error {
	logger.GetLogger().Debug("setFwPolicyState", "isBd", isBd, "vbs", vbs)

	vbs2 := []VrfBd{}
	for _, vb := range vbs {
		if !vb.IsGlobal || !vb.IsService {
			logger.GetLogger().Debug("Skip VRF/BD", "name", vb.Name)
			continue
		}
		vbs2 = append(vbs2, vb)
	}
	if len(vbs2) == 0 {
		logger.GetLogger().Debug("setFwPolicyState: No VRF/BD to program")
		return nil
	}
	logger.GetLogger().Debug("setFwPolicyState for VRFs/BDs", "name", vbs2)
	var err error
	if isBd {
		err = n.setFwPolicyStateBd(ctx, vbs2)
	} else {
		err = n.setFwPolicyStateVrf(ctx, vbs2)
	}
	if err != nil {
		logger.GetLogger().Error("Fail to set fw policy state", logfields.Error, err)
	}
	return err
}

func (n *Nxos) delFwPolicyState(ctx context.Context, isBd bool, name string) error {
	logger.GetLogger().Debug("delFwPolicyState", "isBd", isBd, "name", name)

	var path string
	if isBd {
		path = fmt.Sprintf("%s/fwpolicystate-items/bdstate-items/vlan-items/VlanState-list[vlanId=%s]/ext-items",
			svcInst, name)
	} else {
		path = fmt.Sprintf("%s/fwpolicystate-items/ipvrfstate-items/dom-items/DomState-list[name=%s]/ext-items",
			svcInst, name)
	}
	err := n.gnmiDel(ctx, path)
	if err != nil {
		logger.GetLogger().Error("", logfields.Error, err)
		return err
	}
	return nil
}

// clear the way to forward to DPU
func (n *Nxos) setSystemState(ctx context.Context) error {

	var state string
	if n.Agent.SystemState == SysStDpuPending {
		state = "0x1"
	} else if n.Agent.SystemState == SysStConnPending {
		state = "0x2"
	} else if n.Agent.SystemState == (SysStDpuPending | SysStConnPending) {
		state = "0x3"
	} else if n.Agent.SystemState == SysStDpuReady {
		state = "0x4"
	} else if n.Agent.SystemState == (SysStDpuReady | SysStConnPending) {
		state = "0x6"
	} else if n.Agent.SystemState == (SysStDpuReady | SysStRedirDone) {
		state = "0xC"
	} else if n.Agent.SystemState == (SysStDpuReady | SysStRedirDone | SysStConnPending) {
		state = "0xE"
	} else {
		logger.GetLogger().Error("Unexpected systemState", "state", n.Agent.SystemState)
		err := errors.New("Unexpected systemState")
		return err
	}
	logger.GetLogger().Debug("SetSystemState", "newState", state)

	var items model.Cisco_NX_OSDevice_System_SasItems_SvcItems_SvcinstItems_SvcInstanceList_SagentItems_ExtItems
	items.SystemState = &state
	jstr, err := ygot.EmitJSON(&items, &ygot.EmitJSONConfig{
		Format:        ygot.RFC7951,
		Indent:        "  ",
		RFC7951Config: &ygot.RFC7951JSONConfig{},
	})
	if err != nil {
		logger.GetLogger().Error("Fail to emit json", logfields.Error, err)
		return err
	}
	path := svcInst + "/sagent-items/ext-items"
	err = n.gnmiSet(ctx, path, jstr)
	if err != nil {
		logger.GetLogger().Error("", logfields.Error, err)
		return err
	}
	return nil
}

// notify DPU issue via asicState
//func (n *Nxos) setDpuState(ctx context.Context, dpu uint16, state model.E_Cisco_NX_OSDevice_Sas_DpuAsicStateE) error {
//	var items model.Cisco_NX_OSDevice_System_SasItems_DpuItems_InstItems_InstList_ExtItems
//	items.AsicState = state
//
//	jstr, err := ygot.EmitJSON(&items, &ygot.EmitJSONConfig{
//		Format:        ygot.RFC7951,
//		Indent:        "  ",
//		RFC7951Config: &ygot.RFC7951JSONConfig{},
//	})
//	if err != nil {
//		logger.GetLogger().Error("Fail to emit json", logfields.Error, err)
//		return err
//	}
//
//	path := fmt.Sprintf("/System/sas-items/dpu-items/inst-items[moduleNum=%d]/ext-items", dpu)
//	err = n.gnmiSet(ctx, path, jstr)
//	if err != nil {
//		logger.GetLogger().Error("", logfields.Error, err)
//		return err
//	}
//	return nil
//}

func (n *Nxos) setDpuPortRange(ctx context.Context, dpu uint16) error {
	logger.GetLogger().Debug("setDpuPortRange:", "dpu", dpu)

	var items model.Cisco_NX_OSDevice_System_SasItems_DpuItems_InstItems_InstList_ExtItems
	portRange := n.calcDpuPortRange(dpu)
	logger.GetLogger().Debug("portRange", "ports", portRange)
	items.TcpCpPortRange = &portRange
	items.UdpCpPortRange = &portRange

	jstr, err := ygot.EmitJSON(&items, &ygot.EmitJSONConfig{
		Format:        ygot.RFC7951,
		Indent:        "  ",
		RFC7951Config: &ygot.RFC7951JSONConfig{},
	})
	if err != nil {
		logger.GetLogger().Error("Fail to emit json", logfields.Error, err)
		return err
	}

	path := fmt.Sprintf("System/sas-items/dpu-items/inst-items/Inst-list[moduleNum=%d]/ext-items", dpu)
	err = n.gnmiSet(ctx, path, jstr)
	if err != nil {
		logger.GetLogger().Error("", logfields.Error, err)
		return err
	}
	return nil
}

func (n *Nxos) delDpuPortRange(ctx context.Context) error {
	logger.GetLogger().Debug("delDpuPortRange")

	for i := 1; i <= int(n.NumDpu); i++ {
		// delete ep
		path := fmt.Sprintf("System/sas-items/dpu-items/inst-items/Inst-list[moduleNum=%d]/ext-items", i)
		logger.GetLogger().Debug("delete path", "path", path)
		err := n.gnmiDel(ctx, path)
		if err != nil {
			logger.GetLogger().Error("", logfields.Error, err)
			return err
		}
	}
	return nil
}

func (n *Nxos) setAccessList(ctx context.Context) error {

	ipv4AddrAny := "0.0.0.0"
	proto := uint8(0)
	sn := uint32(seqNum)
	aceIpv4 := model.Cisco_NX_OSDevice_System_AclItems_Ipv4Items_NameItems_ACLList_SeqItems_ACEList{
		Action:    model.Cisco_NX_OSDevice_Acl_ActionType_permit,
		DstPrefix: &ipv4AddrAny,
		Protocol:  &proto,
		SeqNum:    &sn,
		SrcPrefix: &ipv4AddrAny,
	}
	jstr, err := ygot.EmitJSON(&aceIpv4, &ygot.EmitJSONConfig{
		Format:        ygot.RFC7951,
		Indent:        "  ",
		RFC7951Config: &ygot.RFC7951JSONConfig{},
	})
	if err != nil {
		logger.GetLogger().Error("Fail to emit json", logfields.Error, err)
		return err
	}

	name := "__dpu_redir"
	path := fmt.Sprintf("/System/acl-items/ipv4-items/name-items/ACL-list[name=%s]/seq-items/ACE-list[seqNum=%d]",
		name, seqNum)
	err = n.gnmiSet(ctx, path, jstr)
	if err != nil {
		logger.GetLogger().Error("", logfields.Error, err)
		return err
	}

	// remove for eft. revisit later
	/*
		ipv4McastAny := "224.0.0.0"
		ipv4PrefixLen := uint8(4)
		aceIpv4Exc := model.Cisco_NX_OSDevice_System_AclItems_Ipv4Items_NameItems_ACLList_SeqItems_ACEList{
			Action:          model.Cisco_NX_OSDevice_Acl_ActionType_permit,
			DstPrefix:       &ipv4McastAny,
			DstPrefixLength: &ipv4PrefixLen,
			Protocol:        &proto,
			SeqNum:          &sn,
			SrcPrefix:       &ipv4AddrAny,
			SrcPrefixMask:   &ipv4AddrAny,
		}
		jstr, err = ygot.EmitJSON(&aceIpv4Exc, &ygot.EmitJSONConfig{
			Format:        ygot.RFC7951,
			Indent:        "  ",
			RFC7951Config: &ygot.RFC7951JSONConfig{},
		})
		if err != nil {
			logger.GetLogger().Error("Fail to emit json")
			return err
		}

		name = "__dpu_exclude"
		path = fmt.Sprintf("/System/acl-items/ipv4-items/name-items/ACL-list[name=%s]/seq-items/ACE-list[seqNum=%d]",
			name, seqNum)
		err = n.gnmiSet(ctx, path, jstr)
		if err != nil {
			logger.GetLogger().Error("", logfields.Error, err)
			return err
		}
	*/

	ipv6AddrAny := "0::0"
	aceIpv6 := model.Cisco_NX_OSDevice_System_AclItems_Ipv6Items_NameItems_ACLList_SeqItems_ACEList{
		Action:    model.Cisco_NX_OSDevice_Acl_ActionType_permit,
		DstPrefix: &ipv6AddrAny,
		Protocol:  &proto,
		SeqNum:    &sn,
		SrcPrefix: &ipv6AddrAny,
	}
	jstr, err = ygot.EmitJSON(&aceIpv6, &ygot.EmitJSONConfig{
		Format:        ygot.RFC7951,
		Indent:        "  ",
		RFC7951Config: &ygot.RFC7951JSONConfig{},
	})
	if err != nil {
		logger.GetLogger().Error("Fail to emit json", logfields.Error, err)
		return err
	}

	name = "__dpu_ipv6_redir"
	path = fmt.Sprintf("/System/acl-items/ipv6-items/name-items/ACL-list[name=%s]/seq-items/ACE-list[seqNum=%d]",
		name, seqNum)
	err = n.gnmiSet(ctx, path, jstr)
	if err != nil {
		logger.GetLogger().Error("", logfields.Error, err)
		return err
	}

	// remove for eft. reconsider later
	/*
		ipv6McastAny := "ff00::"
		ipv6DstPrefixLen := uint8(8)
		ipv6SrcPrefixLen := uint8(0)
		aceIpv6Exc := model.Cisco_NX_OSDevice_System_AclItems_Ipv6Items_NameItems_ACLList_SeqItems_ACEList{
			Action:          model.Cisco_NX_OSDevice_Acl_ActionType_permit,
			DstPrefix:       &ipv6McastAny,
			DstPrefixLength: &ipv6DstPrefixLen,
			Protocol:        &proto,
			SeqNum:          &sn,
			SrcPrefix:       &ipv6AddrAny,
			SrcPrefixLength: &ipv6SrcPrefixLen,
		}
		jstr, err = ygot.EmitJSON(&aceIpv6Exc, &ygot.EmitJSONConfig{
			Format:        ygot.RFC7951,
			Indent:        "  ",
			RFC7951Config: &ygot.RFC7951JSONConfig{},
		})
		if err != nil {
			logger.GetLogger().Error("Fail to emit json")
			return err
		}

		name = "__dpu_ipv6_exclude"
		path = fmt.Sprintf("/System/acl-items/ipv6-items/name-items/ACL-list[name=%s]/seq-items/ACE-list[seqNum=%d]",
			name, seqNum)
		err = n.gnmiSet(ctx, path, jstr)
		if err != nil {
			logger.GetLogger().Error("", logfields.Error, err)
			return err
		}
	*/

	return nil
}

func (n *Nxos) setDpuEndpointVrf(ctx context.Context, vrfs []VrfBd) error {
	logger.GetLogger().Debug("setDpuEndpointVrf: vrfs", "vrf", vrfs)

	serviceItems := model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_ServiceItems{
		ServiceList: map[string]*model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_ServiceItems_ServiceList{},
	}

	for _, vrf := range vrfs {
		gid, ok := n.Alloc.Gids[vrf.Name]
		if !ok {
			err := errors.New("Global id not allocated for VRF " + vrf.Name)
			logger.GetLogger().Error("", logfields.Error, err)
			return err
		}

		svcEndPointDpuList := model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_ServiceItems_ServiceList_DpuepItems_SvcEndPointDpuList{
			Vlan: &gid,
		}
		if n.IsLbModePinning(ctx) {
			svcEndPointDpuList.DpuNum = dpu2mod(ctx, vrf.DpuPinned)
		} else {
			svcEndPointDpuList.DpuNum = model.Cisco_NX_OSDevice_Sas_SvcModulePinning_all
		}

		dpuepItems := model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_ServiceItems_ServiceList_DpuepItems{
			SvcEndPointDpuList: map[model.E_Cisco_NX_OSDevice_Sas_SvcModulePinning]*model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_ServiceItems_ServiceList_DpuepItems_SvcEndPointDpuList{},
		}

		var pinned model.E_Cisco_NX_OSDevice_Sas_SvcModulePinning
		if n.IsLbModePinning(ctx) {
			pinned = dpu2mod(ctx, vrf.DpuPinned)
		} else {
			pinned = model.Cisco_NX_OSDevice_Sas_SvcModulePinning_all
		}
		dpuepItems.SvcEndPointDpuList[pinned] = &svcEndPointDpuList

		name := fmt.Sprintf("__%s_dpu_redir", vrf.Name)
		serviceList := model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_ServiceItems_ServiceList{
			Name:       &name,
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
		logger.GetLogger().Error("Fail to emit json", logfields.Error, err)
		return err
	}

	path := "/System/serviceredir-items/inst-items/service-items"
	err = n.gnmiSet(ctx, path, jstr)
	if err != nil {
		logger.GetLogger().Error("", logfields.Error, err)
		return err
	}
	return nil
}

func (n *Nxos) delDpuEndpointVrf(ctx context.Context, vrf string) error {
	logger.GetLogger().Debug("delDpuEndpointVrf:", "name", vrf)

	// delete ep
	path := fmt.Sprintf("/System/serviceredir-items/inst-items/service-items/Service-list[name=__%s_dpu_redir]/dpuep-items", vrf)
	err := n.gnmiDel(ctx, path)
	if err != nil {
		logger.GetLogger().Error("", logfields.Error, err)
		return err
	}

	return nil
}

func (n *Nxos) setServiceEndpointVrf(ctx context.Context, vrfs []VrfBd) error {
	logger.GetLogger().Debug("setServiceEndpointVrf", "vrfs", vrfs)

	serviceItems := model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_ServiceItems{
		ServiceList: map[string]*model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_ServiceItems_ServiceList{},
	}

	for _, vrf := range vrfs {
		gid, ok := n.Alloc.Gids[vrf.Name]
		if !ok {
			err := errors.New("Global id not allocated for VRF " + vrf.Name)
			logger.GetLogger().Error("", logfields.Error, err)
			return err
		}

		svcEndPointDpuList := model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_ServiceItems_ServiceList_DpuepItems_SvcEndPointDpuList{
			Vlan: &gid,
		}
		if n.IsLbModePinning(ctx) {
			svcEndPointDpuList.DpuNum = dpu2mod(ctx, vrf.DpuPinned)
		} else {
			svcEndPointDpuList.DpuNum = model.Cisco_NX_OSDevice_Sas_SvcModulePinning_all
		}

		dpuepItems := model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_ServiceItems_ServiceList_DpuepItems{
			SvcEndPointDpuList: map[model.E_Cisco_NX_OSDevice_Sas_SvcModulePinning]*model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_ServiceItems_ServiceList_DpuepItems_SvcEndPointDpuList{},
		}
		var pinned model.E_Cisco_NX_OSDevice_Sas_SvcModulePinning
		if n.IsLbModePinning(ctx) {
			pinned = dpu2mod(ctx, vrf.DpuPinned)
		} else {
			pinned = model.Cisco_NX_OSDevice_Sas_SvcModulePinning_all
		}
		dpuepItems.SvcEndPointDpuList[pinned] = &svcEndPointDpuList

		name := fmt.Sprintf("__%s_dpu_redir", vrf.Name)
		serviceList := model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_ServiceItems_ServiceList{
			Name:       &name,
			Type:       model.Cisco_NX_OSDevice_Epbr_EpbrType_dpu,
			Vrf:        &vrf.Name,
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
		logger.GetLogger().Error("Fail to emit json", logfields.Error, err)
		return err
	}

	path := "/System/serviceredir-items/inst-items/service-items"
	err = n.gnmiSet(ctx, path, jstr)
	if err != nil {
		logger.GetLogger().Error("", logfields.Error, err)
		return err
	}
	return nil
}

func (n *Nxos) setServiceEndpointBd(ctx context.Context) error {
	logger.GetLogger().Debug("setServiceEndpointBd")

	serviceItems := model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_ServiceItems{
		ServiceList: map[string]*model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_ServiceItems_ServiceList{},
	}

	for dpu := 1; dpu < int(n.NumDpu+2); dpu++ {
		svcEndPointDpuList := model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_ServiceItems_ServiceList_DpuepItems_SvcEndPointDpuList{}
		var pinned model.E_Cisco_NX_OSDevice_Sas_SvcModulePinning
		var name string

		if dpu < int(n.NumDpu+1) {
			svcEndPointDpuList.DpuNum = dpu2mod(ctx, uint16(dpu))
			name = dpu2name(ctx, uint16(dpu))
			pinned = dpu2mod(ctx, uint16(dpu))
		} else {
			svcEndPointDpuList.DpuNum = model.Cisco_NX_OSDevice_Sas_SvcModulePinning_all
			name = dpu2name(ctx, allDpu)
			pinned = model.Cisco_NX_OSDevice_Sas_SvcModulePinning_all
		}

		dpuepItems := model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_ServiceItems_ServiceList_DpuepItems{
			SvcEndPointDpuList: map[model.E_Cisco_NX_OSDevice_Sas_SvcModulePinning]*model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_ServiceItems_ServiceList_DpuepItems_SvcEndPointDpuList{},
		}
		dpuepItems.SvcEndPointDpuList[pinned] = &svcEndPointDpuList

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
		logger.GetLogger().Error("Fail to emit json", logfields.Error, err)
		return err
	}

	path := "/System/serviceredir-items/inst-items/service-items"
	err = n.gnmiSet(ctx, path, jstr)
	if err != nil {
		logger.GetLogger().Error("", logfields.Error, err)
		return err
	}
	return nil
}

func (n *Nxos) setPolicyMapVrf(ctx context.Context, vrfs []VrfBd) error {
	logger.GetLogger().Debug("setPolicyMapVrf", "vrfs", vrfs)

	pmapItems := model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_PmapItems{
		PolicyMapList: map[string]*model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_PmapItems_PolicyMapList{},
	}

	for _, vrf := range vrfs {
		name := fmt.Sprintf("__%s_dpu_redir", vrf.Name)
		sn := uint32(seqNum)
		epbrMatchSeqList := model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_PmapItems_PolicyMapList_MatchItems_EpbrMatchList_SeqItems_EpbrMatchSeqList{

			Failaction: model.Cisco_NX_OSDevice_Epbr_FailactionType_drop,
			Name:       &name,
			Seqno:      &sn,
		}

		seqItems := model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_PmapItems_PolicyMapList_MatchItems_EpbrMatchList_SeqItems{
			EpbrMatchSeqList: map[uint32]*model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_PmapItems_PolicyMapList_MatchItems_EpbrMatchList_SeqItems_EpbrMatchSeqList{},
		}
		seqItems.EpbrMatchSeqList[sn] = &epbrMatchSeqList

		aclName_v4 := "__dpu_redir"
		isIPv6_v4 := false
		epbrMatchList_v4 := model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_PmapItems_PolicyMapList_MatchItems_EpbrMatchList{
			AclType:       model.Cisco_NX_OSDevice_Epbr_IpType_ipv4,
			IsIPv6:        &isIPv6_v4,
			Name:          &aclName_v4,
			TrafficAction: model.Cisco_NX_OSDevice_Epbr_TrafficActionType_redirect,
			SeqItems:      &seqItems,
		}

		/*
			aclNameEx_v4 := "__dpu_exclude"
			epbrMatchEx_v4 := model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_PmapItems_PolicyMapList_MatchItems_EpbrMatchList{
				AclType:       model.Cisco_NX_OSDevice_Epbr_IpType_ipv4,
				IsIPv6:        &isIPv6_v4,
				Name:          &aclNameEx_v4,
				TrafficAction: model.Cisco_NX_OSDevice_Epbr_TrafficActionType_exclude,
			}
		*/

		aclName_v6 := "__dpu_ipv6_redir"
		isIPv6_v6 := true
		epbrMatchList_v6 := model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_PmapItems_PolicyMapList_MatchItems_EpbrMatchList{
			AclType:       model.Cisco_NX_OSDevice_Epbr_IpType_ipv6,
			IsIPv6:        &isIPv6_v6,
			Name:          &aclName_v6,
			TrafficAction: model.Cisco_NX_OSDevice_Epbr_TrafficActionType_redirect,
			SeqItems:      &seqItems,
		}

		/*
			aclNameEx_v6 := "__dpu_ipv6_exclude"
			epbrMatchEx_v6 := model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_PmapItems_PolicyMapList_MatchItems_EpbrMatchList{
				AclType:       model.Cisco_NX_OSDevice_Epbr_IpType_ipv6,
				IsIPv6:        &isIPv6_v6,
				Name:          &aclNameEx_v6,
				TrafficAction: model.Cisco_NX_OSDevice_Epbr_TrafficActionType_exclude,
			}
		*/

		matchItems := model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_PmapItems_PolicyMapList_MatchItems{
			EpbrMatchList: map[string]*model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_PmapItems_PolicyMapList_MatchItems_EpbrMatchList{},
		}
		matchItems.EpbrMatchList[aclName_v4] = &epbrMatchList_v4
		// match.EpbrMatchList[aclNameEx_v4] = &epbrMatchEx_v4
		matchItems.EpbrMatchList[aclName_v6] = &epbrMatchList_v6
		// match.EpbrMatchList[aclNameEx_v6] = &epbrMatchEx_v6

		stats := true
		policyMapList := model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_PmapItems_PolicyMapList{
			Name:       &name,
			Statistics: &stats,
			MatchItems: &matchItems,
		}

		pmapItems.PolicyMapList[name] = &policyMapList
	}

	jstr, err := ygot.EmitJSON(&pmapItems, &ygot.EmitJSONConfig{
		Format:        ygot.RFC7951,
		Indent:        "  ",
		RFC7951Config: &ygot.RFC7951JSONConfig{},
	})
	if err != nil {
		logger.GetLogger().Error("Fail to emit json", logfields.Error, err)
		return err
	}

	path := "/System/serviceredir-items/inst-items/pmap-items"
	err = n.gnmiSet(ctx, path, jstr)
	if err != nil {
		logger.GetLogger().Error("", logfields.Error, err)
		return err
	}
	return nil
}

func (n *Nxos) setPolicyMapBd(ctx context.Context) error {
	logger.GetLogger().Debug("setPolicyMapBd")

	pmapItems := model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_PmapItems{
		PolicyMapList: map[string]*model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_PmapItems_PolicyMapList{},
	}

	for dpu := 1; dpu < int(n.NumDpu+2); dpu++ {
		var name string
		if dpu < int(n.NumDpu+1) {
			name = dpu2name(ctx, uint16(dpu))
		} else {
			name = dpu2name(ctx, allDpu)
		}

		sn := uint32(seqNum)
		epbrMatchSeqList := model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_PmapItems_PolicyMapList_MatchItems_EpbrMatchList_SeqItems_EpbrMatchSeqList{

			Failaction: model.Cisco_NX_OSDevice_Epbr_FailactionType_drop,
			Name:       &name,
			Seqno:      &sn,
		}

		seqItems := model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_PmapItems_PolicyMapList_MatchItems_EpbrMatchList_SeqItems{
			EpbrMatchSeqList: map[uint32]*model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_PmapItems_PolicyMapList_MatchItems_EpbrMatchList_SeqItems_EpbrMatchSeqList{},
		}
		seqItems.EpbrMatchSeqList[sn] = &epbrMatchSeqList

		aclName_v4 := "__dpu_redir"
		isIPv6_v4 := false
		epbrMatchList_v4 := model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_PmapItems_PolicyMapList_MatchItems_EpbrMatchList{
			AclType:       model.Cisco_NX_OSDevice_Epbr_IpType_ipv4,
			IsIPv6:        &isIPv6_v4,
			Name:          &aclName_v4,
			TrafficAction: model.Cisco_NX_OSDevice_Epbr_TrafficActionType_redirect,
			SeqItems:      &seqItems,
		}

		aclName_v6 := "__dpu_ipv6_redir"
		isIPv6_v6 := true
		epbrMatchList_v6 := model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_PmapItems_PolicyMapList_MatchItems_EpbrMatchList{
			AclType:       model.Cisco_NX_OSDevice_Epbr_IpType_ipv6,
			IsIPv6:        &isIPv6_v6,
			Name:          &aclName_v6,
			TrafficAction: model.Cisco_NX_OSDevice_Epbr_TrafficActionType_redirect,
			SeqItems:      &seqItems,
		}

		matchItems := model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_PmapItems_PolicyMapList_MatchItems{
			EpbrMatchList: map[string]*model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_PmapItems_PolicyMapList_MatchItems_EpbrMatchList{},
		}
		matchItems.EpbrMatchList[aclName_v4] = &epbrMatchList_v4
		matchItems.EpbrMatchList[aclName_v6] = &epbrMatchList_v6

		stats := true
		policyMapList := model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_PmapItems_PolicyMapList{
			Name:       &name,
			Statistics: &stats,
			MatchItems: &matchItems,
		}

		pmapItems.PolicyMapList[name] = &policyMapList
	}

	jstr, err := ygot.EmitJSON(&pmapItems, &ygot.EmitJSONConfig{
		Format:        ygot.RFC7951,
		Indent:        "  ",
		RFC7951Config: &ygot.RFC7951JSONConfig{},
	})
	if err != nil {
		logger.GetLogger().Error("Fail to emit json", logfields.Error, err)
		return err
	}

	path := "/System/serviceredir-items/inst-items/pmap-items"
	err = n.gnmiSet(ctx, path, jstr)
	if err != nil {
		logger.GetLogger().Error("", logfields.Error, err)
		return err
	}
	return nil
}

func (n *Nxos) setPolicyEnfVrf(ctx context.Context, vrfs []VrfBd) error {
	logger.GetLogger().Debug("setPolicyEnfVrf", "vrfs", vrfs)

	domItems := model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_DomItems{
		DomList: map[string]*model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_DomItems_DomList{},
	}

	for _, vrf := range vrfs {
		name := vrf.Name
		policy := fmt.Sprintf("__%s_dpu_redir", name)
		domList := model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_DomItems_DomList{
			Name:   &name,
			Policy: &policy,
		}

		domItems.DomList[name] = &domList
	}

	jstr, err := ygot.EmitJSON(&domItems, &ygot.EmitJSONConfig{
		Format:        ygot.RFC7951,
		Indent:        "  ",
		RFC7951Config: &ygot.RFC7951JSONConfig{},
	})
	if err != nil {
		logger.GetLogger().Error("Fail to emit json", logfields.Error, err)
		return err
	}

	path := "/System/serviceredir-items/inst-items/dom-items"
	err = n.gnmiSet(ctx, path, jstr)
	if err != nil {
		logger.GetLogger().Error("", logfields.Error, err)
		return err
	}
	return nil
}

func (n *Nxos) setPolicyEnfBd(ctx context.Context, bds []VrfBd) error {
	logger.GetLogger().Debug("setPolicyEnfBd", "bds", bds)

	bdItems := model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_BdItems{
		BDList: map[string]*model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_BdItems_BDList{},
	}

	for _, bd := range bds {
		id := bd.Name
		var pol string
		if n.IsLbModePinning(ctx) {
			pol = dpu2name(ctx, bd.DpuPinned)
		} else {
			pol = dpu2name(ctx, allDpu)
		}

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
		logger.GetLogger().Error("Fail to emit json", logfields.Error, err)
		return err
	}

	path := "/System/serviceredir-items/inst-items/bd-items"
	err = n.gnmiSet(ctx, path, jstr)
	if err != nil {
		logger.GetLogger().Error("", logfields.Error, err)
		return err
	}
	return nil
}

func (n *Nxos) setPolicyEnf(ctx context.Context, isBd bool, vbs []VrfBd) error {
	logger.GetLogger().Debug("setPolicyEnf", "isBd", isBd, "vbs", vbs)

	if isBd {
		return n.setPolicyEnfBd(ctx, vbs)
	}
	return n.setPolicyEnfVrf(ctx, vbs)
}

func (n *Nxos) delPolicyEnfBd(ctx context.Context, name string) error {
	logger.GetLogger().Debug("delPolicyEnfBd", "name", name)

	path := fmt.Sprintf("/System/serviceredir-items/inst-items/bd-items/BD-list[id=%s]", name)
	err := n.gnmiDel(ctx, path)
	if err != nil {
		logger.GetLogger().Error("", logfields.Error, err)
		return err
	}

	return nil
}

func (n *Nxos) setServiceRedir(ctx context.Context, isBd bool, vbs []VrfBd) error {
	logger.GetLogger().Debug("setServiceRedir", "isBd", isBd, "vbs", vbs)

	var vbs2 []VrfBd
	for _, vb := range vbs {
		if !vb.IsGlobal || !vb.IsService {
			logger.GetLogger().Debug("Skip VRF/BD", "name", vb.Name)
			continue
		}
		vbs2 = append(vbs2, vb)
	}
	if len(vbs2) == 0 {
		logger.GetLogger().Debug("setServiceRedir: no VRFs/BDs to program")
		return nil
	}
	logger.GetLogger().Debug("setServiceRedir", "vbs2", vbs2)

	if !isBd {
		err := n.setServiceEndpointVrf(ctx, vbs2)
		if err != nil {
			logger.GetLogger().Error("", logfields.Error, err)
		}
		err = n.setPolicyMapVrf(ctx, vbs2)
		if err != nil {
			logger.GetLogger().Error("", logfields.Error, err)
		}
	}
	err := n.setPolicyEnf(ctx, isBd, vbs2)
	if err != nil {
		logger.GetLogger().Error("", logfields.Error, err)
	}
	return nil
}

func (n *Nxos) delServiceRedir(ctx context.Context, isBd bool, name string) error {
	logger.GetLogger().Debug("delServiceRedir", "isBd", isBd, "name", name)

	// delete enforce
	var path string
	if isBd {
		path = fmt.Sprintf("/System/serviceredir-items/inst-items/bd-items/BD-list[id=%s]", name)
	} else {
		path = fmt.Sprintf("/System/serviceredir-items/inst-items/dom-items/Dom-list[name=%s]", name)
	}
	err := n.gnmiDel(ctx, path)
	if err != nil {
		logger.GetLogger().Error("", logfields.Error, err)
		return err
	}

	if !isBd {
		// delete pmap
		path = fmt.Sprintf("/System/serviceredir-items/inst-items/pmap-items/PolicyMap-list[name=__%s_dpu_redir]", name)
		err = n.gnmiDel(ctx, path)
		if err != nil {
			logger.GetLogger().Error("", logfields.Error, err)
			return err
		}

		// delete ep
		path = fmt.Sprintf("/System/serviceredir-items/inst-items/service-items/Service-list[name=__%s_dpu_redir]", name)
		err = n.gnmiDel(ctx, path)
		if err != nil {
			logger.GetLogger().Error("", logfields.Error, err)
			return err
		}
	}

	return nil
}

func (n *Nxos) setPkgAction(ctx context.Context, isFile bool, fpath string) error {
	logger.GetLogger().Debug("SetPkgAction", "isFile", isFile, "fpath", fpath)

	/*
		var url string
		if isFile {
			url = "appmgr://HypershieldAgent" + fpath
		} else {
			url = fpath
		}
		isProcessed := uint32(0)
		items := model.Cisco_NX_OSDevice_System_SwpkgsItems_RpmactionItems{
			IsProcessed: &isProcessed,
			Url:         &url,
		}
		if isFile {
			items.PkgAction = model.Cisco_NX_OSDevice_Swpkgs_PackageAction_add_activate
		} else {
			items.PkgAction = model.Cisco_NX_OSDevice_Swpkgs_PackageAction_activate
		}

		jstr, err := ygot.EmitJSON(&items, &ygot.EmitJSONConfig{
			Format:        ygot.RFC7951,
			Indent:        "  ",
			RFC7951Config: &ygot.RFC7951JSONConfig{},
		})
		if err != nil {
			logger.GetLogger().Error("Fail to emit json", logfields.Error, err)
			return err
		}

		path := "/System/swpkgs-items/rpmaction-items"
		err = n.gnmiSet(ctx, path, jstr)
		if err != nil {
			logger.GetLogger().Error("", logfields.Error, err)
			return err
		}
	*/
	return nil
}

func (n *Nxos) setLocalSvcState(ctx context.Context) error {
	logger.GetLogger().Debug("setLocalSvcState", "state", n.Ha.NxStates.SvcState)

	var items model.Cisco_NX_OSDevice_System_SasItems_SvcItems_SvcinstItems_SvcInstanceList_FwpolicystateItems_ExtItems
	switch n.Ha.NxStates.SvcState {
	case hav1.SERVICE_STATE_SVC_SUCCESS:
		items.LocalSvcState = model.Cisco_NX_OSDevice_SasSvcStateE_ready

	case hav1.SERVICE_STATE_SVC_FAILURE:
		items.LocalSvcState = model.Cisco_NX_OSDevice_SasSvcStateE_not_ready
	}
	jstr, err := ygot.EmitJSON(&items, &ygot.EmitJSONConfig{
		Format:        ygot.RFC7951,
		Indent:        "  ",
		RFC7951Config: &ygot.RFC7951JSONConfig{},
	})
	if err != nil {
		logger.GetLogger().Error("Fail to emit json", logfields.Error, err)
		return err
	}
	path := svcInst + "/fwpolicystate-items/ext-items"
	err = n.gnmiSet(ctx, path, jstr)
	if err != nil {
		logger.GetLogger().Error("", logfields.Error, err)
		return err
	}
	return nil
}

func (n *Nxos) setLocalSvcStateToFailure(ctx context.Context) error {
	logger.GetLogger().Debug("setLocalSvcStateToFailure")

	items := model.Cisco_NX_OSDevice_System_SasItems_SvcItems_SvcinstItems_SvcInstanceList_FwpolicystateItems_ExtItems{
		LocalSvcState: model.Cisco_NX_OSDevice_SasSvcStateE_not_ready,
	}
	jstr, err := ygot.EmitJSON(&items, &ygot.EmitJSONConfig{
		Format:        ygot.RFC7951,
		Indent:        "  ",
		RFC7951Config: &ygot.RFC7951JSONConfig{},
	})
	if err != nil {
		logger.GetLogger().Error("Fail to emit json", logfields.Error, err)
		return err
	}
	path := svcInst + "/fwpolicystate-items/ext-items"
	err = n.gnmiSet(ctx, path, jstr)
	if err != nil {
		logger.GetLogger().Error("", logfields.Error, err)
		return err
	}
	return nil
}

func (n *Nxos) setRemoteMbrState(ctx context.Context, ip string) error {
	peer, ok := n.Ha.Peers[ip]
	if !ok {
		logger.GetLogger().Error("Member missing")
		return nil
	}

	logger.GetLogger().Debug("setRemoteMbrState", "peer", peer.State)

	items := model.Cisco_NX_OSDevice_System_SasItems_SvcItems_SvcinstItems_SvcInstanceList_HaItems_ExtItems_PeerItems{
		HaPeerExtList: map[string]*model.Cisco_NX_OSDevice_System_SasItems_SvcItems_SvcinstItems_SvcInstanceList_HaItems_ExtItems_PeerItems_HaPeerExtList{},
	}

	list := model.Cisco_NX_OSDevice_System_SasItems_SvcItems_SvcinstItems_SvcInstanceList_HaItems_ExtItems_PeerItems_HaPeerExtList{
		IpAddr: &ip,
	}

	switch peer.State {
	case hav1.MBR_STATE_HA_NA:
		list.SvcHaState = model.Cisco_NX_OSDevice_SasSvcHaStateE_no_ha

	case hav1.MBR_STATE_HA_OK:
		list.SvcHaState = model.Cisco_NX_OSDevice_SasSvcHaStateE_ha_ok

	case hav1.MBR_STATE_HA_FAIL:
		list.SvcHaState = model.Cisco_NX_OSDevice_SasSvcHaStateE_ha_fail
	}

	items.HaPeerExtList[ip] = &list
	jstr, err := ygot.EmitJSON(&items, &ygot.EmitJSONConfig{
		Format:        ygot.RFC7951,
		Indent:        "  ",
		RFC7951Config: &ygot.RFC7951JSONConfig{},
	})
	if err != nil {
		logger.GetLogger().Error("Fail to emit json", logfields.Error, err)
		return err
	}
	path := svcInst + "/ha-items/ext-items/peer-items"
	err = n.gnmiSet(ctx, path, jstr)
	if err != nil {
		logger.GetLogger().Error("", logfields.Error, err)
		return err
	}
	return nil
}

func (n *Nxos) setRemoteSvcState(ctx context.Context, ip string) error {
	logger.GetLogger().Debug("setRemoteSvcState", "ip", ip)

	mbr, ok := n.Ha.Members[ip]
	if !ok {
		logger.GetLogger().Error("Member missing")
		return nil
	}

	logger.GetLogger().Debug("setRemoteSvcState", "svc", mbr.Info.HaInfo.Service)

	items := model.Cisco_NX_OSDevice_System_SasItems_SvcItems_SvcinstItems_SvcInstanceList_HaItems_ExtItems_PeerItems{
		HaPeerExtList: map[string]*model.Cisco_NX_OSDevice_System_SasItems_SvcItems_SvcinstItems_SvcInstanceList_HaItems_ExtItems_PeerItems_HaPeerExtList{},
	}

	list := model.Cisco_NX_OSDevice_System_SasItems_SvcItems_SvcinstItems_SvcInstanceList_HaItems_ExtItems_PeerItems_HaPeerExtList{
		IpAddr: &ip,
	}
	switch mbr.Info.HaInfo.Service {
	case hav1.SERVICE_STATE_SVC_SUCCESS:
		list.SvcState = model.Cisco_NX_OSDevice_SasSvcStateE_ready

	case hav1.SERVICE_STATE_SVC_FAILURE:
		list.SvcState = model.Cisco_NX_OSDevice_SasSvcStateE_not_ready
	}

	items.HaPeerExtList[ip] = &list
	jstr, err := ygot.EmitJSON(&items, &ygot.EmitJSONConfig{
		Format:        ygot.RFC7951,
		Indent:        "  ",
		RFC7951Config: &ygot.RFC7951JSONConfig{},
	})
	if err != nil {
		logger.GetLogger().Error("Fail to emit json", logfields.Error, err)
		return err
	}
	path := svcInst + "/ha-items/ext-items/peer-items"
	err = n.gnmiSet(ctx, path, jstr)
	if err != nil {
		logger.GetLogger().Error("", logfields.Error, err)
		return err
	}
	return nil
}

func (n *Nxos) setRemoteStatesAdjDown(ctx context.Context, ip string) error {
	logger.GetLogger().Debug("setRemoteStatesAdjDown:", "ip", ip)

	items := model.Cisco_NX_OSDevice_System_SasItems_SvcItems_SvcinstItems_SvcInstanceList_HaItems_ExtItems_PeerItems{
		HaPeerExtList: map[string]*model.Cisco_NX_OSDevice_System_SasItems_SvcItems_SvcinstItems_SvcInstanceList_HaItems_ExtItems_PeerItems_HaPeerExtList{},
	}

	list := model.Cisco_NX_OSDevice_System_SasItems_SvcItems_SvcinstItems_SvcInstanceList_HaItems_ExtItems_PeerItems_HaPeerExtList{
		IpAddr: &ip,
	}
	list.SvcState = model.Cisco_NX_OSDevice_SasSvcStateE_not_ready
	list.SvcHaState = model.Cisco_NX_OSDevice_SasSvcHaStateE_no_ha

	items.HaPeerExtList[ip] = &list
	jstr, err := ygot.EmitJSON(&items, &ygot.EmitJSONConfig{
		Format:        ygot.RFC7951,
		Indent:        "  ",
		RFC7951Config: &ygot.RFC7951JSONConfig{},
	})
	if err != nil {
		logger.GetLogger().Error("fail to emit json", logfields.Error, err)
		return err
	}
	path := svcInst + "/ha-items/ext-items/peer-items"
	err = n.gnmiSet(ctx, path, jstr)
	if err != nil {
		logger.GetLogger().Error("fail in gnmiSet", logfields.Error, err)
		return err
	}
	return nil
}

func (n *Nxos) setLocalHaState(ctx context.Context) error {
	logger.GetLogger().Debug("setHaState", "state", n.Ha.NxStates.HaState)

	var items model.Cisco_NX_OSDevice_System_SasItems_SvcItems_SvcinstItems_SvcInstanceList_HaItems_ExtItems
	switch n.Ha.NxStates.HaState {
	case hav1.HA_STATE_NO_HA:
		items.AgentHaState = model.Cisco_NX_OSDevice_SasAgentHaStateE_no_ha
		return nil

	case hav1.HA_STATE_HA_READY:
		items.AgentHaState = model.Cisco_NX_OSDevice_SasAgentHaStateE_ha_ready

	case hav1.HA_STATE_HA_NOTREADY:
		items.AgentHaState = model.Cisco_NX_OSDevice_SasAgentHaStateE_ha_not_ready

	case hav1.HA_STATE_HA_SWITCHOVER:
		items.AgentHaState = model.Cisco_NX_OSDevice_SasAgentHaStateE_ha_switchover
	}
	jstr, err := ygot.EmitJSON(&items, &ygot.EmitJSONConfig{
		Format:        ygot.RFC7951,
		Indent:        "  ",
		RFC7951Config: &ygot.RFC7951JSONConfig{},
	})
	if err != nil {
		logger.GetLogger().Error("fail to emit json", logfields.Error, err)
		return err
	}
	path := svcInst + "/ha-items/ext-items"
	err = n.gnmiSet(ctx, path, jstr)
	if err != nil {
		logger.GetLogger().Error("fail in gnmiSet", logfields.Error, err)
		return err
	}
	return nil
}

func (n *Nxos) setLocalHaStateToNotReady(ctx context.Context) error {
	logger.GetLogger().Debug("setLocalHaStateToNotReady")

	var items model.Cisco_NX_OSDevice_System_SasItems_SvcItems_SvcinstItems_SvcInstanceList_HaItems_ExtItems
	items.AgentHaState = model.Cisco_NX_OSDevice_SasAgentHaStateE_ha_not_ready
	jstr, err := ygot.EmitJSON(&items, &ygot.EmitJSONConfig{
		Format:        ygot.RFC7951,
		Indent:        "  ",
		RFC7951Config: &ygot.RFC7951JSONConfig{},
	})
	if err != nil {
		logger.GetLogger().Error("fail to emit json", logfields.Error, err)
		return err
	}
	path := svcInst + "/ha-items/ext-items"
	err = n.gnmiSet(ctx, path, jstr)
	if err != nil {
		logger.GetLogger().Error("fail in gnmiSet", logfields.Error, err)
		return err
	}
	return nil
}

// notify DPU issue via asicState

func (n *Nxos) SetRegFail(ctx context.Context, reason string) {
	logger.GetLogger().Debug("SetRegFail", "reason", reason)

	n.setControllerStatus(ctx, true,
		model.Cisco_NX_OSDevice_Sas_CommonStateE_failure, reason, "")
	if reason == RegFailK8sAuth {
		n.setSkipReg(ctx, reason)
	}
}

func (n *Nxos) SetRegOk(ctx context.Context, reason string) {
	logger.GetLogger().Debug("SetRegOk", "reason", reason)
	n.setControllerStatus(ctx, true,
		model.Cisco_NX_OSDevice_Sas_CommonStateE_success, reason, "")
}

func (n *Nxos) SetConnOk(ctx context.Context, reason string) {
	logger.GetLogger().Debug("SetConnOk", "reason", reason)
	n.setControllerStatus(ctx, false,
		model.Cisco_NX_OSDevice_Sas_CommonStateE_success, "", "")
}

func (n *Nxos) SetConnFail(ctx context.Context, reason string) {
	logger.GetLogger().Debug("SetConnFail", "reason", reason)
	n.setControllerStatus(ctx, false,
		model.Cisco_NX_OSDevice_Sas_CommonStateE_failure, reason, "")
}

func (n *Nxos) ResetReg(ctx context.Context) {
	logger.GetLogger().Debug("ResetReg")
	n.setControllerStatus(ctx, true,
		model.Cisco_NX_OSDevice_Sas_CommonStateE_unknown, "", "")
}

func (n *Nxos) ResetConn(ctx context.Context) {
	logger.GetLogger().Debug("ResetConn")
	n.setControllerStatus(ctx, false,
		model.Cisco_NX_OSDevice_Sas_CommonStateE_unknown, "", "")
}

func (n *Nxos) StartUpdate(ctx context.Context, uid, utype, uver, fpath string) error {
	logger.GetLogger().Debug("StartUpdate",
		"UpdateId", uid, "UpdateType", utype, "file", fpath)

	err := n.setPkgAction(ctx, true, fpath)
	if err != nil {
		logger.GetLogger().Error("fail to set update MO", logfields.Error, err)
		return err
	}

	update := UpdatePersist{
		Id:      uid,
		Type:    utype,
		Version: uver,
	}
	err = n.store(ctx, updateFname, update)
	if err != nil {
		logger.GetLogger().Error("fail to persist update", logfields.Error, err)
	}
	return err
}

func (n *Nxos) ActivateInactive(ctx context.Context, uid, utype, uver string) (bool, error) {
	logger.GetLogger().Debug("ActivateInactive", "UpdateId", uid, "UpdateType", utype, "UpdateVersion", uver)

	jstrs, err := n.gnmiGet(ctx, "/System/swpkgs-items/rpminfo-items")
	if err != nil {
		logger.GetLogger().Error("Fail to get rpminfo-items", logfields.Error, err)
		return false, err
	}
	// logger.GetLogger().Debug("jstrs: %v", jstrs)
	var found bool
	var fpath string
	if len(jstrs) > 0 && len(jstrs[0]) > 0 {
		items := &model.Cisco_NX_OSDevice_System_SwpkgsItems_RpminfoItems{}
		opts := []ytypes.UnmarshalOpt{&ytypes.IgnoreExtraFields{}}
		err = model.Unmarshal([]byte(jstrs[0]), items, opts...)
		if err != nil {
			logger.GetLogger().Error("Fail to unmarshal rpminfo-items", logfields.Error, err)
		} else {
			name := "dpu_fw-" + uver
			logger.GetLogger().Debug("Check inactive version", "name", name)
			for _, info := range items.RpmInfoList {
				if info.Name == nil {
					continue
				}
				if strings.HasPrefix(*info.Name, name) &&
					info.OperSt == model.Cisco_NX_OSDevice_Swpkgs_OperState_inactive_base {
					logger.GetLogger().Debug("inactive version found")
					fpath = *info.Name
					found = true
					break
				}
			}
		}
	}

	if !found {
		logger.GetLogger().Debug("inactive version not found")
		return false, nil
	}

	logger.GetLogger().Debug("activate inactive version", "path", fpath)
	err = n.setPkgAction(ctx, false, fpath)
	if err != nil {
		logger.GetLogger().Error("fail to set update MO", logfields.Error, err)
		return false, err
	}

	update := UpdatePersist{
		Id:      uid,
		Type:    utype,
		Version: uver,
	}
	err = n.store(ctx, updateFname, update)
	if err != nil {
		logger.GetLogger().Error("fail to persist update", logfields.Error, err)
	}
	return true, err
}

func (n *Nxos) setGlobalId(ctx context.Context, recon map[string]uint16) error {
	logger.GetLogger().Debug("setGlobalId: ", "recon", recon)

	serviceItems := model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_ServiceItems{
		ServiceList: map[string]*model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_ServiceItems_ServiceList{},
	}

	for nm, gid := range recon {
		vrf, ok := n.Vrfs[nm]
		if !ok {
			err := errors.New("Not found: VRF " + vrf.Name)
			logger.GetLogger().Error("", logfields.Error, err)
			return err
		}

		svcEndPointDpuList := model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_ServiceItems_ServiceList_DpuepItems_SvcEndPointDpuList{
			Vlan: &gid,
		}
		if n.IsLbModePinning(ctx) {
			svcEndPointDpuList.DpuNum = dpu2mod(ctx, vrf.DpuPinned)
		} else {
			svcEndPointDpuList.DpuNum = model.Cisco_NX_OSDevice_Sas_SvcModulePinning_all
		}

		dpuepItems := model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_ServiceItems_ServiceList_DpuepItems{
			SvcEndPointDpuList: map[model.E_Cisco_NX_OSDevice_Sas_SvcModulePinning]*model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_ServiceItems_ServiceList_DpuepItems_SvcEndPointDpuList{},
		}

		var pinned model.E_Cisco_NX_OSDevice_Sas_SvcModulePinning
		if n.IsLbModePinning(ctx) {
			pinned = dpu2mod(ctx, vrf.DpuPinned)
		} else {
			pinned = model.Cisco_NX_OSDevice_Sas_SvcModulePinning_all
		}
		dpuepItems.SvcEndPointDpuList[pinned] = &svcEndPointDpuList

		name := fmt.Sprintf("__%s_dpu_redir", vrf.Name)
		serviceList := model.Cisco_NX_OSDevice_System_ServiceredirItems_InstItems_ServiceItems_ServiceList{
			Name:       &name,
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
		logger.GetLogger().Error("Fail to emit json", logfields.Error, err)
		return err
	}

	path := "/System/serviceredir-items/inst-items/service-items"
	err = n.gnmiSet(ctx, path, jstr)
	if err != nil {
		logger.GetLogger().Error("", logfields.Error, err)
		return err
	}
	return nil
}

// setControllerEndpoint sets or removes the controller endpoint configuration in nxos device via gNMI
func (n *Nxos) setControllerEndpoint(ctx context.Context, endpoint string, port uint32, remove bool) error {
	logger.GetLogger().Debug("setControllerEndpoint", "endpoint", endpoint)
	if endpoint == "" && !remove {
		// For add operation, empty endpoint is no-op
		logger.GetLogger().Info("Controller endpoint is empty")
		return nil
	}

	// System/sas-items/scontroller-items/ext-items
	items := model.Cisco_NX_OSDevice_System_SasItems_SvcItems_SvcinstItems_SvcInstanceList_ScontrollerItems_ExtItems{
		ControllerEndpoint: &endpoint,
		ControllerPort:     &port,
	}

	jstr, err := ygot.EmitJSON(&items, &ygot.EmitJSONConfig{
		Format:        ygot.RFC7951,
		Indent:        "  ",
		RFC7951Config: &ygot.RFC7951JSONConfig{},
	})
	if err != nil {
		logger.GetLogger().Error("fail to emit json", logfields.Error, err)
		return err
	}

	err = n.gnmiSet(ctx, svcInst+"/scontroller-items/ext-items", jstr)
	if err != nil {
		logger.GetLogger().Error("", logfields.Error, err)
		return err
	}
	return nil
}

func dpu2mod(_ context.Context, dpu uint16) model.E_Cisco_NX_OSDevice_Sas_SvcModulePinning {
	logger.GetLogger().Debug("dpu2mod", "dpu", dpu)
	switch dpu {
	case 1:
		return model.Cisco_NX_OSDevice_Sas_SvcModulePinning_1
	case 2:
		return model.Cisco_NX_OSDevice_Sas_SvcModulePinning_2
	case 3:
		return model.Cisco_NX_OSDevice_Sas_SvcModulePinning_3
	case 4:
		return model.Cisco_NX_OSDevice_Sas_SvcModulePinning_4
	case allDpu:
		return model.Cisco_NX_OSDevice_Sas_SvcModulePinning_all
	}
	logger.GetLogger().Error("Unexpected dpu")
	return model.Cisco_NX_OSDevice_Sas_SvcModulePinning_invalid
}

func mod2dpu(_ context.Context, mod model.E_Cisco_NX_OSDevice_Sas_SvcModulePinning) uint16 {
	logger.GetLogger().Debug("mod2dpu", "mod", mod)
	switch mod {
	case model.Cisco_NX_OSDevice_Sas_SvcModulePinning_1:
		return uint16(1)
	case model.Cisco_NX_OSDevice_Sas_SvcModulePinning_2:
		return uint16(2)
	case model.Cisco_NX_OSDevice_Sas_SvcModulePinning_3:
		return uint16(3)
	case model.Cisco_NX_OSDevice_Sas_SvcModulePinning_4:
		return uint16(4)
	case model.Cisco_NX_OSDevice_Sas_SvcModulePinning_all:
		return uint16(allDpu)
	}
	logger.GetLogger().Error("Unexpected mod")
	return uint16(0)
}

func dpu2name(_ context.Context, dpu uint16) string {
	logger.GetLogger().Debug("dpu2name", "dpu", dpu)
	switch dpu {
	case 1:
		return "__dpu1_dpu_vlan_redir"
	case 2:
		return "__dpu2_dpu_vlan_redir"
	case 3:
		return "__dpu3_dpu_vlan_redir"
	case 4:
		return "__dpu4_dpu_vlan_redir"
	case allDpu:
		return "__dpu_all_dpu_vlan_redir"
	}
	logger.GetLogger().Error("Unexpected dpu")
	return ""
}

func name2dpu(_ context.Context, name string) uint16 {
	logger.GetLogger().Debug("name2dpu", "name", name)

	dpu := strings.TrimPrefix(name, "__dpu")
	dpu = strings.TrimSuffix(dpu, "_dpu_vlan_redir")
	logger.GetLogger().Debug("dpu", "dpu", dpu)
	switch dpu {
	case "1":
		return uint16(1)
	case "2":
		return uint16(2)
	case "3":
		return uint16(3)
	case "4":
		return uint16(4)
	case "_all":
		return uint16(allDpu)
	}
	logger.GetLogger().Error("Unexpected name")
	return uint16(0)
}

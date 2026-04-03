// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.
package paths

// Device Store Paths
const (
	// --------------------------------
	// Switch managed paths (subscribe)
	// --------------------------------

	// deviceStore.Token
	DeviceStoreConnToken = "device:/System/sas-items/volatiledata-items/agent-items/SasAgentData-list[svcName=hypershield]/connToken"
	// deviceStore.ProxyServer
	DeviceStoreProxyServer = "device:/System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/scontroller-items/httpsProxySvr"
	// deviceStore.ProxyPort
	DeviceStoreProxyPort = "device:/System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/scontroller-items/httpsProxyPort"
	// deviceStore.SerialNumber
	DeviceStoreSerialNumber = "device:/System/ch-items/spbp-items/spcmn-items/serNum"
	// deviceStore.Model
	DeviceStoreModel = "device:/System/ch-items/spbp-items/spcmn-items/pdNum"
	// deviceStore.ServiceIP
	DeviceStoreServiceIP = "device:/System/sas-items/state-items/agent-items/SasAgent-list[svcName=hypershield]/agentSrcIntfAddr"
	// deviceStore.InService
	DeviceStoreInService = "device:/System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/fwpolicy-items/operState"
	// Supervisor slot types, used to pull deviceStore.SoftwareVersion
	DeviceStoreSupervisorType = "device:/System/ch-items/supslot-items/SupCSlot-list/sup-items/type"
	// deviceStore.LbMode
	DeviceStoreLoadBalancingMode = "device:/System/sas-items/globalpol-items/lbMode"

	// -------------------------
	// Agent managed paths (set)
	// -------------------------

	// DeviceStoreAdmissionStatus
	DeviceStoreAdmissionStatus = "device:/System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/scontroller-items/ext-items/admissionStatus"
	// DeviceStoreConnectionStatus
	DeviceStoreConnectionStatus = "device:/System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/scontroller-items/ext-items/connectionStatus"
	// DeviceStoreRejectReason
	DeviceStoreRejectReason = "device:/System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/scontroller-items/ext-items/rejectReason"
	// DeviceStoreControllerEndpoint
	DeviceStoreControllerEndpoint = "device:/System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/scontroller-items/ext-items/controllerEndpoint"
	// DeviceStoreControllerPort
	DeviceStoreControllerPort = "device:/System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/scontroller-items/ext-items/controllerPort"
	// DeviceStoreVersion
	DeviceStoreControllerVersion = "device:/System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/scontroller-items/ext-items/version"
	// DeviceStoreSystemState
	DeviceStoreSystemState = "device:/System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/sagent-items/ext-items/systemState"
)

// DPU Store Paths
const (
	// --------------------------------
	// Switch managed paths (subscribe)
	// --------------------------------

	// dpuStore.DpuCount
	DPUStoreNumDPUs = "device:/System/sas-items/dpu-items/ext-items/numDpus"
	// dpuStore.InventoryState
	DPUStoreInitState = "device:/System/sas-items/dpu-items/ext-items/initState"
	// dpuStore.Dpu.Ip
	DPUStoreIP = "device:/System/sas-items/dpu-items/inst-items/Inst-list/ext-items/ip"
	// dpuStore.Dpu.Version
	DPUStoreVersion = "device:/System/sas-items/dpu-items/inst-items/Inst-list/ext-items/mainFwVer"
	// dpuStore.Dpu.State
	DPUStoreState = "device:/System/sas-items/dpu-items/inst-items/Inst-list/ext-items/state"

	// -------------------------
	// Agent managed paths (set)
	// -------------------------

	// DPUStoreTCPPorts
	DPUStoreTCPPorts = "device:/System/sas-items/dpu-items/inst-items/Inst-list[moduleNum=%d]/ext-items/tcpCpPortRange"
	// DPUStoreUDPPorts
	DPUStoreUDPPorts = "device:/System/sas-items/dpu-items/inst-items/Inst-list[moduleNum=%d]/ext-items/udpCpPortRange"
)

// HA Store Paths
const (
	// --------------------------------
	// Switch managed paths (subscribe)
	// --------------------------------

	// haStore HA container (used for full-config delete detection)
	HAStoreHaItems = "device:/System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/ha-items"
	// haStore.Enabled
	HAStoreEnabled = "device:/System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/ha-items/adminState"
	// haStore.SwitchState
	HAStoreSwitchState = "device:/System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/ha-items/nxHaOperState"
	// haStore.Peer
	HAStorePeers = "device:/System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/ha-items/peer-items/HaPeer-list"
	// haStore.Peer.IpAddr
	HAStorePeerIpAddr = "device:/System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/ha-items/peer-items/HaPeer-list/ipAddr"
	// haStore.Peer.IpConfigState
	HAStorePeerIpConfigState = "device:/System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/ha-items/peer-items/HaPeer-list/ipConfigState"
	// haStore.HaIp
	HAStoreHaIp = "device:/System/sas-items/state-items/agent-items/SasAgent-list[svcName=hypershield]/agentHaSrcIntfAddr"

	// -------------------------
	// Agent managed paths (set)
	// -------------------------

	// haStore.HaPort
	HAStoreHaPort = "device:/System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/ha-items/ext-items/agentHaPort"
	// haStore.Local.SvcState
	HAStoreLocalSvcState = "device:/System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/fwpolicystate-items/ext-items/localSvcState"
	// haStore.Local.SvcStateReason
	HAStoreLocalSvcStateReason = "device:/System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/fwpolicystate-items/ext-items/localSvcStateReason"
	// haStore.Local.HaState
	HAStoreLocalHaState = "device:/System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/ha-items/ext-items/agentHaState"
	// haStore.Local.HaStateReason
	HAStoreLocalHaStateReason = "device:/System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/ha-items/ext-items/agentHaStateReason"
	// haStore.Peer.Ip
	HAStorePeerIp = "device:/System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/ha-items/ext-items/peer-items/HaPeerExt-list[ipAddr=%s]/ipAddr"
	// haStore.Peer.SvcState
	HAStorePeerSvcState = "device:/System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/ha-items/ext-items/peer-items/HaPeerExt-list[ipAddr=%s]/svcState"
	// haStore.Peer.SvcStateReason
	HAStorePeerSvcStateReason = "device:/System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/ha-items/ext-items/peer-items/HaPeerExt-list[ipAddr=%s]/svcStateReason"
	// haStore.Peer.HaState
	HAStorePeerHaState = "device:/System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/ha-items/ext-items/peer-items/HaPeerExt-list[ipAddr=%s]/svcHaState"
	// haStore.Peer.HaStateReason
	HAStorePeerHaStateReason = "device:/System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/ha-items/ext-items/peer-items/HaPeerExt-list[ipAddr=%s]/svcHaStateReason"
)

// NXOS Manager Paths
const (
	// SvcInstancePath is the gNMI path for the hypershield service instance.
	// A DELETE on this path indicates the service instance has been removed.
	SvcInstancePath = "device:/System/sas-items/svc-items/svcinst-items/SvcInstance-list"

	// SvcFwPolicyPath is the gNMI path for the firewall policy under hypershield.
	// A DELETE on this path indicates the firewall policy has been removed.
	SvcFwPolicyPath = "device:/System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/fwpolicy-items"
)

// VRF Store Paths
const (
	// --------------------------------
	// Switch managed paths (subscribe)
	// --------------------------------

	// Global Vrf delete path
	VrfStoreGlobalVrf = "device:/System/inst-items/Inst-list"
	// vrfStore.Vrf.Name
	VrfStoreGlobalVrfName = "device:/System/inst-items/Inst-list/name"
	// Service Vrf delete path
	VrfStoreServiceVrf = "device:/System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/fwpolicy-items/ipvrf-items/dom-items/Dom-list"
	// vrfStore.Vrf.Name
	VrfStoreServiceVrfName = "device:/System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/fwpolicy-items/ipvrf-items/dom-items/Dom-list/name"
	// vrfStore.Vrf.Affinity
	VrfStoreServiceVrfAffinity = "device:/System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/fwpolicy-items/ipvrf-items/dom-items/Dom-list/affinity"

	// -------------------------
	// Agent managed paths (set)
	// -------------------------

	// Vrf enforcement binding, used for redirects
	VrfStoreEnforcementBinding = "device:/System/serviceredir-items/inst-items/dom-items"
)

// VLAN Store Paths
const (
	// --------------------------------
	// Switch managed paths (subscribe)
	// --------------------------------

	// Global Vlan delete path
	VlanStoreGlobalVlan = "device:/System/bd-items/bd-items/BD-list"
	// vlanStore.Vlan.Name
	VlanStoreGlobalVlanName = "device:/System/bd-items/bd-items/BD-list/fabEncap"
	// Service Vlan delete path
	VlanStoreServiceVlan = "device:/System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/fwpolicy-items/bd-items/vlan-items/Vlan-list"
	// vlanStore.Vlan.Name
	VlanStoreServiceVlanName = "device:/System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/fwpolicy-items/bd-items/vlan-items/Vlan-list/vlanId"
	// vlanStore.Vlan.Affinity
	VlanStoreServiceVlanAffinity = "device:/System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/fwpolicy-items/bd-items/vlan-items/Vlan-list/affinity"

	// -------------------------
	// Agent managed paths (set)
	// -------------------------

	// Vlan enforcement binding, used for redirects
	VlanStoreEnforcementBinding = "device:/System/serviceredir-items/inst-items/bd-items"
)

// Service Redirect Paths (agent managed, SET/DELETE)
const (
	ServiceRedirServiceItems = "device:/System/serviceredir-items/inst-items/service-items"
	ServiceRedirPmapItems    = "device:/System/serviceredir-items/inst-items/pmap-items"
	ServiceRedirDomItems     = "device:/System/serviceredir-items/inst-items/dom-items"
	ServiceRedirBdItems      = "device:/System/serviceredir-items/inst-items/bd-items"
)

// FW Policy State Paths (agent managed, SET/DELETE)
const (
	FwPolicyStateVrf  = "device:/System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/fwpolicystate-items/ipvrfstate-items/dom-items"
	FwPolicyStateVlan = "device:/System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/fwpolicystate-items/bdstate-items/vlan-items"

	// FW Policy State subscription paths (switch-initiated deletes)
	FwPolicyStateVrfSub  = "device:/System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/fwpolicystate-items/ipvrfstate-items/dom-items/DomState-list"
	FwPolicyStateVlanSub = "device:/System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/fwpolicystate-items/bdstate-items/vlan-items/VlanState-list"
)

// ACL Redirect Paths (agent managed, SET)
const (
	AclIPv4Redirect = "device:/System/acl-items/ipv4-items/name-items/ACL-list[name=%s]/seq-items/ACE-list[seqNum=%d]"
	AclIPv6Redirect = "device:/System/acl-items/ipv6-items/name-items/ACL-list[name=%s]/seq-items/ACE-list[seqNum=%d]"
	AclNameIPv4     = "__dpu_redir"
	AclNameIPv6     = "__dpu_ipv6_redir"
)

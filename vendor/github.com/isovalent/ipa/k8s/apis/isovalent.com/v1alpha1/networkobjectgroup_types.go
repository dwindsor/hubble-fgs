// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this
// information or reproduction of this material is strictly forbidden unless
// prior written permission is obtained from Isovalent Inc.

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	isovalentcom "github.com/isovalent/ipa/k8s/apis/isovalent.com"
)

const (
	// NOGPluralName is the plural name of Network Object Group.
	NOGPluralName = "networkobjectgroups"

	// NOGKindDefinition is the kind name of Network Object Group.
	NOGKindDefinition = "NetworkObjectGroup"

	// NOGName is the full name of Network Object Group.
	NOGName = NOGPluralName + "." + isovalentcom.GroupName
)

// +genclient
// +genclient:noStatus
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:singular="networkobjectgroup",path="networkobjectgroups",scope="Namespaced"

// NetworkObjectGroup is a range of network locations which may be used for
// network policy enforcement by a specific device such as a Smart Switch or
// Tetragon Node.
//
// It is loosely based on the Cisco Security Cloud Control Network Object, as
// described at https://securitydocs.cisco.com/docs/scc-fw/manage/52934.dita .
type NetworkObjectGroup struct {
	metav1.TypeMeta `json:",inline"`
	// +kubebuilder:validation:Optional
	metav1.ObjectMeta `json:"metadata"`

	// +kubebuilder:validation:Required
	Spec NetworkObjectGroupSpec `json:"spec"`

	// +deepequal-gen=false
	// +kubebuilder:validation:Optional
	Status *NetworkObjectGroupStatus `json:"status,omitempty"`
}

// NetworkObjectGroupList is a list of NetworkObjectGroup objects.
//
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +deepequal-gen=false.
type NetworkObjectGroupList struct {
	metav1.TypeMeta `json:",inline"`
	// +kubebuilder:validation:Required
	metav1.ListMeta `json:"metadata"`

	// Items is a list of NetworkObjectGroup.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	Items []NetworkObjectGroup `json:"items"`
}

// NetworkObjectGroupSpec describes the Network Object Group.
//
// A Network Object Group consists of a set of IP locations within a logical network.
// For traffic to be considered part of the Network Object Group, the traffic must
// match all fields in this structure that are specified in the user-configured
// resource.
//
// +kubebuilder:validation:XValidation:rule="!(has(self.cidr) && has(self.cidrs))",message="at most one of the fields in [cidr cidrs] may be set"
// +kubebuilder:validation:XValidation:rule="!(has(self.virtualNetwork) && has(self.vlan))",message="at most one of the fields in [virtual vlan] may be set"
// +kubebuilder:validation:XValidation:rule="!(has(self.virtualNetwork) && has(self.vrf))",message="at most one of the fields in [virtual vrf] may be set"
// +kubebuilder:validation:XValidation:rule="!(has(self.vlan) && has(self.vrf))",message="at most one of the fields in [vlan vrf] may be set"
//
//nolint:godoclint
type NetworkObjectGroupSpec struct {
	// +kubebuilder:validation:Optional
	Description string `json:"description,omitempty"`
	// Virtual is the logical network for the Network Object Group.
	//
	// If omitted, the Network Object Group contains traffic in the default
	// virtual network.
	//
	// +kubebuilder:validation:Optional
	VirtualNetwork *VirtualNetwork `json:"virtualNetwork,omitempty"`

	// CIDRs is a list of IP prefixes in CIDR format. Network locations
	// are considered part of the Network Object Group if they have an IPv4 or
	// IPv6 address that falls within a CIDR listed in this field.
	//
	// If omitted, the Network Object Group contains all IP addresses within the
	// Virtual Network.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:items:Format:=cidr
	CIDRs []string `json:"cidrs,omitempty"`

	// ** Deprecated fields **
	//
	// The fields below were added in an earlier v1alpha1 of
	// SmartSwitchNetworkPolicy. They should be removed in favor of the
	// newer definitions above.

	// CIDR describes a range of IP locations.
	//
	// Deprecated: Use 'cidrs' instead.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Format=cidr
	CIDR string `json:"cidr,omitempty"`

	// VRF is a Virtual Routing and Forwarding name.
	//
	// Deprecated: Use 'virtual.vrf' instead.
	//
	// +kubebuilder:validation:Optional
	VRF string `json:"vrf,omitempty"`

	// VLAN is a Virtual LAN tag.
	//
	// Deprecated: Use 'virtual.vlans[]' instead.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=4094
	VLAN int32 `json:"vlan,omitempty"`
}

// VirtualNetwork defines the logical network identifiers for the Network
// Group.
//
// For traffic to be considered part of the Virtual Network, all specified
// fields in this structure must match the traffic.
//
// This API does not specify how virtual network identifiers map to network
// interfaces or devices.
//
// +kubebuilder:validation:XValidation:rule="has(self.vrfs) || has(self.vlans)",message="specify at least one of [vrfs vlans]"
//
//nolint:godoclint
type VirtualNetwork struct {
	// VRFs is a list of Virtual Routing and Forwarding names for the
	// Virtual Network.
	//
	// When combining with other fields ,if the traffic matches any VRF
	// specified here and matches the other field's constraint, then the
	// traffic is considered "part of" this Virtual Network.
	//
	// Only one VRF can be specified currently.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=1
	VRFs []string `json:"vrfs,omitempty"`

	// VLANs is a list of Virtual LANs in the Network Object Group.
	//
	// If specified, traffic tagged with any of the specified VLANs is
	// considered part of the Virtual Network.
	//
	// If not specified, only untagged traffic is considered part of the
	// Virtual Network.
	//
	// When combining with other fields ,if the traffic matches any VLAN
	// specified here and matches the other field's constraint, then the
	// traffic is considered "part of" this Virtual Network.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=100
	// +kubebuilder:validation:items:Minimum=1
	// +kubebuilder:validation:items:Maximum=4094
	VLANs []int32 `json:"vlans,omitempty"`
}

// NetworkObjectGroupStatus is the status of the Network Object Group.
//
// +deepequal-gen=true.
type NetworkObjectGroupStatus struct {
	// +kubebuilder:validation:Optional
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []NetworkObjectGroupCondition `json:"conditions,omitempty"`
}

// NetworkObjectGroupConditionType is a condition for the
// NetworkObjectGroupStatus.
type NetworkObjectGroupConditionType string

const (
	// NetworkObjectGroupConditionValid is the valid condition for the
	// NetworkObjectGroupStatus. If set, the NetworkObjectGroup has been validated.
	NetworkObjectGroupConditionValid NetworkObjectGroupConditionType = "Valid"
)

// NetworkObjectGroupCondition is a condition for the NetworkObjectGroupStatus.
type NetworkObjectGroupCondition struct {
	// The type of the policy condition
	// +kubebuilder:validation:Required
	Type NetworkObjectGroupConditionType `json:"type"`
	// The status of the condition, one of True, False, or Unknown
	// +kubebuilder:validation:Required
	Status metav1.ConditionStatus `json:"status"`
	// The last time the condition transitioned from one status to another.
	// +kubebuilder:validation:Optional
	LastTransitionTime metav1.Time `json:"lastTransitionTime,omitempty"`
	// The reason for the condition's last transition.
	// +kubebuilder:validation:Optional
	Reason string `json:"reason,omitempty"`
	// A human readable message indicating details about the transition.
	// +kubebuilder:validation:Optional
	Message string `json:"message,omitempty"`
}

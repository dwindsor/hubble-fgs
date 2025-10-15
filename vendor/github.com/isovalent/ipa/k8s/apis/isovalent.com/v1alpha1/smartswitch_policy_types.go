// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// SmartSwitchNetwork consists of a CIDR and the logical Network
// the CIDR is associated with. If the logical network is omitted
// (no VRF or VLAN) then the policy applied against traffic that
// does not belong to any logical network which may or may not
// match any actual traffic depending on the switch configuration.
type SmartSwitchNetwork struct {
	// +kubebuilder:validation:Required
	CIDR string `json:"cidr"`
	// +kubebuilder:validation:Optional
	VRF string `json:"vrf"`
	// +kubebuilder:validation:Optional
	VLAN uint32 `json:"vlan"`
}

// SmartSwitchProtocolPort provides the protocol to apply the policy
// against with an optional port or a port range. When no ports are specified
// the port is a wildcard and policy applies against any port.
type SmartSwitchProtocolPort struct {
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=65535
	// +kubebuilder:validation:Optional
	Port uint32 `json:"port"`
	// EndPort is an optional field to indicate that the policy rule applies to
	// a port range from Port to EndPort inclusive instead of an individual
	// port. This field must not be set if the Port field is not set. The
	// EndPort value must be greater than the Port value.
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=65535
	// +kubebuilder:validation:Optional
	EndPort uint32 `json:"endPort,omitempty"`
	// +kubebuilder:validation:Required,Enum=icmp;tcp;udp
	Protocol string `json:"protocol"`
}

// SmartSwitchNetworkSource only supports IPBlocks at the moment there
// is currently no support to match source port so the policy applies
// against all source ports.
type SmartSwitchNetworkSource struct {
	// +kubebuilder:validation:Required
	IPBlock []SmartSwitchNetwork `json:"ipBlock,omitempty"`
}

// SmartSwitchNetworkDestination matches a specific network with an
// optional SmartSwitchNetworkProtocolPort object. If ProtoPort is
// not specified, the policy applies against all supported protocols
// and all ports.
type SmartSwitchNetworkDestination struct {
	// +kubebuilder:validation:Required
	IPBlock []SmartSwitchNetwork `json:"ipBlock,omitempty"`
	// ProtoPorts is an optional field to specify protocols and ports for a
	// policy rule. The policy rule applies to the cross product of IPBlock
	// and ProtoPorts. If the field is not specified, the policy rule applies
	// to all supported protocols and all ports.
	// +kubebuilder:validation:Optional
	ProtoPorts []SmartSwitchProtocolPort `json:"protoPorts,omitempty"`
}

// SmartSwitchNetworkPolicyRule is specifies the action for a source and
// destination pair. The cross product of the source and destination is
// used to calculate the rules created in the datapath. A description is
// optional and informational only it is exported with any statistics and
// or events related to the rule, but is not actually used otherwise in
// the datapath.
type SmartSwitchNetworkPolicyRule struct {
	// +kubebuilder:validation:Optional
	Description string `json:"description"`
	// +kubebuilder:validation:Required,Enum=allow;deny
	Action string `json:"action"`
	// +kubebuilder:validation:Required
	Source SmartSwitchNetworkSource `json:"source"`
	// +kubebuilder:validation:Required
	Destination SmartSwitchNetworkDestination `json:"destination"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// SmartSwitchNetworkPolicy is the Schema for the smartswitches netops API
type SmartSwitchNetworkPolicy struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty,omitzero"`

	// rules defines the network ops of the SmartSwitch
	// +optional
	Rules []SmartSwitchNetworkPolicyRule `json:"rules,omitempty,omitzero"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// SmartSwitchNetworkPolicyList contains a list of SmartSwitchNetworkPolicy
type SmartSwitchNetworkPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []SmartSwitchNetworkPolicy `json:"items,omitempty"`
}

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
	slimv1 "github.com/isovalent/ipa/k8s/slim/k8s/apis/meta/v1"
)

const (
	// SmartSwitch Network Policy (SNP).

	// SNPPluralName is the plural name of SmartSwitch Network Policy.
	SNPPluralName = "smartswitchnetworkpolicies"

	// SNPKindDefinition is the kind name of SmartSwitch Network Policy.
	SNPKindDefinition = "SmartSwitchNetworkPolicy"

	// SNPName is the full name of SmartSwitch Network Policy.
	SNPName = SNPPluralName + "." + isovalentcom.GroupName
)

// Annotations.
const (
	// AnnotationStaging marks the network policy as a staging policy that
	// is validated, but not deployed. If the value is non-empty then the
	// changes are validated as a difference against the named policy with
	// unchanged rules ignored.
	AnnotationStaging = SNPPluralName + "/" + "staging"

	// AnnotationValidation holds the validation results for a staging policy.
	AnnotationValidation = SNPPluralName + "/" + "validation"
)

// SmartSwitchNetworkPolicyList is a list of SmartSwitchNetworkPolicy resources.
//
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type SmartSwitchNetworkPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []SmartSwitchNetworkPolicy `json:"items,omitempty"`
}

// +genclient
// +genclient:noStatus
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:singular="smartswitchnetworkpolicy",path="smartswitchnetworkpolicies",scope="Namespaced"

// SmartSwitchNetworkPolicy is the Schema for the smartswitches netops API.
type SmartSwitchNetworkPolicy struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty,omitzero"`

	// Spec specifies network policy rules for SmartSwitch.
	// +kubebuilder:validation:Required
	Spec SmartSwitchNetworkPolicySpec `json:"spec"`
}

// SmartSwitchNetworkPolicySpec specifies network policy rules.
type SmartSwitchNetworkPolicySpec struct {
	// Rules defines the network policy rules for SmartSwitch
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	Rules []SmartSwitchNetworkPolicyRule `json:"rules"`
}

// GetObjectMetaStruct returns the generic k8s object metadata.
//
// Implements crdutils.CRDObject interface, required for working with CRDs
// outside of Kubernetes context.
func (snp *SmartSwitchNetworkPolicy) GetObjectMetaStruct() *metav1.ObjectMeta {
	return &snp.ObjectMeta
}

// SmartSwitchProtocolPort provides the protocol to apply the policy
// against with an optional port or a port range. When no ports are specified
// the port is a wildcard and policy applies against any port.
//
// +kubebuilder:validation:XValidation:rule="!has(self.endPort) || has(self.port)",message="endPort requires port to be set also"
// +kubebuilder:validation:XValidation:rule="!has(self.endPort) || self.endPort > self.port",message="endPort must be greater than port"
// +kubebuilder:validation:XValidation:rule="self.protocol != 'ICMP' || !has(self.port)",message="ICMP protocol does not support port numbers; port field must be omitted"
//
//nolint:godoclint
type SmartSwitchProtocolPort struct {
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=65535
	// +kubebuilder:validation:Optional
	Port int32 `json:"port,omitempty"`
	// EndPort is an optional field to indicate that the policy rule applies to
	// a port range from Port to EndPort inclusive instead of an individual
	// port. This field must not be set if the Port field is not set. The
	// EndPort value must be greater than the Port value.
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=65535
	// +kubebuilder:validation:Optional
	EndPort int32 `json:"endPort,omitempty"`
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum=ICMP;TCP;UDP
	Protocol string `json:"protocol"`
}

// NetworkObjectGroupRef is a reference to one or more NetworkObjectGroups.
//
// A Name or Labels selector must be specified. These will match the
// corresponding resources in the specified Namespace.
//
// +kubebuilder:validation:XValidation:rule="(has(self.name) && !has(self.groupSelector)) || (!has(self.name) && has(self.groupSelector))"
//
//nolint:godoclint
type NetworkObjectGroupRef struct {
	// Name of the NetworkObjectGroup.
	//
	// +kubebuilder:validation:Required
	Name string `json:"name"`

	// GroupSelector for the NetworkObjectGroup. This may select multiple
	// NetworkObjectGroup resources based on their metadata.labels.
	GroupSelector *slimv1.LabelSelector `json:"groupSelector,omitempty"`
}

// SmartSwitchNetworkSource only supports IPBlocks. At the moment there
// is no support to match source port so the policy applies against
// all source ports.
//
// All specified fields must match a set of traffic for the traffic to be
// subject to the parent rule.
//
// +kubebuilder:validation:XValidation:rule="(has(self.ipBlock) && !has(self.networkRef)) || (!has(self.ipBlock) && has(self.networkRef))",message="exactly one of the fields in [ipBlock networkRef] must be set"
//
//nolint:godoclint
type SmartSwitchNetworkSource struct {
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MinItems=1
	IPBlock []NetworkObjectGroupSpec `json:"ipBlock,omitempty"`

	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MinItems=1
	NetworkRef []NetworkObjectGroupRef `json:"networkRef,omitempty"`
}

// SmartSwitchNetworkDestination matches a specific network with an
// optional SmartSwitchNetworkProtocolPort object. If ProtoPort is
// not specified, the policy applies against all supported protocols
// and all ports.
//
// All specified fields must match a set of traffic for the traffic to be
// subject to the parent rule.
//
// +kubebuilder:validation:XValidation:rule="(has(self.ipBlock) && !has(self.networkRef)) || (!has(self.ipBlock) && has(self.networkRef))",message="exactly one of the fields in [ipBlock networkRef] must be set"
//
//nolint:godoclint
type SmartSwitchNetworkDestination struct {
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MinItems=1
	IPBlock []NetworkObjectGroupSpec `json:"ipBlock,omitempty"`

	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MinItems=1
	NetworkRef []NetworkObjectGroupRef `json:"networkRef,omitempty"`

	// ProtoPorts is an optional field to specify protocols and ports for a
	// policy rule. The policy rule applies to the cross product of IPBlock
	// and ProtoPorts.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	ProtoPorts []SmartSwitchProtocolPort `json:"protoPorts"`
}

// SmartSwitchNetworkPolicyRule specifies the action for a source and
// destination pair. The cross product of the source and destination is
// used to calculate the rules created in the datapath. A description is
// optional and informational only; it is exported with any statistics and
// or events related to the rule, but is not actually used otherwise in
// the datapath.
type SmartSwitchNetworkPolicyRule struct {
	// +kubebuilder:validation:Optional
	Description string `json:"description,omitempty"`
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum=allow;deny
	Action string `json:"action"`
	// +kubebuilder:validation:Required
	Source SmartSwitchNetworkSource `json:"source"`
	// +kubebuilder:validation:Required
	Destination SmartSwitchNetworkDestination `json:"destination"`
}

//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package v1alpha1

import (
	ciliumio "github.com/isovalent/ipa/k8s/apis/cilium.io"
	slimv1 "github.com/isovalent/ipa/k8s/slim/k8s/apis/meta/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// Tetragon Network Policy (TNP)

	// TNPPluralName is the plural name of Cilium Tracing Policy
	TNPPluralName = "tetragonnetworkpolicies"

	// TPKindDefinition is the kind name of Cilium Tracing Policy
	TNPKindDefinition = "TetragonNetworkPolicy"

	// TPName is the full name of Cilium Egress NAT Policy
	TNPName = TNPPluralName + "." + ciliumio.GroupName

	// TPNamespacedPluralName is the plural name of Cilium Tracing Policy
	TNPNamespacedPluralName = "tetragonnetworkpoliciesnamespaced"

	// TPNamespacedName
	TNPNamespacedName = TNPNamespacedPluralName + "." + ciliumio.GroupName

	// TPKindDefinition is the kind name of Cilium Tracing Policy
	TNPNamespacedKindDefinition = "TetragonNetworkPolicyNamespaced"
)

// Annotations
const (
	// AnnotationStaging marks the network policy as a staging policy that is validated, but
	// not deployed. If the value is non-empty then the changes are validated as a difference
	// against the named policy with unchanged rules ignored.
	AnnotationStaging = TNPName + "/" + "staging"

	// AnnotationValidation holds the validation results for a staging policy.
	AnnotationValidation = TNPName + "/" + "validation"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type TetragonNetworkPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []TetragonNetworkPolicy `json:"items,omitempty"`
}

// +genclient
// +genclient:noStatus
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={tetragon},singular="tetragonnetworkpolicy",path="tetragonnetworkpolicies",scope="Cluster",shortName={tgnp}
type TetragonNetworkPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`
	// network policy specification
	Spec NetworkPolicySpec `json:"spec"`
}

// Implement crdutils.CRDObject interface, required for working with CRDs
// outside of Kubernetes context.
func (tgnp *TetragonNetworkPolicy) GetObjectMetaStruct() *metav1.ObjectMeta {
	return &tgnp.ObjectMeta
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type TetragonNetworkPolicyNamespacedList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []TetragonNetworkPolicyNamespaced `json:"items,omitempty"`
}

// +genclient
// +genclient:noStatus
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={tetragon},singular="tetragonnetworkpolicynamespaced",path="tetragonnetworkpoliciesnamespaced",scope="Namespaced",shortName={tgnpn}
type TetragonNetworkPolicyNamespaced struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`
	// network policy specification
	Spec NetworkPolicySpec `json:"spec"`
}

// Implement crdutils.CRDObject interface, required for working with CRDs
// outside of Kubernetes context.
func (tgnpn *TetragonNetworkPolicyNamespaced) GetObjectMetaStruct() *metav1.ObjectMeta {
	return &tgnpn.ObjectMeta
}

type NetworkDestinationCIDR struct {
	// +kubebuilder:validation:Required
	CIDR string `json:"cidr"`
}

type NetworkDestinationWorkload struct {
	// +kubebuilder:validation:Optional
	Namespace string `json:"namespace,omitempty"`
	// +kubebuilder:validation:Optional
	Name string `json:"workload,omitempty"`
	// +kubebuilder:validation:Optional
	Kind string `json:"workloadKind,omitempty"`
}

type NetworkDestinationPorts struct {
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Enum=TCP
	// +kubebuilder:default=TCP
	// Protocol is the OSI L4 transport protocol.
	Protocol string `json:"protocol"`
	// +kubebuilder:validation:Optional
	// +listType=set
	// +kubebuilder:validation:items:Minimum=1
	// +kubebuilder:validation:items:Maximum=65535
	// Ports is a list of port numbers (1-65535)
	Ports []uint32 `json:"ports,omitempty"`
}

type ServiceSelector struct {
	// +kubebuilder:validation:Required
	// Name is the name of the Kubernetes Service.
	Name string `json:"name"`
	// +kubebuilder:validation:Optional
	// Namespace is the namespace of the Service. If empty, defaults to "default"
	// for cluster-scoped policies or the policy's namespace for namespaced policies.
	Namespace string `json:"namespace,omitempty"`
}

type NetworkDestination struct {
	// +kubebuilder:validation:Optional
	// FQDN (Fully Qualified Domain Name) is a list of domain names to
	// describe a destination.
	FQDN []string `json:"FQDN,omitempty"`
	// +kubebuilder:validation:Optional
	// IPBlock contains a CIDR describing a range of IPv4/IPv6 addresses.
	IPBlock *NetworkDestinationCIDR `json:"ipBlock,omitempty"`
	// +kubebuilder:validation:Optional
	// PodSelector selects pods that this policy applies to.
	PodSelector *slimv1.LabelSelector `json:"podSelector,omitempty"`
	// +kubebuilder:validation:Optional
	// ServiceSelector selects Kubernetes Services to which this policy applies to.
	ServiceSelector *ServiceSelector `json:"serviceSelector,omitempty"`
	// +kubebuilder:validation:Optional
	// Workload is a Kubernetes application defined in the application model format.
	Workload NetworkDestinationWorkload `json:"workload,omitempty"`
	// +kubebuilder:validation:Required
	// Ports contains ports numbers and protocols.
	Ports NetworkDestinationPorts `json:"ports"`
}

type NetworkPolicyRule struct {
	// +kubebuilder:validation:Required
	// Description to explain the rule's purpose.
	Description string `json:"description"`
	// +kubebuilder:validation:Enum=connect
	// +kubebuilder:default=connect
	// Hook configures how the policy is applied in the datapath.
	Hook string `json:"hook"`
	// +kubebuilder:validation:Enum=allow;deny
	// Action is the action to enforce on the network traffic that matches
	// the destinations list.
	Action string `json:"action"`
	// +kubebuilder:validation:Optional
	// Destination is a list of destinations on which to apply the rule
	// action. The action is applied to each entry in the list.
	Destination []NetworkDestination `json:"destination,omitempty"`
}

type NetworkPolicySpec struct {
	// +kubebuilder:validation:Optional
	// NamespaceSelector applies the policy to a Kubernetes namespace
	NamespaceSelector *slimv1.LabelSelector `json:"namespaceSelector,omitempty"`
	// +kubebuilder:validation:Optional
	// PodSelector selects pods that this policy applies to.
	PodSelector *slimv1.LabelSelector `json:"podSelector,omitempty"`
	// +kubebuilder:validation:Optional
	// ProcessSelector selects processes that this policy applies to.
	ProcessSelector *BinarySelector `json:"processSelector,omitempty"`
	// +kubebuilder:validation:Enum=allow;deny
	// DefaultAction is the action to enforce on all network traffic that
	// doesn't match the selectors and the rules.
	DefaultAction string `json:"defaultAction"`
	// Network Policy Spec defines a set of actions for network operations
	// Rules is a list of network policy rules to apply to the traffic that
	// matches the source selectors.
	Rules []NetworkPolicyRule `json:"rules,omitempty"`
}

type BinarySelector struct {
	// +kubebuilder:validation:Enum=In
	// Filter operation.
	Operator string `json:"operator"`
	// Value to compare the argument against.
	Values []string `json:"values"`
	// In addition to binaries, match children processes of specified binaries.
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=false
	FollowChildren bool `json:"followChildren"`
}

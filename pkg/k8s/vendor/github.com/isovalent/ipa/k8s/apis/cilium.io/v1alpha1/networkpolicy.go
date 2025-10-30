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
	slimv1 "github.com/cilium/tetragon/pkg/k8s/slim/k8s/apis/meta/v1"
	ciliumio "github.com/isovalent/ipa/k8s/apis/cilium.io"
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
	// Tracing policy specification.
	Spec NetworkPolicySpec `json:"spec"`
}

// Implement crdutils.CRDObject interface, required for working with CRDs
// outside of Kubernetes context.
func (tgnpn *TetragonNetworkPolicyNamespaced) GetObjectMetaStruct() *metav1.ObjectMeta {
	return &tgnpn.ObjectMeta
}

type LogicalNetworkSelector struct {
	// +kubebuilder:validation:Optional
	VRF string `json:"vrf"`
	// +kubebuilder:validation:Optional
	VLAN uint32 `json:"vlan"`
}

type NetworkDestinationCIDR struct {
	// +kubebuilder:validation:Required
	CIDR string `json:"cidr"`
}

type NetworkDestinationLabels struct {
	// +kubebuilder:validation:Optional
	MatchLabels map[string]string `json:"matchLabels,omitempty" protobuf:"bytes,1,rep,name=matchLabels"`
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
	// +kubebuilder:validation:Enum=TCP;UDP
	// +kubebuilder:default=TCP
	Protocol string `json:"protocol"`
	// +kubebuilder:validation:Optional
	Ports []uint32 `json:"ports,omitempty"`
}

type NetworkSource struct {
	// +kubebuilder:validation:Optional
	IPBlock *NetworkDestinationCIDR `json:"ipBlock,omitempty"`
	// +kubebuilder:validation:Required
	Ports NetworkDestinationPorts `json:"ports"`
}

type NetworkDestination struct {
	// +kubebuilder:validation:Optional
	FQDN []string `json:"FQDN,omitempty"`
	// +kubebuilder:validation:Optional
	IPBlock *NetworkDestinationCIDR `json:"ipBlock,omitempty"`
	// +kubebuilder:validation:Optional
	// PodSelector selects pods that this policy applies to
	PodSelector *slimv1.LabelSelector `json:"podSelector,omitempty"`
	// +kubebuilder:validation:Optional
	Workload NetworkDestinationWorkload `json:"workload,omitempty"`
	// +kubebuilder:validation:Required
	Ports NetworkDestinationPorts `json:"ports"`
}

type NetworkPolicyRule struct {
	// +kubebuilder:validation:Required
	Description string `json:"description"`
	// +kubebuilder:validation:Enum=connect;listen;firewall
	Hook string `json:"hook"`
	// +kubebuilder:validation:Enum=allow;deny
	Action string `json:"action"`
	// +kubebuilder:validation:Optional
	Source []NetworkSource `json:"source,omitempty"`
	// +kubebuilder:validation:Optional
	Destination []NetworkDestination `json:"destination,omitempty"`
}

type NetworkPolicySpec struct {
	// +kubebuilder:validation:Optional
	// LogicalNetworkSelector selects logical network that this policy applies to
	LogicalNetworkSelector *LogicalNetworkSelector `json:"logicalNetworkSelector,omitempty"`
	// +kubebuilder:validation:Optional
	// NamespaceSelector selects namespace that this policy applies to
	NamespaceSelector *slimv1.LabelSelector `json:"namespaceSelector,omitempty"`
	// +kubebuilder:validation:Optional
	// PodSelector selects pods that this policy applies to
	PodSelector *slimv1.LabelSelector `json:"podSelector,omitempty"`
	// +kubebuilder:validation:Optional
	// ProcessSelector selects process that this policy applies to
	ProcessSelector *BinarySelector `json:"processSelector,omitempty"`
	// +kubebuilder:validation:Enum=allow;deny
	DefaultAction string `json:"defaultAction"`
	// Network Policy Spec defines a set of actions for network operations
	Rules []NetworkPolicyRule `json:"rules,omitempty"`
}

type BinarySelector struct {
	// +kubebuilder:validation:Enum=In;NotIn;Prefix;NotPrefix;Postfix;NotPostfix
	// Filter operation.
	Operator string `json:"operator"`
	// Value to compare the argument against.
	Values []string `json:"values"`
	// In addition to binaries, match children processes of specified binaries.
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=false
	FollowChildren bool `json:"followChildren"`
}

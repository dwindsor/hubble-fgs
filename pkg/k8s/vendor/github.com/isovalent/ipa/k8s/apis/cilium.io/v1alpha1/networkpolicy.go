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

	ciliumio "github.com/isovalent/ipa/k8s/apis/cilium.io"
	slimv1 "github.com/isovalent/ipa/k8s/slim/k8s/apis/meta/v1"
)

const (
	// Tetragon Network Policy (TNP).

	// TNPPluralName is the plural name of Tetragon Network Policy.
	TNPPluralName = "tetragonnetworkpolicies"

	// TNPKindDefinition is the kind name of Tetragon Network Policy.
	TNPKindDefinition = "TetragonNetworkPolicy"

	// TNPName is the full name of Tetragon Network Policy.
	TNPName = TNPPluralName + "." + ciliumio.GroupName

	// TNPNamespacedPluralName is the plural name of namespaced TNP.
	TNPNamespacedPluralName = "tetragonnetworkpoliciesnamespaced"

	// TNPNamespacedName is the full name of namespaced TNP.
	TNPNamespacedName = TNPNamespacedPluralName + "." + ciliumio.GroupName

	// TNPNamespacedKindDefinition is the kind name of namespaced TNP.
	TNPNamespacedKindDefinition = "TetragonNetworkPolicyNamespaced"
)

// Annotations.
const (
	// AnnotationStaging marks the network policy as a staging policy
	// that is validated, but not deployed. If the value is non-empty
	// then the changes are validated as a difference against the named
	// policy with unchanged rules ignored.
	AnnotationStaging = TNPName + "/" + "staging"

	// AnnotationValidation holds the validation results for a staging
	// policy.
	AnnotationValidation = TNPName + "/" + "validation"
)

// TetragonNetworkPolicyList is a list of TetragonNetworkPolicy resources.
//
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type TetragonNetworkPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []TetragonNetworkPolicy `json:"items,omitempty"`
}

// TetragonNetworkPolicy is a cluster-scoped network policy resource.
//
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

// GetObjectMetaStruct implements crdutils.CRDObject interface, required
// for working with CRDs outside of Kubernetes context.
func (tgnp *TetragonNetworkPolicy) GetObjectMetaStruct() *metav1.ObjectMeta {
	return &tgnp.ObjectMeta
}

// TetragonNetworkPolicyNamespacedList is a list of
// TetragonNetworkPolicyNamespaced resources.
//
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type TetragonNetworkPolicyNamespacedList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []TetragonNetworkPolicyNamespaced `json:"items,omitempty"`
}

// TetragonNetworkPolicyNamespaced is a namespace-scoped network policy
// resource.
//
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

// GetObjectMetaStruct implements crdutils.CRDObject interface, required
// for working with CRDs outside of Kubernetes context.
func (tgnpn *TetragonNetworkPolicyNamespaced) GetObjectMetaStruct() *metav1.ObjectMeta {
	return &tgnpn.ObjectMeta
}

// NetworkDestinationCIDR defines a CIDR block for network destinations.
type NetworkDestinationCIDR struct {
	// +kubebuilder:validation:Required
	CIDR string `json:"cidr"`
}

// NetworkDestinationWorkload defines a workload-based destination selector.
type NetworkDestinationWorkload struct {
	// +kubebuilder:validation:Optional
	Namespace string `json:"namespace,omitempty"`
	// +kubebuilder:validation:Optional
	Name string `json:"workload,omitempty"`
	// +kubebuilder:validation:Optional
	Kind string `json:"workloadKind,omitempty"`
}

// NetworkDestinationPorts defines port and protocol specifications.
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

// ServiceSelector selects Kubernetes Services by name and namespace.
type ServiceSelector struct {
	// +kubebuilder:validation:Required
	// Name is the name of the Kubernetes Service.
	Name string `json:"name"`
	// +kubebuilder:validation:Optional
	// Namespace is the namespace of the Service. If empty, defaults to "default"
	// for cluster-scoped policies or the policy's namespace for namespaced policies.
	Namespace string `json:"namespace,omitempty"`
}

// NetworkDestination defines a destination endpoint for network policy rules.
//
// +kubebuilder:validation:XValidation:rule="!has(self.nodeSelector) || (!has(self.FQDN) && !has(self.ipBlock) && !has(self.serviceSelector) && !has(self.workload) && !has(self.podSelector))",message="nodeSelector must be used standalone and cannot be combined with FQDN, ipBlock, serviceSelector, workload, or podSelector"
type NetworkDestination struct {
	// +kubebuilder:validation:Optional
	// FQDN (Fully Qualified Domain Name) is a list of domain names to
	// describe a destination.
	FQDN []string `json:"FQDN,omitempty"`
	// +kubebuilder:validation:Optional
	// IPBlock contains a CIDR describing a range of IPv4/IPv6 addresses.
	IPBlock *NetworkDestinationCIDR `json:"ipBlock,omitempty"`
	// +kubebuilder:validation:Optional
	// NodeSelector selects destination nodes for this rule.
	// Matches connections to nodes (such as VM acting as a TetragonNode or Kubernetes Node), and does not match connections to Pods.
	// Cannot be combined with FQDN, ipBlock, serviceSelector, workload, or podSelector.
	// For pod-based policies, use spec.nodeSelector or pod labels instead.
	NodeSelector *slimv1.LabelSelector `json:"nodeSelector,omitempty"`
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

// NetworkPolicyRule defines a single network policy rule with action and
// destinations.
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

// NetworkPolicySpec defines the specification for a Tetragon Network Policy.
//
// Selector Semantics:
// All selector fields at the spec level are combined using AND logic to
// determine where and what the policy monitors:
//   - NodeSelector AND NamespaceSelector AND PodSelector AND ProcessSelector
//   - An empty/nil selector field means "no constraint" (matches all)
//   - If ALL selector fields are empty, the policy applies to all traffic
//     on all nodes
//
// Source Selection (spec level):
//   - spec.nodeSelector: Selects which nodes the policy is applied
//   - spec.namespaceSelector: Selects which namespaces to apply
//   - spec.podSelector: Selects which pods within those namespaces to apply
//   - spec.processSelector: Selects which processes within those pods to apply
//
// Destination Selection (rule level):
//   - See NetworkDestination documentation for destination matching semantics
type NetworkPolicySpec struct {
	// +kubebuilder:validation:Optional
	// NodeSelector selects which nodes this policy is enforced on.
	// Empty/nil means the policy applies to all nodes in the cluster.
	// This determines where policy enforcement occurs, not what traffic is matched.
	// Combined with other spec-level selectors using AND logic.
	NodeSelector *slimv1.LabelSelector `json:"nodeSelector,omitempty"`
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

// BinarySelector selects processes by binary path with optional child
// process matching.
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

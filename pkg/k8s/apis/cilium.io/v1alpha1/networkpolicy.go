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
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

type NetworkDestinationFQDN struct {
	// +kubebuilder:validation:Required
	Fqdn []string `json:"fqdn"`
}

type NetworkDestinationCIDR struct {
	// +kubebuilder:validation:Required
	CIDR []string `json:"cidr"`
}

type NetworkDestinationLabels struct {
	// +kubebuilder:validation:Required
	MatchLabels []string `json:"matchLabels"`
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

type NetworkDestination struct {
	// +kubebuilder:validation:Optional
	FQDN NetworkDestinationFQDN `json:"FQDN,omitempty"`
	// +kubebuilder:validation:Optional
	CIDR NetworkDestinationCIDR `json:"CIDR,omitempty"`
	// +kubebuilder:validation:Optional
	Labels NetworkDestinationLabels `json:"labels,omitempty"`
	// +kubebuilder:validation:Optional
	Workload NetworkDestinationWorkload `json:"workload,omitempty"`
	// +kubebuilder:validation:Required
	Ports NetworkDestinationPorts `json:"ports"`
	// +kubebuilder:validation:Required
	Action string `json:"action"`
}

type NetworkPolicyRule struct {
	// +kubebuilder:validation:Enum=connect;listen
	Hook string `json:"hook"`
	// +kubebuilder:validation:Enum=allow;deny
	DefaultAction string `json:"action"`
	// +kubebuilder:validation:Optional
	Destination []NetworkDestination `json:"destination,omitempty"`
}

type NetworkPolicySpec struct {
	// +kubebuilder:validation:Optional
	// PodSelector selects pods that this policy applies to
	PodSelector *slimv1.LabelSelector `json:"podSelector,omitempty"`

	// Network Policy Spec defines a set of actions for network operations
	Rules []NetworkPolicyRule `json:"rules,omitempty"`
}

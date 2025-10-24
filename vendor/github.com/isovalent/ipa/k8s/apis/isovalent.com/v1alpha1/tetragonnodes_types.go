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

type AddressType string

const (
	NodeHostName    AddressType = "Hostname"
	NodeExternalIP  AddressType = "ExternalIP"
	NodeInternalIP  AddressType = "InternalIP"
	NodeExternalDNS AddressType = "ExternalDNS"
	NodeInternalDNS AddressType = "InternalDNS"
)

type TetragonEnforcementPointSpec struct {
}

// NodeAddress is a node address.
type NodeAddress struct {
	// Type is the type of the node address
	Type AddressType `json:"type,omitempty"`

	// IP is an IP of a node
	IP string `json:"ip,omitempty"`
}

// TetragonNodeStatus defines the observed state of TetragonNode.
type TetragonNodeStatus struct {
	// Id is the identifier of the node. This is different from the
	// node name which is typically the FQDN of the node. The Id
	// typically refers to the identifier used by the cloud provider or
	// some other means of identification.
	Id string `json:"id,omitempty"`

	// Addresses is the list of all node addresses.
	//
	// +kubebuilder:validation:Optional
	Addresses []NodeAddress `json:"addresses,omitempty"`

	// SoftwareVersion is the Tetragon version running on this device.
	SoftwareVersion string `json:"software_version,omitempty"`

	// Conditions represents the latest available observations of a
	// node's current state.
	// +listType=map
	// +listMapKey=type
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=8
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// TetragonNode is the Schema for the TetragonNodes API
type TetragonNode struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty,omitzero"`

	// status defines the observed state of TetragonNode
	// +optional
	Status TetragonNodeStatus `json:"status,omitempty,omitzero"`
}

// Implement crdutils.CRDObject interface, required for working with CRDs
// outside of Kubernetes context.
func (tn *TetragonNode) GetObjectMetaStruct() *metav1.ObjectMeta {
	return &tn.ObjectMeta
}

// +kubebuilder:object:root=true

// TetragonNodeList contains a list of TetragonNode
type TetragonNodeList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []TetragonNode `json:"items"`
}

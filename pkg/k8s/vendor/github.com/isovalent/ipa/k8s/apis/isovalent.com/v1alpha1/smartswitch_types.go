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
	isovalentcom "github.com/isovalent/ipa/k8s/apis/isovalent.com"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// SmartSwitch

	// SmartSwitchPluralName is the plural name of SmartSwitch
	SmartSwitchPluralName = "smartswitches"

	// SmartSwitchKindDefinition is the kind name of SmartSwitch
	SmartSwitchKindDefinition = "SmartSwitch"

	// SmartSwitchName is the full name of SmartSwitch
	SmartSwitchName = SmartSwitchPluralName + "." + isovalentcom.GroupName
)

// +kubebuilder:object:root=true

// SmartSwitchList contains a list of SmartSwitch
type SmartSwitchList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SmartSwitch `json:"items"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope="Namespaced"
// +kubebuilder:subresource:status

// SmartSwitch is the Schema used by smart switches to register themselves
// with the on-prem Kubernetes control plane. The registration is a one-time
// operation that happens when the software on the smart switch starts up.
type SmartSwitch struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty,omitzero"`

	// status defines the observed state of SmartSwitch
	// +optional
	Status SmartSwitchStatus `json:"status,omitempty,omitzero"`
}

// Implement crdutils.CRDObject interface, required for working with CRDs
// outside of Kubernetes context.
func (s *SmartSwitch) GetObjectMetaStruct() *metav1.ObjectMeta {
	return &s.ObjectMeta
}

type DPUStatus struct {
	// ID of the DPU that is unique within the SmartSwitch.
	ID string `json:"id,omitempty"`
	// ManagementIP is the management IP address of this DPU.
	ManagementIP string `json:"managementIP,omitempty"`
	// PortLow is the low end of the port range assigned to this DPU.
	PortLow uint16 `json:"portLow,omitempty"`
	// PortHigh is the high end of the port range assigned to this DPU.
	PortHigh uint16 `json:"portHigh,omitempty"`
	// HardwareModel is the DPU hardware model (e.g. "Elba", "Giglio").
	HardwareModel string `json:"hardwareModel,omitempty"`
	// SoftwareVersion is the version of the software running on this DPU.
	SoftwareVersion string `json:"softwareVersion,omitempty"`
}

// SmartSwitchStatus defines the observed state of SmartSwitch.
type SmartSwitchStatus struct {
	// ServiceIP is the service IP address of the SmartSwitch.
	ServiceIP string `json:"serviceIP,omitempty"`
	// ServiceMAC is the service MAC address of the SmartSwitch.
	ServiceMAC string `json:"serviceMAC,omitempty"`
	// BiosVersion is the BIOS version of the SmartSwitch.
	BiosVersion string `json:"biosVersion,omitempty,omitzero"`
	// SerialNumber is the serial number of the SmartSwitch.
	SerialNumber string `json:"serialNumber,omitempty,omitzero"`
	// SoftwareVersion is the version of the agent software running on this
	// SmartSwitch which reports SmartSwitchStatus.
	SoftwareVersion string `json:"softwareVersion,omitempty,omitzero"`
	// DPUStatuses is the statuses of DPUs associated with this SmartSwitch.
	DPUStatuses []DPUStatus `json:"dpuStatuses,omitempty,omitzero"`
}

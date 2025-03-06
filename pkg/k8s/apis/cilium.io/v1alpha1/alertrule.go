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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type AlertRuleList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []AlertRule `json:"items,omitempty"`
}

// +genclient
// +genclient:noStatus
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={tetragon},singular="alertrule",path="alertrules",scope="Cluster",shortName={tgar}
type AlertRule struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`
	Spec              AlertRuleSpec `json:"spec"`
}

// Implement crdutils.CRDObject interface, required for working with CRDs
// outside of Kubernetes context.
func (ar *AlertRule) GetObjectMetaStruct() *metav1.ObjectMeta {
	return &ar.ObjectMeta
}

type AlertRuleSpec struct {
	// CEL expression
	// +kubebuilder:validation:Required
	Expression string `json:"expression"`

	// +kubebuilder:validation:Enum=critical;warning;info
	// +kubebuilder:default=info
	Severity string `json:"severity"`

	// Message to inform the user what is going on. Max 256 characters.
	// It has similar purpose as the message field in kprobe, tracepoint, etc
	// fields in generic TracingPolicy.
	// +kubebuilder:validation:MaxLength=256
	// +kubebuilder:validation:Optional
	Message string `json:"message,omitempty"`

	// Tags to categorize the alert. Max 16 tags are supported.
	// It has similar purpose as the tags field in kprobe, tracepoint, etc
	// fields in generic TracingPolicy.
	// +kubebuilder:validation:MaxItems=16
	// +listType=set
	// +kubebuilder:validation:Optional
	Tags []string `json:"tags,omitempty"`
}

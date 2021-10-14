//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.
//

package v1alpha1

import (
	isovalentcom "github.com/isovalent/hubble-fgs/pkg/k8s/apis/isovalent.com"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// Tracing Policy (TP)

	// TPSingularName is the singular name of Cilium Egress NAT Policy
	TPSingularName = "tracingpolicy"

	// TPPluralName is the plural name of Cilium Egress NAT Policy
	TPPluralName = "tracingpolicies"

	// TPKindDefinition is the kind name of Cilium Egress NAT Policy
	TPKindDefinition = "TracingPolicy"

	// TPName is the full name of Cilium Egress NAT Policy
	TPName = TPPluralName + "." + isovalentcom.GroupName
)

// +genclient
// +genclient:noStatus
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:singular="tracingpolicy",path="tracingpolicies",scope="Cluster",shortName={}
type TracingPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`
	// Tracing policy specification.
	Spec TracingPolicySpec `json:"spec"`
}

type TracingPolicySpec struct {
	// +kubebuilder:validation:Optional
	// A list of kprobe specs.
	KProbes []KProbeSpec `json:"kprobes"`
	// +kubebuilder:validation:Optional
	// A list of tracepoint specs.
	Tracepoints []TracepointSpec `json:"tracepoints"`
	// +kubebuilder:validation:Optional
	// Parser policy specification.
	Parser ParserPolicySpec `json:"parser"`
}

type KProbeSpec struct {
	// Name of the function to apply the kprobe spec to.
	Call string `json:"call"`
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=false
	// Indicates whether to collect return value of the traced function.
	Return bool `json:"return"`
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=true
	// Indicates whether the traced function is a syscall.
	Syscall bool `json:"syscall"`
	// +kubebuilder:validation:Optional
	// A list of function arguments to include in the trace output.
	Args []KProbeArg `json:"args"`
	// +kubebuilder:validation:Optional
	// A return argument to include in the trace output.
	ReturnArg KProbeArg `json:"returnArg"`
	// +kubebuilder:validation:Optional
	// Selectors to apply before producing trace output. Selectors are ORed.
	Selectors []KProbeSelector `json:"selectors"`
}

type KProbeArg struct {
	// +kubebuilder:validation:Minimum=0
	// Position of the argument.
	Index uint32 `json:"index"`
	// +kubebuilder:validation:Enum=int;uint32;int32;uint64;int64;char_buf;char_iovec;size_t;skb;sock;string;fd;file;filename;path;nop;
	// Argument type.
	Type string `json:"type"`
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=0
	// Specifies the position of the corresponding size argument for this argument.
	// This field is used only for char_buf and char_iovec types.
	SizeArgIndex uint32 `json:"sizeArgIndex"`
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=false
	// This field is used only for char_buf and char_iovec types.
	ReturnCopy bool `json:"returnCopy"`
}

// KProbeSelector selects function calls for kprobe based on PIDs and function arguments. The
// results of MatchPIDs and MatchArgs are ANDed.
type KProbeSelector struct {
	// +kubebuilder:validation:Optional
	// A list of process ID filters. MatchPIDs are ANDed.
	MatchPIDs []PIDSelector `json:"matchPIDs"`
	// +kubebuilder:validation:Optional
	// A list of argument filters. MatchArgs are ANDed.
	MatchArgs []ArgSelector `json:"matchArgs"`
	// +kubebuilder:validation:Optional
	// A list of actions to execute when this selector matches
	MatchActions []ActionSelector `json:"matchActions"`
}

type PIDSelector struct {
	// +kubebuilder:validation:Enum=In;NotIn
	// PID selector operator.
	Operator string `json:"operator"`
	// Process IDs to match.
	Values []uint32 `json:"values"`
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=false
	// Indicates whether PIDs are namespace PIDs.
	IsNamespacePID bool `json:"isNamespacePID"`
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=false
	// Matches any descendant processes of the matching PIDs.
	FollowForks bool `json:"followForks"`
}

type ArgSelector struct {
	// +kubebuilder:validation:Minimum=0
	// Position of the argument to apply fhe filter to.
	Index uint32 `json:"index"`
	// +kubebuilder:validation:Enum=Equal;NotEqual;Prefix;Postfix
	// Filter operation.
	Operator string `json:"operator"`
	// Value to compare the argument against.
	Values []string `json:"values"`
}

type ActionSelector struct {
	// +kubebuilder:validation:Enum=Post;FollowFD;UnfollowFD;Sigkill
	// Action to execute.
	Action string `json:"action"`
	// +kubebuilder:validation:Optional
	// An arg index for the fd for fdInstall action
	ArgFd uint32 `json:"argFd"`
	// +kubebuilder:validation:Optional
	// An arg index for the filename for fdInstall action
	ArgName uint32 `json:"argName"`
}

type TracepointSpec struct {
	// Tracepoint subsystem
	Subsystem string `json:"subsystem"`
	// Tracepoint event
	Event string `json:"event"`
	// +kubebuilder:validation:Optional
	// A list of function arguments to include in the trace output.
	Args []KProbeArg `json:"args"`
	// +kubebuilder:validation:Optional
	// Selectors to apply before producing trace output. Selectors are ORed.
	Selectors []KProbeSelector `json:"selectors"`
}

type TlsSelector struct {
	// +kubebuilder:validation:Optional
	// A list of ports to match. Ports are ORd.
	MatchPorts []uint32 `json:"matchPorts"`
}

type TlsSpec struct {
	// TLS enable parser
	Enable bool `json:"enable"`
	// +kubebuilder:default="tc"
	// +kubebuilder:validation:Enum=socket;tc;
	// TLS parser type
	Mode string `json:"mode"`
	// +kubebuilder:validation:Optional
	// Selectors to apply TLS parser against. Selectors are ORed.
	Selectors []TlsSelector `json:"selectors"`
}

type HttpSelector struct {
	// +kubebuilder:validation:Optional
	// A list of ports to match. Ports are ORd.
	MatchPorts []uint32 `json:"matchPorts"`
}

type HttpSpec struct {
	// Http enable parser
	Enable bool `json:"enable"`
	// +kubebuilder:validation:Optional
	// Selectors to apply TLS parser against. Selectors are ORed.
	Selectors []HttpSelector `json:"selectors"`
}

type ParserPolicySpec struct {
	// +kubebuilder:validation:Optional
	// A Tls specs.
	Tls TlsSpec `json:"tls"`
	// +kubebuilder:validation:Optional
	// A Http spec.
	Http HttpSpec `json:"http"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type TracingPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []TracingPolicy `json:"items"`
}

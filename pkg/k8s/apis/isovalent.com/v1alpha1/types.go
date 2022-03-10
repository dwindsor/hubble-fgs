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
	metav1.TypeMeta   `json:",inline" yaml:",inline"`
	metav1.ObjectMeta `json:"metadata" yaml:"metadata"`
	// Tracing policy specification.
	Spec TracingPolicySpec `json:"spec" yaml:"spec"`
}

type TracingPolicySpec struct {
	// +kubebuilder:validation:Optional
	// A list of kprobe specs.
	KProbes []KProbeSpec `json:"kprobes" yaml:"kprobes"`
	// +kubebuilder:validation:Optional
	// A list of tracepoint specs.
	Tracepoints []TracepointSpec `json:"tracepoints" yaml:"tracepoints"`
	// +kubebuilder:validation:Optional
	// Parser policy specification.
	Parser ParserPolicySpec `json:"parser" yaml:"parser"`
}

type KProbeSpec struct {
	// Name of the function to apply the kprobe spec to.
	Call string `json:"call" yaml:"call"`
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=false
	// Indicates whether to collect return value of the traced function.
	Return bool `json:"return" yaml:"return"`
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=true
	// Indicates whether the traced function is a syscall.
	Syscall bool `json:"syscall" yaml:"syscall"`
	// +kubebuilder:validation:Optional
	// A list of function arguments to include in the trace output.
	Args []KProbeArg `json:"args" yaml:"args"`
	// +kubebuilder:validation:Optional
	// A return argument to include in the trace output.
	ReturnArg KProbeArg `json:"returnArg" yaml:"returnArg"`
	// +kubebuilder:validation:Optional
	// Selectors to apply before producing trace output. Selectors are ORed.
	Selectors []KProbeSelector `json:"selectors" yaml:"selectors"`
}

type KProbeArg struct {
	// +kubebuilder:validation:Minimum=0
	// Position of the argument.
	Index uint32 `json:"index" yaml:"index"`
	// +kubebuilder:validation:Enum=int;uint32;int32;uint64;int64;char_buf;char_iovec;size_t;skb;sock;string;fd;file;filename;path;nop;
	// Argument type.
	Type string `json:"type" yaml:"type"`
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=0
	// Specifies the position of the corresponding size argument for this argument.
	// This field is used only for char_buf and char_iovec types.
	SizeArgIndex uint32 `json:"sizeArgIndex" yaml:"sizeArgIndex"`
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=false
	// This field is used only for char_buf and char_iovec types.
	ReturnCopy bool `json:"returnCopy" yaml:"returnCopy"`
}

type BinarySelector struct {
	// +kubebuilder:validation:Enum=In
	// Filter operation.
	Operator string `json:"operator" yaml:"operator"`
	// Value to compare the argument against.
	Values []string `json:"values" yaml:"values"`
}

// KProbeSelector selects function calls for kprobe based on PIDs and function arguments. The
// results of MatchPIDs and MatchArgs are ANDed.
type KProbeSelector struct {
	// +kubebuilder:validation:Optional
	// A list of process ID filters. MatchPIDs are ANDed.
	MatchPIDs []PIDSelector `json:"matchPIDs" yaml:"matchPIDs"`
	// +kubebuilder:validation:Optional
	// A list of argument filters. MatchArgs are ANDed.
	MatchArgs []ArgSelector `json:"matchArgs" yaml:"matchArgs"`
	// +kubebuilder:validation:Optional
	// A list of actions to execute when this selector matches
	MatchActions []ActionSelector `json:"matchActions" yaml:"matchActions"`
	// +kubebuilder:validation:Optional
	// A list of argument filters. MatchArgs are ANDed.
	MatchReturnArgs []ArgSelector `json:"matchReturnArgs" yaml:"matchReturnArgs"`
	// +kubebuilder:validation:Optional
	// A list of binary exec name filters.
	MatchBinaries []BinarySelector `json:"matchBinaries" yaml:"matchBinaries"`
	// +kubebuilder:validation:Optional
	// A list of namespaces and IDs
	MatchNamespaces []NamespaceSelector `json:"matchNamespaces" yaml:"matchNamespaces"`
	// +kubebuilder:validation:Optional
	// IDs for namespace changes
	MatchNamespaceChanges []NamespaceChangesSelector `json:"matchNamespaceChanges" yaml:"matchNamespaceChanges"`
	// +kubebuilder:validation:Optional
	// A list of capabilities and IDs
	MatchCapabilities []CapabilitiesSelector `json:"matchCapabilities" yaml:"matchCapabilities"`
}

type NamespaceChangesSelector struct {
	// +kubebuilder:validation:Enum=In;NotIn
	// Namespace selector operator.
	Operator string `json:"operator" yaml:"operator"`
	// +kubebuilder:validation:Enum=Uts;Ipc;Mnt;Pid;PidForChildren;Net;Time;TimeForChildren;Cgroup;User
	// Process IDs to match.
	Values []string `json:"values" yaml:"values"`
}

type NamespaceSelector struct {
	// +kubebuilder:validation:Enum=Uts;Ipc;Mnt;Pid;PidForChildren;Net;Time;TimeForChildren;Cgroup;User
	// Namespace selector name.
	Namespace string `json:"namespace" yaml:"namespace"`
	// +kubebuilder:validation:Enum=In;NotIn
	// Namespace selector operator.
	Operator string `json:"operator" yaml:"operator"`
	// Process IDs to match.
	Values []string `json:"values" yaml:"values"`
}

type CapabilitiesSelector struct {
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Enum=Effective;Inheritable;Permitted
	// +kubebuilder:default=Effective
	// Type of capabilities
	Type string `json:"type" yaml:"type"`
	// +kubebuilder:validation:Enum=In;NotIn
	// Namespace selector operator.
	Operator string `json:"operator" yaml:"operator"`
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=false
	// Indicates whether these caps are namespace caps.
	IsNamespaceCapability bool `json:"isNamespaceCapability" yaml:"isNamespaceCapability"`
	// Capabilities to match.
	Values []string `json:"values" yaml:"values"`
}

type PIDSelector struct {
	// +kubebuilder:validation:Enum=In;NotIn
	// PID selector operator.
	Operator string `json:"operator" yaml:"operator"`
	// Process IDs to match.
	Values []uint32 `json:"values" yaml:"values"`
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=false
	// Indicates whether PIDs are namespace PIDs.
	IsNamespacePID bool `json:"isNamespacePID" yaml:"isNamespacePID"`
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=false
	// Matches any descendant processes of the matching PIDs.
	FollowForks bool `json:"followForks" yaml:"followForks"`
}

type ArgSelector struct {
	// +kubebuilder:validation:Minimum=0
	// Position of the argument to apply fhe filter to.
	Index uint32 `json:"index" yaml:"index"`
	// +kubebuilder:validation:Enum=Equal;NotEqual;Prefix;Postfix
	// Filter operation.
	Operator string `json:"operator" yaml:"operator"`
	// Value to compare the argument against.
	Values []string `json:"values" yaml:"values"`
}

type ActionSelector struct {
	// +kubebuilder:validation:Enum=Post;FollowFD;UnfollowFD;Sigkill
	// Action to execute.
	Action string `json:"action" yaml:"action"`
	// +kubebuilder:validation:Optional
	// An arg index for the fd for fdInstall action
	ArgFd uint32 `json:"argFd" yaml:"argFd"`
	// +kubebuilder:validation:Optional
	// An arg index for the filename for fdInstall action
	ArgName uint32 `json:"argName" yaml:"argName"`
}

type TracepointSpec struct {
	// Tracepoint subsystem
	Subsystem string `json:"subsystem" yaml:"subsystem"`
	// Tracepoint event
	Event string `json:"event" yaml:"event"`
	// +kubebuilder:validation:Optional
	// A list of function arguments to include in the trace output.
	Args []KProbeArg `json:"args" yaml:"args"`
	// +kubebuilder:validation:Optional
	// Selectors to apply before producing trace output. Selectors are ORed.
	Selectors []KProbeSelector `json:"selectors" yaml:"selectors"`
}

type TlsSelector struct {
	// +kubebuilder:validation:Optional
	// A list of ports to match. Ports are ORd.
	MatchPorts []uint32 `json:"matchPorts" yaml:"matchPorts"`
}

type TlsSpec struct {
	// TLS enable parser
	Enable bool `json:"enable" yaml:"enable"`
	// +kubebuilder:default="tc"
	// +kubebuilder:validation:Enum=socket;tc;
	// TLS parser type
	Mode string `json:"mode" yaml:"mode"`
	// +kubebuilder:validation:Optional
	// Selectors to apply TLS parser against. Selectors are ORed.
	Selectors []TlsSelector `json:"selectors" yaml:"selectors"`
}

type HttpsSelector struct {
	// +kubebuilder:validation:Optional
	// A list of ports to match. Ports are ORd.
	MatchPorts []uint32 `json:"matchPorts" yaml:"matchPorts"`
}

type HttpsSpec struct {
	// HTTPS enable parser
	Enable bool `json:"enable" yaml:"enable"`
	// +kubebuilder:validation:Optional
	// Selectors to apply TLS parser against. Selectors are ORed.
	Selectors []HttpsSelector `json:"selectors" yaml:"selectors"`
}

type HttpSelector struct {
	// +kubebuilder:validation:Optional
	// A list of ports to match. Ports are ORd.
	MatchPorts []uint32 `json:"matchPorts" yaml:"matchPorts"`
}

type HttpSpec struct {
	// Http enable parser
	Enable bool `json:"enable" yaml:"enable"`
	// +kubebuilder:validation:Optional
	// Selectors to apply TLS parser against. Selectors are ORed.
	Selectors []HttpSelector `json:"selectors" yaml:"selectors"`
}

type InterfacePolicySpec struct {
	// Interface enable parser
	Enable bool `json:"enable" yaml:"enable"`
	// +kubebuilder:validation:Optional
	// Interface interval in seconds
	StatsInterval uint32 `json:"statsInterval" yaml:"statsInterval"`
}

type DnsPolicySpec struct {
	// DNS enable parser
	Enable bool `json:"enable" yaml:"enable"`
	// +kubebuilder:validation:Optional
	// A list of DNS ports
	Ports []uint16 `json:"ports" yaml:"ports"`
}

type NopSelector struct {
	// +kubebuilder:validation:Optional
	// A list of ports to match. Ports are ORd.
	MatchPorts []uint32 `json:"matchPorts" yaml:"matchPorts"`
}

type NopSpec struct {
	// Nop enable parser
	Enable bool `json:"enable" yaml:"enable"`
	// +kubebuilder:validation:Optional
	// Selectors to apply Nop parser against. Selectors are ORed.
	Selectors []NopSelector `json:"selectors" yaml:"selectors"`
}

type ParserPolicySpec struct {
	// +kubebuilder:validation:Optional
	// A Tls specs.
	Tls TlsSpec `json:"tls" yaml:"tls"`
	// +kubebuilder:validation:Optional
	// A Tls specs.
	Https HttpsSpec `json:"https" yaml:"https"`
	// +kubebuilder:validation:Optional
	// A Http spec.
	Http HttpSpec `json:"http" yaml:"http"`
	// +kubebuilder:validation:Optional
	// UDP policy specification
	Udp UdpPolicySpec `json:"udp" yaml:"udp"`
	// +kubebuilder:validation:Optional
	// Network policy specification
	Interface InterfacePolicySpec `json:"interface" yaml:"interface"`
	// +kubebuilder:validation:Optional
	// Network policy specification
	Dns DnsPolicySpec `json:"dns" yaml:"dns"`
	// +kubebuilder:validation:Optional
	// Network policy specification
	Nop NopSpec `json:"nop" yaml:"nop"`
	// +kubebuilder:validation:Optional
	// TCP policy specification
	Tcp TcpPolicySpec `json:"tcp" yaml:"tcp"`
	// +kubebuilder:validation:Optional
}

type TcpPolicySpec struct {
	// Enable TCP statistics
	Enable bool `json:"enable" yaml:"enable"`
	// +kubebuilder:validation:Optional
	// Configures the Stat collection interval in seconds
	StatsInterval uint32 `json:"statsInterval" yaml:"statsInterval"`
}

type UdpPolicySpec struct {
	// Enable UDP observability
	Enable bool `json:"enable" yaml:"enable"`
	// +kubebuilder:default=true
	// +kubebuilder:validation:Optional
	// UDP has two modes one for newer kernels (cgroup) and then an
	// older fallback mode for kprobe use cases. Allow running older
	// kprobe version on newer kernels by setting cgroup knob to false.
	Cgroup bool `json:"cgroup" yaml:"cgroup"`
	// +kubebuilder:validation:Optional
	// Configures the Stat collection interval in seconds
	StatsInterval uint32 `json:"statsInterval" yaml:"statsInterval"`
	// +kubebuilder:validation:Optional
	// Configure socket idle time to delete sockets in seconds
	DeleteIdleSocketInterval uint32 `json:"deleteIdleSocketInterval" yaml:"deleteIdleSocketInterval"`
	// +kubebuilder:validation:Optional
	// Network policy specification
	Burst UdpBurstPolicySpec `json:"burst" yaml:"burst"`
}

type UdpBurstPolicySpec struct {
	// Enable UDP burst observability
	// +kubebuilder:default=false
	// +kubebuilder:validation:Optional
	Enable bool `json:"enable" yaml:"enable"`
	// +kubebuilder:default=1000
	// +kubebuilder:validation:Optional
	// Configures the burst window size in milliseconds
	WindowSize uint32 `json:"windowSize" yaml:"windowSize"`
	// +kubebuilder:default=100
	// +kubebuilder:validation:Optional
	// Configures the percent over average deemed to be a burst
	TriggerPercent uint32 `json:"triggerPercent" yaml:"triggerPercent"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type TracingPolicyList struct {
	metav1.TypeMeta `json:",inline" yaml:",inline"`
	metav1.ListMeta `json:"metadata" yaml:"metadata"`
	Items           []TracingPolicy `json:"items" yaml:"items"`
}

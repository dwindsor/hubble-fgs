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
	"fmt"

	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	ciliumio "github.com/cilium/tetragon/pkg/k8s/apis/cilium.io"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// Tracing Policy (TP)

	// TPPluralName is the plural name of Cilium Tracing Policy
	TPPluralName = "tracingpolicies"

	// TPKindDefinition is the kind name of Cilium Tracing Policy
	TPKindDefinition = "TracingPolicy"

	// TPName is the full name of Cilium Egress NAT Policy
	TPName = TPPluralName + "." + ciliumio.GroupName

	// TPNamespacedPluralName is the plural name of Cilium Tracing Policy
	TPNamespacedPluralName = "tracingpoliciesnamespaced"

	// TPNamespacedName
	TPNamespacedName = TPNamespacedPluralName + "." + ciliumio.GroupName

	// TPKindDefinition is the kind name of Cilium Tracing Policy
	TPNamespacedKindDefinition = "TracingPolicyNamespaced"
)

// +genclient
// +genclient:noStatus
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:singular="tracingpolicynamespaced",path="tracingpoliciesnamespaced",scope="Namespaced",shortName={}
type TracingPolicyNamespaced struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`
	// Tracing policy specification.
	Spec TracingPolicySpec `json:"spec"`
}

func (tp *TracingPolicyNamespaced) TpSpec() *TracingPolicySpec {
	return &tp.Spec
}

func (tp *TracingPolicyNamespaced) TpInfo() string {
	return fmt.Sprintf("%s (object:%d/%s) (type:%s/%s)", tp.ObjectMeta.Name, tp.ObjectMeta.Generation, tp.ObjectMeta.UID, tp.TypeMeta.Kind, tp.TypeMeta.APIVersion)
}

func (tp *TracingPolicyNamespaced) TpName() string {
	return tp.ObjectMeta.Name
}

func (tp *TracingPolicyNamespaced) TpNamespace() string {
	return tp.ObjectMeta.Namespace
}

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

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type TracingPolicyNamespacedList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []TracingPolicyNamespaced `json:"items"`
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
	// +kubebuilder:validation:Optional
	// File monitoring policy specification.
	FileMonitoring FileSpec `json:"file"`
	// +kubebuilder:validation:Optional
	// Enable loader events
	Loader bool `json:"loader"`
	// +kubebuilder:validation:Optional
	// A list of uprobe specs.
	UProbes []UProbeSpec `json:"uprobes"`
}

func (tp *TracingPolicy) TpSpec() *TracingPolicySpec {
	return &tp.Spec
}

func (tp *TracingPolicy) TpInfo() string {
	return fmt.Sprintf("%s (object:%d/%s) (type:%s/%s)", tp.ObjectMeta.Name, tp.ObjectMeta.Generation, tp.ObjectMeta.UID, tp.TypeMeta.Kind, tp.TypeMeta.APIVersion)
}

func (tp *TracingPolicy) TpName() string {
	return tp.ObjectMeta.Name
}

type OperationSelector struct {
	// +kubebuilder:validation:Enum=In;NotIn
	// Filter operation.
	Operator string `json:"operator"`
	// +kubebuilder:validation:Enum=FILE_INVALID;FILE_WRITE;FILE_READ;FILE_DELETE;FILE_CREATE;FILE_RMDIR;FILE_MKDIR;FILE_RENAME;FILE_READDIR;FILE_CHATTR
	// Value to compare the argument against.
	Values []string `json:"values"`
}

// FileSelector selects file operations.
type FileSelector struct {
	// +kubebuilder:validation:Optional
	// A list of binary exec name filters.
	MatchBinaries []BinarySelector `json:"matchBinaries"`
	// +kubebuilder:validation:Optional
	// A list of operation filters.
	MatchOperations []OperationSelector `json:"matchOperations"`
}

type FileSpec struct {
	// +kubebuilder:validation:Optional
	// What paths to monitor
	Paths []string `json:"file_paths"`
	// +kubebuilder:validation:Optional
	// What paths to exclude from monitored paths
	PathsExclude []string `json:"file_paths_exclude"`
	// +kubebuilder:validation:Optional
	// Config flags to enable/disable specific functionality
	Config map[string]string `json:"file_config"`
	// +kubebuilder:validation:Optional
	// Selectors to apply before producing trace output. Selectors are ORed.
	Selectors []FileSelector `json:"selectors"`
	// +kubebuilder:default=false
	// +kubebuilder:validation:Optional
	// Do monitoring on host files
	OnlyPodFiles bool `json:"onlyPodFiles"`
	// +kubebuilder:validation:Optional
	// This is a label selector which selects Pods. This field follows standard label
	// selector semantics; if present but empty, it selects all pods.
	PodSelector *slimv1.LabelSelector `json:"podSelector,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type TracingPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []TracingPolicy `json:"items"`
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

type HttpsSelector struct {
	// +kubebuilder:validation:Optional
	// A list of ports to match. Ports are ORd.
	MatchPorts []uint32 `json:"matchPorts"`
}

type HttpsSpec struct {
	// HTTPS enable parser
	Enable bool `json:"enable"`
	// +kubebuilder:validation:Optional
	// Selectors to apply TLS parser against. Selectors are ORed.
	Selectors []HttpsSelector `json:"selectors"`
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

type InterfacePolicySpec struct {
	// Interface enable parser
	Enable bool `json:"enable"`
	// +kubebuilder:validation:Optional
	// Interface interval in seconds
	StatsInterval uint32 `json:"statsInterval"`
	// +kubebuilder:validation:Optional
	// Interface packet level BPF
	Packet bool `json:"packet"`
}

type DnsPolicySpec struct {
	// DNS enable parser
	Enable bool `json:"enable"`
	// +kubebuilder:validation:Optional
	// A list of DNS ports
	Ports []uint16 `json:"ports"`
}

type NopSelector struct {
	// +kubebuilder:validation:Optional
	// A list of ports to match. Ports are ORd.
	MatchPorts []uint32 `json:"matchPorts"`
}

type NopSpec struct {
	// Nop enable parser
	Enable bool `json:"enable"`
	// +kubebuilder:validation:Optional
	// Selectors to apply Nop parser against. Selectors are ORed.
	Selectors []NopSelector `json:"selectors"`
}

type ParserPolicySpec struct {
	// +kubebuilder:validation:Optional
	// A Tls specs.
	Tls TlsSpec `json:"tls"`
	// +kubebuilder:validation:Optional
	// A Tls specs.
	Https HttpsSpec `json:"https"`
	// +kubebuilder:validation:Optional
	// A Http spec.
	Http HttpSpec `json:"http"`
	// +kubebuilder:validation:Optional
	// UDP policy specification
	Udp UdpPolicySpec `json:"udp"`
	// +kubebuilder:validation:Optional
	// Network policy specification
	Interface InterfacePolicySpec `json:"interface"`
	// +kubebuilder:validation:Optional
	// Network policy specification
	Dns DnsPolicySpec `json:"dns"`
	// +kubebuilder:validation:Optional
	// Network policy specification
	Nop NopSpec `json:"nop"`
	// +kubebuilder:validation:Optional
	// TCP policy specification
	Tcp TcpPolicySpec `json:"tcp"`
	// +kubebuilder:validation:Optional
	// UDP and TCP burst exit checking policy specification
	// +kubebuilder:deprecatedversion:warning="burstExitGen is deprecated. Use networkWatermarksExitGen instead"
	BurstExitGen NetworkWatermarksExitGenPolicySpec `json:"burstExitGen"`
	// +kubebuilder:validation:Optional
	// UDP and TCP watermarks exit checking policy specification
	NetworkWatermarksExitGen NetworkWatermarksExitGenPolicySpec `json:"networkWatermarksExitGen"`
	// +kubebuilder:validation:Optional
	// UDP and TCP heartbeat policy specification
	Heartbeat HeartbeatPolicySpec `json:"heartbeat"`
}

type TcpRttHistogram struct {
	// Enable TCP RTT Histogram
	Enable bool `json:"enable"`
	// +kubebuilder:validation:Optional
	// Configures the expected RTT Max value
	Max uint32 `json:"max"`
	// +kubebuilder:validation:Optional
	// Configures the expected RTT Min value
	Min uint32 `json:"min"`
}

type TcpPolicySpec struct {
	// Enable TCP statistics
	Enable bool `json:"enable"`
	// +kubebuilder:validation:Optional
	// Configures the Stat collection interval in seconds
	StatsInterval uint32 `json:"statsInterval"`
	// +kubebuilder:validation:Optional
	// Network policy specification
	// +kubebuilder:deprecatedversion:warning="burst is deprecated. Use watermarks instead"
	Burst TcpWatermarksPolicySpec `json:"burst"`
	// +kubebuilder:validation:Optional
	// Network policy specification
	Watermarks TcpWatermarksPolicySpec `json:"watermarks"`
	// +kubebuilder:validation:Optional
	// Rtt Histogram
	RttHistogram TcpRttHistogram `json:"histogram"`
}

type TcpWatermarksPolicySpec struct {
	// Enable TCP watermarks observability
	// +kubebuilder:default=false
	// +kubebuilder:validation:Optional
	Enable bool `json:"enable"`
	// +kubebuilder:default=1000
	// +kubebuilder:validation:Optional
	// Configures the watermarks window size in milliseconds
	WindowSize uint32 `json:"windowSize"`
	// +kubebuilder:default=100
	// +kubebuilder:validation:Optional
	// Configures the percent over average deemed to be a burst
	// +kubebuilder:deprecatedversion:warning="triggerPercent is deprecated. Use burstTriggerPercent instead"
	TriggerPercent uint32 `json:"triggerPercent"`
	// +kubebuilder:default=100
	// +kubebuilder:validation:Optional
	// Configures the percent over average deemed to be a burst
	BurstTriggerPercent uint32 `json:"burstTriggerPercent"`
	// +kubebuilder:default=100
	// +kubebuilder:validation:Optional
	// Configures the percent under average deemed to be a dip
	DipTriggerPercent uint32 `json:"dipTriggerPercent"`
}

type UdpPolicySpec struct {
	// Enable UDP observability
	Enable bool `json:"enable"`
	// +kubebuilder:default=true
	// +kubebuilder:validation:Optional
	// UDP has two modes one for newer kernels (cgroup) and then an
	// older fallback mode for kprobe use cases. Allow running older
	// kprobe version on newer kernels by setting cgroup knob to false.
	Cgroup bool `json:"cgroup"`
	// +kubebuilder:validation:Optional
	// Configures the Stat collection interval in seconds
	StatsInterval uint32 `json:"statsInterval"`
	// +kubebuilder:validation:Optional
	// Configure socket idle time to delete sockets in seconds
	DeleteIdleSocketInterval uint32 `json:"deleteIdleSocketInterval"`
	// +kubebuilder:validation:Optional
	// Network policy specification
	// kubebuilder:deprecatedversion:warning="burst is deprecated. Use watermarks instead"
	Burst UdpWatermarksPolicySpec `json:"burst"`
	// +kubebuilder:validation:Optional
	// Network policy specification
	Watermarks UdpWatermarksPolicySpec `json:"watermarks"`
	// +kubebuilder:validation:Optional
	// UDP latency observability policy specification
	Latency UdpLatencyPolicySpec `json:"latency"`
}

type UdpWatermarksPolicySpec struct {
	// Enable UDP watermarks observability
	// +kubebuilder:default=false
	// +kubebuilder:validation:Optional
	Enable bool `json:"enable"`
	// +kubebuilder:default=1000
	// +kubebuilder:validation:Optional
	// Configures the burst window size in milliseconds
	WindowSize uint32 `json:"windowSize"`
	// +kubebuilder:default=100
	// +kubebuilder:validation:Optional
	// Configures the percent over average deemed to be a burst
	// +kubebuilder:deprecatedversion:warning="triggerPercent is deprecated. Use burstTriggerPercent instead"
	TriggerPercent uint32 `json:"triggerPercent"`
	// +kubebuilder:default=100
	// +kubebuilder:validation:Optional
	// Configures the percent over average deemed to be a burst
	BurstTriggerPercent uint32 `json:"burstTriggerPercent"`
	// +kubebuilder:default=100
	// +kubebuilder:validation:Optional
	// Configures the percent under average deemed to be a dip
	DipTriggerPercent uint32 `json:"dipTriggerPercent"`
}

type UdpLatencyPolicySpec struct {
	// Enable UDP latency observability
	// +kubebuilder:default=false
	// +kubebuilder:validation:Optional
	Enable bool `json:"enable"`
	// +kubebuilder:validation:Optional
	// Configures the subnets to enable on
	MatchSubnets []string `json:"matchSubnets"`
	// +kubebuilder:validation:Optional
	// Configures the ports to enable on
	MatchPorts []uint16 `json:"matchPorts"`
	// +kubebuilder:validation:Optional
	// Configures the expected Max Latency value
	Max uint32 `json:"max"`
	// +kubebuilder:validation:Optional
	// Configures the expected Min Latency value
	Min uint32 `json:"min"`
	// +kubebuilder:validation:Optional
	// Configures the clock check interval in seconds
	ClockCheckInterval uint32 `json:"clockCheckInterval"`
	// +kubebuilder:validation:Optional
	// Configures the maximum acceptable clock skew before updating in microseconds
	ClockMaxSkew uint32 `json:"clockMaxSkew"`
	// +kubebuilder:validation:Optional
	// Configures the interfaces to enable on
	Interfaces []string `json:"interfaces"`
	// +kubebuilder:validation:Optional
	// Configures the maximum packet size
	MaxPacketSize uint16 `json:"maxPacketSize"`
}

type NetworkWatermarksExitGenPolicySpec struct {
	// Enable watermarks checks for end events from userland
	// +kubebuilder:default=true
	// +kubebuilder:validation:Optional
	Enable bool `json:"enable"`
	// +kubebuilder:default=1000
	// +kubebuilder:validation:Optional
	// Configures the checking interval in milliseconds
	Interval uint32 `json:"interval"`
}

type HeartbeatPolicySpec struct {
	// Enable heartbeat
	// +kubebuilder:default=true
	// +kubebuilder:validation:Optional
	Enable bool `json:"enable"`
	// +kubebuilder:default=60
	// +kubebuilder:validation:Optional
	// Configures the heartbeat interval in seconds
	Interval uint32 `json:"interval"`
	// +kubebuilder:default=6399
	// +kubebuilder:validation:Optional
	// Configures the UDP port
	UdpPort uint32 `json:"udpPort"`
	// +kubebuilder:default=6399
	// +kubebuilder:validation:Optional
	// Configures the TCP port
	TcpPort uint32 `json:"tcpPort"`
}

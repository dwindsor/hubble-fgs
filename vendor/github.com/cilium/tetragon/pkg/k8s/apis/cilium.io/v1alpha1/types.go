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

	ciliumio "github.com/cilium/tetragon/pkg/k8s/apis/cilium.io"
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
	TPName = TPPluralName + "." + ciliumio.GroupName
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
	// +kubebuilder:validation:Optional
	// File monitoring policy specification.
	FileMonitoring FileSpec `json:"file"`
	// +kubebuilder:validation:Optional
	// Enable loader events
	Loader bool `json:"loader"`
}

func (tp *TracingPolicy) TpSpec() *TracingPolicySpec {
	return &tp.Spec
}

func (tp *TracingPolicy) TpInfo() string {
	return fmt.Sprintf("%s (object:%d/%s) (type:%s/%s)", tp.ObjectMeta.Name, tp.ObjectMeta.Generation, tp.ObjectMeta.UID, tp.TypeMeta.Kind, tp.TypeMeta.APIVersion)
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
	BurstExitGen BurstExitGenPolicySpec `json:"burstExitGen"`
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
	Burst TcpBurstPolicySpec `json:"burst"`
	// +kubebuilder:validation:Optional
	// Rtt Histogram
	RttHistogram TcpRttHistogram `json:"histogram"`
}

type TcpBurstPolicySpec struct {
	// Enable TCP burst observability
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
	TriggerPercent uint32 `json:"triggerPercent"`
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
	Burst UdpBurstPolicySpec `json:"burst"`
	// +kubebuilder:validation:Optional
	// UDP latency observability policy specification
	Latency UdpLatencyPolicySpec `json:"latency"`
}

type UdpBurstPolicySpec struct {
	// Enable UDP burst observability
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
	TriggerPercent uint32 `json:"triggerPercent"`
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
}

type BurstExitGenPolicySpec struct {
	// Enable burst checks for end events from userland
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

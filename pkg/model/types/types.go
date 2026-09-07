// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package types

import (
	"fmt"
	"net/netip"
)

type ProcessExecveKey struct {
	Pid   uint32
	Pad   uint32
	Ktime uint64
}

type ProcessTreeKey struct {
	WLID  uint64
	CGID  uint64
	Depth uint64
	Self  uint64
	Path  [8]uint64
}

type ProcessTreeValue struct {
	KtimeFirstExec   uint64
	KtimeLastExec    uint64
	KtimeLatestExit  uint64
	CgroupID         uint64
	ExecCount        uint64
	ExitCount        uint64
	Pad0             [5]uint8
	MaybeMissingWLID bool
	InContainer      bool
	InInitTree       bool
	Binary           [256]byte
	Args             [256]byte
}

const (
	DestinationSourceUnknown = 0
	DestinationSourceBPF     = 1
	DestinationSourceUser    = 2
	DestinationSourceDNS     = 3
)

type DestinationEndpointKey struct {
	LocalId           uint64
	LocalWLID         uint64
	DestinationId     uint64
	DestinationSource uint64
	DestinationPort   uint32
	Protocol          uint32
}

func (v DestinationEndpointKey) String() string {
	return fmt.Sprintf("DestinationEndpointKey: %d-%d-%d-%d-%d-%d", v.LocalId, v.LocalWLID, v.DestinationId, v.DestinationSource, v.DestinationPort, v.Protocol)
}

// DestFlagPolicyTemplateOnly indicates an entry created by policy programming
// that has not yet observed any actual network traffic.
const DestFlagPolicyTemplateOnly uint64 = 0x1

// DestFlagObservedAtDestination indicates the first real traffic on this entry
// was ingress, so the local workload observed this connection at the destination.
const DestFlagObservedAtDestination uint64 = 0x2

// DestFlagObservationDecided indicates the observation point has been decided
// for this entry, so later traffic must not revisit the direction.
const DestFlagObservationDecided uint64 = 0x4

type DestinationEndpointValue struct {
	TxDropBytes           uint64
	TxDefaultAllowBytes   uint64
	TxDefaultDropBytes    uint64
	TxAction              uint64
	TxBytes               uint64
	RxBytes               uint64
	Policy                uint64
	RuleID                uint64
	IPv6                  uint64
	KtimeCreate           uint64
	AddrCreate            [2]uint64
	Port                  uint32
	Protocol              uint32
	Flags                 uint64
	Sessions              uint64
	TxDropPackets         uint64
	TxDefaultDropPackets  uint64
	TxDefaultAllowPackets uint64
	RxDropBytes           uint64
	RxDropPackets         uint64
	RxDefaultDropBytes    uint64
	RxDefaultDropPackets  uint64
	RxDefaultAllowBytes   uint64
	RxDefaultAllowPackets uint64
}

type TreeId struct {
	Uid uint32
	Cpu uint32
}

type ListenKey struct {
	Addr [2]uint64
	WLID uint64
	Port uint64
}

type ListenValue struct {
	Self     TreeId
	Accepted uint64
	TxBytes  uint64
	RxBytes  uint64
	Pad      uint64
}

type EndpointIdKey struct {
	Addr [2]uint64
}

type EndpointIdValue struct {
	Id uint64
}

type ProcessTreeBinaryUUIDValue struct {
	Binary [256]byte
	Args   [256]byte
}

const SyscallBitmaskSize = 16

type ProcessSyscallValue struct {
	Syscalls [SyscallBitmaskSize]uint64
}

const ProcessTreeMaxExecIds = 8

type ProcessTreeExecIds struct {
	ExecIds [ProcessTreeMaxExecIds]ProcessExecveKey
	CurHead uint64
	CurLen  uint64
}

type ContainerInfo struct {
	Id    string
	Name  string
	Image string
}

func (c ContainerInfo) String() string {
	// Not truncating container id here, this version is only used
	// for hashing
	return fmt.Sprintf("%s %s(%s)", c.Image, c.Name, c.Id)
}

type TetragonWorkloadNetworkSubject struct {
	Namespace string
	Name      string
	Kind      string
	Binary    string
}

const TetragonBinaryPathMaxLen = 256

type TetragonNetworkSubject struct {
	Labels        TetragonNetworkLabels
	Workload      TetragonWorkloadNetworkSubject
	InProcessName []string
}

type TetragonNetworkFQDN struct {
	Names []string
}

type TetragonNetworkLabels struct {
	Equal map[string]string
}

type TetragonNetworkCIDR struct {
	CIDR string `json:"cidr"`
}

// For now firewall only knows CIDR:Port
type TetragonNetworkSource struct {
	CIDR  *TetragonNetworkCIDR
	Ports []uint32
}

// TetragonServiceRef references a Kubernetes Service for policy matching
type TetragonServiceRef struct {
	Name      string
	Namespace string
}

type TetragonNetworkDestination struct {
	FQDN       *TetragonNetworkFQDN
	Labels     TetragonNetworkLabels
	CIDR       netip.Prefix
	ServiceRef *TetragonServiceRef
	Ports      []uint32
}

type TetragonEnforceAction struct {
	Deny   bool
	Allow  bool
	Reject bool // Reject behaves like Deny but also sends an error message to the sender.
}

type TetragonNetworkAction struct {
	EnforceAction *TetragonEnforceAction
}

type TetragonPolicyUniqueID struct {
	PolicyName string
	RuleName   string
}

type TetragonNetworkPolicy struct {
	PolicyUID       TetragonPolicyUniqueID
	RuleDescription string
	Subject         TetragonNetworkSubject
	Source          *TetragonNetworkSource
	Destination     TetragonNetworkDestination
	Action          TetragonNetworkAction
	Default         TetragonNetworkAction
}

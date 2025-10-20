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

import "fmt"

type ProcessExecveKey struct {
	Pid   uint32
	Pad   uint32
	Ktime uint64
}

type ProcessTreeKey struct {
	NSID  uint64
	Depth uint64
	Self  uint64
	Path  [8]uint64
}

type ProcessTreeValue struct {
	KtimeFirstExec   uint64
	KtimeLastExec    uint64
	KtimeLatestExit  uint64
	CgroupID         uint64
	Pad0             [5]uint8
	MaybeMissingNSID bool
	InContainer      bool
	InInitTree       bool
}

const (
	DestinationSourceUnknown = 0
	DestinationSourceBPF     = 1
	DestinationSourceUser    = 2
	DestinationSourceDNS     = 3
)

type DestinationEndpointKey struct {
	LocalId           uint64
	LocalNSId         uint64
	DestinationId     uint64
	DestinationSource uint64
	DestinationPort   uint64
}

func (v DestinationEndpointKey) String() string {
	return fmt.Sprintf("DestinationEndpointKey: %d-%d-%d-%d-%d", v.LocalId, v.LocalNSId, v.DestinationId, v.DestinationSource, v.DestinationPort)
}

type DestinationEndpointValue struct {
	TxQuota           uint64
	TxLimit           uint64
	TxDrops           uint64
	AllowDefaultBytes uint64
	DenyDefaultBytes  uint64
	TxAction          uint64
	KtimeLastReset    uint64
	KtimeTxReset      uint64
	TxBytes           uint64
	RxBytes           uint64
	Policy            uint64
	RuleID            uint64
	IPv6              uint64
	KtimeCreate       uint64
	AddrCreate        [2]uint64
	Port              uint64
}

type TreeId struct {
	Uid uint32
	Cpu uint32
}

type ListenKey struct {
	Addr [2]uint64
	Nsid uint64
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

type ProcessTreeBinaryUUIDKey struct {
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

type TetragonWorkloadNetworkSubject struct {
	Namespace string
	Name      string
	Kind      string
	Binary    string
}

const TetragonBinaryPathMaxLen = 256

type TetragonLogicalNetworkSubject struct {
	VRF  string
	VLAN uint32
}

type TetragonNetworkSubject struct {
	Labels         TetragonNetworkLabels
	Workload       TetragonWorkloadNetworkSubject
	InProcessName  []string
	LogicalNetwork TetragonLogicalNetworkSubject
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

type TetragonNetworkDestination struct {
	FQDN   *TetragonNetworkFQDN
	Labels TetragonNetworkLabels
	CIDR   *TetragonNetworkCIDR
	Ports  []uint32
}

type TetragonQuotaAction struct {
	Quota string
	Reset string
}

type TetragonEnforceAction struct {
	Deny  bool
	Allow bool
}

type TetragonNetworkAction struct {
	QuotaAction   *TetragonQuotaAction
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

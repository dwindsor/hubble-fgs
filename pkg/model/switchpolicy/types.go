package switchpolicy

import (
	"bytes"
	"crypto/sha256"
	"encoding/gob"
)

type PolicyUniqueID struct {
	PolicyName string
	RuleName   string
}

type SmartSwitchNetworkPolicy struct {
	Source      SmartSwitchNetworkSource
	Destination SmartSwitchNetworkDestination
	Action      SmartSwitchNetworkAction
	Default     SmartSwitchNetworkAction
}

func (s *SmartSwitchNetworkPolicy) Hash() ([sha256.Size]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(*s)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(buf.Bytes()), nil
}

type SmartSwitchNetworkProtocolPorts struct {
	Port     uint32
	EndPort  uint32
	Protocol string
}

type SmartSwitchNetworkEndpoint struct {
	CIDR string
	VRF  string
	VLAN uint32
}

type SmartSwitchNetworkSource struct {
	Endpoint SmartSwitchNetworkEndpoint
}

type SmartSwitchNetworkDestination struct {
	// FQDN   *TetragonNetworkFQDN
	// Labels TetragonNetworkLabels
	Endpoint   SmartSwitchNetworkEndpoint
	ProtoPorts *SmartSwitchNetworkProtocolPorts
}

type SmartSwitchNetworkAction struct {
	EnforceAction SmartSwitchEnforceAction
}

type SmartSwitchEnforceAction struct {
	Deny  bool
	Allow bool
}

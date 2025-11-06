package switchpolicy

import (
	"crypto/sha256"
	"encoding/binary"
	"io"
)

type PolicyUniqueID struct {
	PolicyName string
	RuleName   string
}

type SmartSwitchNetworkPolicy struct {
	K8SResourceVersion string
	K8SUid             string
	Source             SmartSwitchNetworkSource
	Destination        SmartSwitchNetworkDestination
	Action             SmartSwitchNetworkAction
	Default            SmartSwitchNetworkAction
}

func (s *SmartSwitchNetworkPolicy) Hash() ([sha256.Size]byte, error) {
	h := sha256.New()

	// Write all fields in fixed order
	_, err := io.WriteString(h, s.K8SResourceVersion)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	_, err = io.WriteString(h, s.K8SUid)
	if err != nil {
		return [sha256.Size]byte{}, err
	}

	// Source Endpoint
	_, err = io.WriteString(h, s.Source.Endpoint.CIDR)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	_, err = io.WriteString(h, s.Source.Endpoint.VRF)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	err = binary.Write(h, binary.BigEndian, s.Source.Endpoint.VLAN)
	if err != nil {
		return [sha256.Size]byte{}, err
	}

	// Destination Endpoint
	_, err = io.WriteString(h, s.Destination.Endpoint.CIDR)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	_, err = io.WriteString(h, s.Destination.Endpoint.VRF)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	err = binary.Write(h, binary.BigEndian, s.Destination.Endpoint.VLAN)
	if err != nil {
		return [sha256.Size]byte{}, err
	}

	// Destination ProtoPorts
	if s.Destination.ProtoPorts != nil {
		err = binary.Write(h, binary.BigEndian, s.Destination.ProtoPorts.Port)
		if err != nil {
			return [sha256.Size]byte{}, err
		}
		err = binary.Write(h, binary.BigEndian, s.Destination.ProtoPorts.EndPort)
		if err != nil {
			return [sha256.Size]byte{}, err
		}
		_, err = io.WriteString(h, s.Destination.ProtoPorts.Protocol)
		if err != nil {
			return [sha256.Size]byte{}, err
		}
	}

	// Action
	err = binary.Write(h, binary.BigEndian, s.Action.EnforceAction.Deny)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	err = binary.Write(h, binary.BigEndian, s.Action.EnforceAction.Allow)
	if err != nil {
		return [sha256.Size]byte{}, err
	}

	// Default
	err = binary.Write(h, binary.BigEndian, s.Default.EnforceAction.Deny)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	err = binary.Write(h, binary.BigEndian, s.Default.EnforceAction.Allow)
	if err != nil {
		return [sha256.Size]byte{}, err
	}

	var result [sha256.Size]byte
	copy(result[:], h.Sum(nil))
	return result, nil
}

type SmartSwitchNetworkProtocolPorts struct {
	Port     int32
	EndPort  int32
	Protocol string
}

type SmartSwitchNetworkEndpoint struct {
	CIDR string
	VRF  string
	VLAN int32
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

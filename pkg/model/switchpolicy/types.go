package switchpolicy

import (
	"crypto/sha256"
	"encoding/binary"
	"io"

	"github.com/isovalent/ipa/l3l4networkpolicy/v1alpha"
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

// Copy creates a deep copy of the SmartSwitchNetworkPolicy
func (s *SmartSwitchNetworkPolicy) Copy() *SmartSwitchNetworkPolicy {
	if s == nil {
		return nil
	}
	cp := *s
	// Deep copy the ProtoPorts slice
	if s.Destination.ProtoPorts != nil {
		protoPortsCopy := make([]SmartSwitchNetworkProtocolPorts, len(*s.Destination.ProtoPorts))
		copy(protoPortsCopy, *s.Destination.ProtoPorts)
		cp.Destination.ProtoPorts = &protoPortsCopy
	}
	return &cp
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
	if len(*s.Destination.ProtoPorts) > 0 {
		for _, p := range *s.Destination.ProtoPorts {
			err = binary.Write(h, binary.BigEndian, p.Port)
			if err != nil {
				return [sha256.Size]byte{}, err
			}
			err = binary.Write(h, binary.BigEndian, p.EndPort)
			if err != nil {
				return [sha256.Size]byte{}, err
			}
			err = binary.Write(h, binary.BigEndian, p.Protocol)
			if err != nil {
				return [sha256.Size]byte{}, err
			}
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
	Port     uint32
	EndPort  uint32
	Protocol v1alpha.PolicyProtocol
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
	ProtoPorts *[]SmartSwitchNetworkProtocolPorts
}

type SmartSwitchNetworkAction struct {
	EnforceAction SmartSwitchEnforceAction
}

type SmartSwitchEnforceAction struct {
	Deny  bool
	Allow bool
}

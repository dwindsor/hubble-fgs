// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package policy

type FwEnforcement struct {
	PermanentHash string         `json:"permanentHash"`
	Add           map[string]any `json:"add"`
	Delete        map[string]any `json:"delete"`
	Edit          map[string]any `json:"edit"`
	Data          []FwPolicy     `json:"data"`
}

type FwPolicyMsg struct {
	Hash         string     `json:"hash"`
	Verification bool       `json:"verification"`
	Policies     []FwPolicy `json:"policies"`
}

type FwPolicy struct {
	Id          string   `json:"id"`
	ReferenceId string   `json:"referenceId"`
	Name        string   `json:"name"`
	Effect      string   `json:"effect"`
	Protocol    []string `json:"protocol"`
	Source      Endpoint `json:"source"`
	Destination Endpoint `json:"destination"`
}

type Endpoint struct {
	Addresses []Address `json:"addresses"`
	Vlan      []string  `json:"vlan"`
	Sgt       []string  `json:"sgt"`
	IpCount   uint64    `json:"-"` // This field is internal
	PortCount uint64    `json:"-"` // This field is internal
}

type Address struct {
	Ips   []string `json:"ips"`
	Ports []Port   `json:"ports"`
}

type Port struct {
	PortLow  uint16 `json:"portLow"`
	PortHigh uint16 `json:"portHigh"`
}

type FwPolicyMsgV2 struct {
	Hash         string       `json:"hash"`
	Verification bool         `json:"verification"`
	Policies     []FwPolicyV2 `json:"policies"`
}

type FwPolicyV2 struct {
	Id          string     `json:"id"`
	Name        string     `json:"name"`
	Operation   uint16     `json:"operation"` // OPERATION_UPDATE|DELETE
	Effect      string     `json:"effect"`    // permit/allow or deny
	Source      EndpointV2 `json:"source"`
	Destination EndpointV2 `json:"destination"`
}

type PortV2 struct {
	PortHigh uint16   `json:"port_high"`
	PortLow  uint16   `json:"port_low"`
	Protocol []string `json:"protocol"` // any or udp or tcp or icmp
}

type EndpointV2 struct {
	Ip        string   `json:"ip"`
	Ports     []PortV2 `json:"port"`
	Vlan      int      `json:"vlan"`
	Vrf       int      `json:"vrf"`
	IpCount   uint64   `json:"-"` // This field is internal
	PortCount uint64   `json:"-"` // This field is internal
}

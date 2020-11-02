// Copyright 2020 Authors of Hubble
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// helper functions to manage 5-tuples
package vtuple

import (
	"fmt"
	"net"
)

type VTuple interface {
	IsUDP() bool
	IsTCP() bool
	IsIP4() bool
	IsIP6() bool

	SrcAddr() net.IP
	DstAddr() net.IP
	SrcPort() uint16
	DstPort() uint16
}

const (
	VT_IP4     = 0x4000
	VT_IP6     = 0x6000
	VT_L3_MASK = 0xff00

	// Let's use the actual TCP/UDP nextheader ids because why not?
	VT_TCP     = 0x06
	VT_UDP     = 0x11
	VT_L4_MASK = 0xff

	VT_TCP4 = VT_IP4 | VT_TCP
	VT_TCP6 = VT_IP6 | VT_TCP
	VT_UDP4 = VT_IP4 | VT_UDP
	VT_UDP6 = VT_IP6 | VT_UDP
)

type VTupleImpl struct {
	srcAddr net.IP
	dstAddr net.IP
	srcPort uint16
	dstPort uint16
	proto   uint16
}

func (t *VTupleImpl) IsUDP() bool {
	return (t.proto & VT_L4_MASK) == VT_UDP
}

func (t *VTupleImpl) IsTCP() bool {
	return (t.proto & VT_L4_MASK) == VT_TCP
}
func (t *VTupleImpl) IsIP4() bool {
	return (t.proto & VT_L3_MASK) == VT_IP4
}
func (t *VTupleImpl) IsIP6() bool {
	return (t.proto & VT_L3_MASK) == VT_IP6
}
func (t *VTupleImpl) SrcAddr() net.IP {
	return t.srcAddr[:]
}
func (t *VTupleImpl) DstAddr() net.IP {
	return t.dstAddr[:]
}
func (t *VTupleImpl) SrcPort() uint16 {
	return t.srcPort
}
func (t *VTupleImpl) DstPort() uint16 {
	return t.dstPort
}

func CreateTCPv4(saddr [4]byte, sport uint16, daddr [4]byte, dport uint16) VTupleImpl {
	return VTupleImpl{
		proto:   VT_TCP4,
		srcAddr: net.IPv4(saddr[0], saddr[1], saddr[2], saddr[3]),
		dstAddr: net.IPv4(daddr[0], daddr[1], daddr[2], daddr[3]),
		srcPort: sport,
		dstPort: dport,
	}

}

func CreateUDPv4(saddr [4]byte, sport uint16, daddr [4]byte, dport uint16) VTupleImpl {
	return VTupleImpl{
		proto:   VT_UDP4,
		srcAddr: net.IPv4(saddr[0], saddr[1], saddr[2], saddr[3]),
		dstAddr: net.IPv4(daddr[0], daddr[1], daddr[2], daddr[3]),
		srcPort: sport,
		dstPort: dport,
	}

}

func CreateVTupleV4(proto byte, saddr [4]byte, sport uint16, daddr [4]byte, dport uint16) VTupleImpl {

	switch proto {
	case VT_TCP, VT_UDP:
	default:
		panic(fmt.Sprintf("Unsupported protocol: %d", proto))
	}

	return VTupleImpl{
		proto:   VT_IP4 | uint16(proto),
		srcAddr: net.IPv4(saddr[0], saddr[1], saddr[2], saddr[3]),
		dstAddr: net.IPv4(daddr[0], daddr[1], daddr[2], daddr[3]),
		srcPort: sport,
		dstPort: dport,
	}
}

func StringRep(vt VTuple) string {
	proto := "?"
	if vt.IsTCP() {
		proto = "tcp"
	} else if vt.IsUDP() {
		proto = "udp"
	}

	return fmt.Sprintf("%s:%d→%s:%d/%s", vt.SrcAddr(), vt.SrcPort(), vt.DstAddr(), vt.DstPort(), proto)
}

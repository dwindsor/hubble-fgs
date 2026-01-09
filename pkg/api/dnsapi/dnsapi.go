// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package dnsapi

import (
	"encoding/binary"
	"net/netip"

	"golang.org/x/net/dns/dnsmessage"
)

type MsgDns struct {
	Response      bool
	RCode         uint16
	AnswerTypes   []uint32
	QuestionTypes []uint32
	Names         []string
	IPs           []string
}

// All Type constants defined in golang.org/x/net/dns/dnsmessage/message.go
var KnownDNSTypes = []dnsmessage.Type{
	dnsmessage.TypeA,
	dnsmessage.TypeNS,
	dnsmessage.TypeCNAME,
	dnsmessage.TypeSOA,
	dnsmessage.TypePTR,
	dnsmessage.TypeMX,
	dnsmessage.TypeTXT,
	dnsmessage.TypeAAAA,
	dnsmessage.TypeSRV,
	dnsmessage.TypeOPT,
	dnsmessage.TypeWKS,
	dnsmessage.TypeHINFO,
	dnsmessage.TypeMINFO,
	dnsmessage.TypeAXFR,
	dnsmessage.TypeALL,
}

type IPAddr struct {
	Addr    [2]uint64 `align:"addr"`
	AFINET6 bool      `align:"af_inet6"`
	_       [7]uint8  `align:"pad"`
}

func NewIPAddr(a netip.Addr) IPAddr {
	i := IPAddr{}
	i.Set(a)
	return i
}

func (ip IPAddr) String() string {
	return ip.Get().String()
}

func (ip IPAddr) Get() netip.Addr {
	if ip.AFINET6 {
		b := [16]byte{}
		binary.LittleEndian.PutUint64(b[:], ip.Addr[0])
		binary.LittleEndian.PutUint64(b[8:], ip.Addr[1])
		return netip.AddrFrom16(b)
	}

	b := [4]byte{}
	binary.LittleEndian.PutUint32(b[:], uint32(ip.Addr[0]))
	return netip.AddrFrom4(b)
}

func (ip *IPAddr) Set(addr netip.Addr) {
	if addr.Is4() {
		ip.Addr[0] = uint64(binary.LittleEndian.Uint32(addr.AsSlice()))
	} else {
		ip.Addr[0] = binary.LittleEndian.Uint64(addr.AsSlice()[:8])
		ip.Addr[1] = binary.LittleEndian.Uint64(addr.AsSlice()[8:])
		ip.AFINET6 = true
	}
}

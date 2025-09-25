//-----------------------------------------------------------------------------
// {C} Copyright 2023 AMD Inc. All rights reserved
//-----------------------------------------------------------------------------

package utils

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/isovalent/hubble-fgs/pkg/dpu/pensando/pds"
)

var (
	Uint8MaskAllBitsSet  = ((1 << 8) - 1)
	Uint16MaskAllBitsSet = ((1 << 16) - 1)
	Uint32MaskAllBitsSet = ((1 << 32) - 1)
)

// IPAddrStrtoUint32 converts string IP address to uint32
func IPAddrStrtoUint32(ip string) uint32 {
	var addr [4]uint32
	fmt.Sscanf(ip, "%d.%d.%d.%d", &addr[0], &addr[1], &addr[2], &addr[3])
	return ((addr[0] << 24) + (addr[1] << 16) + (addr[2] << 8) + (addr[3]))
}

// IPAddrStrToPDSIPAddr converts string ip address to pds native IPAddress Type
func IPAddrStrToPDSIPAddr(ip string) *pds.IPAddress {
	netIP := net.ParseIP(ip)

	var ipAddr *pds.IPAddress
	if netIP == nil {
		ipAddr = &pds.IPAddress{
			Af: pds.IPAF_IP_AF_NONE,
		}
	} else if netIP.To4() == nil {
		ipAddr = &pds.IPAddress{
			Af: pds.IPAF_IP_AF_INET6,
			V4OrV6: &pds.IPAddress_V6Addr{
				V6Addr: netIP,
			},
		}
	} else {
		ipAddr = &pds.IPAddress{
			Af: pds.IPAF_IP_AF_INET,
			V4OrV6: &pds.IPAddress_V4Addr{
				V4Addr: IPAddrStrtoUint32(ip),
			},
		}
	}
	return ipAddr
}

// IPPrefixStrToPDSIPPrefix converts ip prefix string to pds native IPPrefix type
func IPPrefixStrToPDSIPPrefix(pfx string) *pds.IPPrefix {
	var ipPrefix *pds.IPPrefix
	var ipAddr *pds.IPAddress
	var pfxLen uint64 = 32
	var err error

	ip := strings.Split(pfx, "/")
	if len(ip) >= 2 {
		pfxLen, err = strconv.ParseUint(ip[1], 10, 32)
		if err != nil {
			return nil
		}
	}
	ipAddr = IPAddrStrToPDSIPAddr(ip[0])
	ipPrefix = &pds.IPPrefix{
		Len:  uint32(pfxLen),
		Addr: ipAddr,
	}
	return ipPrefix
}

// converts IP Prefix Mask to bytes in BigEndian format
func IPPrefixMaskToBigEndian(pfx *pds.IPPrefix) []byte {
	IPPrefixMask := make([]byte, 16)

	if pfx.GetAddr().GetAf() == pds.IPAF_IP_AF_INET {
		mask := net.CIDRMask(int(pfx.GetLen()), 32)
		for i := range mask {
			IPPrefixMask[i] = mask[len(mask)-1-i]
		}
	} else if pfx.GetAddr().GetAf() == pds.IPAF_IP_AF_INET6 {
		mask := net.CIDRMask(int(pfx.GetLen()), 128)
		for i := range mask {
			IPPrefixMask[i] = mask[len(mask)-1-i]
		}
	}
	return IPPrefixMask
}

// converts given IP Prefix address in BigEndian format
func IPPrefixAddressToBigEndian(pfx *pds.IPPrefix) []byte {
	addrByte := make([]byte, 16)

	af := pfx.GetAddr().GetAf()
	if af == pds.IPAF_IP_AF_INET {
		binary.BigEndian.PutUint32(addrByte, pfx.GetAddr().GetV4Addr())
	} else {
		BigEndianAddrByte := make([]byte, 16)
		copy(BigEndianAddrByte, pfx.GetAddr().GetV6Addr())
		for i := range BigEndianAddrByte {
			addrByte[i] = BigEndianAddrByte[len(BigEndianAddrByte)-1-i]
		}
	}
	return addrByte
}

// performs AND operation on given IP address and IP Mask
func IPPrefixToMaskedIPAddr(IPaddr, IPMask []byte) []byte {
	lengthIP := len(IPaddr)
	result := make([]byte, lengthIP)
	for i := 0; i < lengthIP; i++ {
		result[i] = IPaddr[i] & IPMask[i]
	}
	return result
}

// converts IP Prefix to string
func BigEndianToIPPrefixStr(pfx []byte, mask []byte, af uint32) string {
	// IPV4
	if af == 1 {
		ip := net.IPv4(pfx[3], pfx[2], pfx[1], pfx[0])
		prefixMask := make([]byte, 4)
		for i := range prefixMask {
			prefixMask[i] = mask[len(prefixMask)-1-i]
		}
		ipNet := net.IPNet{IP: ip, Mask: prefixMask}
		return ipNet.String()
	} else if af == 2 { //IPV6
		prefixMask := make([]byte, 16)
		for i := range mask {
			prefixMask[i] = mask[len(mask)-1-i]
		}
		ip := make([]byte, 16)
		for j := range pfx {
			ip[j] = pfx[len(pfx)-1-j]
		}
		ipNet := net.IPNet{IP: ip, Mask: prefixMask}
		return ipNet.String()
	}
	return "_/_"
}

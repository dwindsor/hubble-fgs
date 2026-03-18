// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package igmp

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

func interfaceBySAddr(SAddr uint32) (*net.Interface, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	saddrBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(saddrBytes, SAddr)
	saddr := net.IP(saddrBytes)
	saddrStr := saddr.String()
	for _, i := range ifs {
		addrs, err := i.Addrs()
		if err != nil {
			return nil, err
		}
		for _, addr := range addrs {
			addrStr := addr.String()
			slashIdx := strings.IndexByte(addrStr, '/')
			if slashIdx >= 0 {
				addrStr = addrStr[:slashIdx]
			}
			if addrStr == saddrStr {
				return &i, nil
			}
		}
	}
	return nil, fmt.Errorf("address not found")
}

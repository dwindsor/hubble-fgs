// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

//go:build !windows

package tests

import (
	"context"
	"fmt"
	"net"
	"os"
	"slices"
	"strings"
	"syscall"
	"time"
)

func waitForSocketToListen(ctx context.Context, addr net.IP, port uint16, protocol uint16, addressFamily uint16) error {
	for {
		listening, err := isSocketListening(addr, port, protocol, addressFamily)
		if err != nil {
			return err
		}
		if listening {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			// The intention of this millisleep is to allow CPU relaxing, task switching, etc
			// so that hopefully some amount of time has passed between checks, mainly just to
			// reduce churn.
			time.Sleep(time.Millisecond)
		}
	}
}

func ipToHexstring(addr net.IP) string {
	var builder strings.Builder
	if addr.To4() == nil {
		for index := range 4 {
			for offset := 3; offset >= 0; offset-- {
				fmt.Fprintf(&builder, "%02X", addr[index*4+offset])
			}
		}
		return builder.String()
	}
	addr = addr.To4()
	for _, value := range slices.Backward(addr) {
		fmt.Fprintf(&builder, "%02X", value)
	}
	return builder.String()
}

func isSocketListening(addr net.IP, port uint16, protocol uint16, addressFamily uint16) (bool, error) {
	netFile := "/proc/net/"
	switch protocol {
	case syscall.IPPROTO_TCP:
		netFile += "tcp"
	case syscall.IPPROTO_UDP:
		netFile += "udp"
	default:
		return false, fmt.Errorf("protocol must be IPPROTO_TCP or IPPROTO_UDP")
	}
	switch addressFamily {
	case syscall.AF_INET:
	case syscall.AF_INET6:
		netFile += "6"
	default:
		return false, fmt.Errorf("address family must be AF_INET or AF_INET6")
	}

	addressPort := ipToHexstring(addr)
	addressPort += fmt.Sprintf(":%04X", port)

	netData, err := os.ReadFile(netFile)
	if err != nil {
		return false, err
	}
	for line := range strings.SplitSeq(string(netData), "\n") {
		fields := strings.Fields(line)
		// fields[1] is local address:port
		// fields[2] is remote address:port
		if len(fields) >= 3 && fields[1] == addressPort {
			return true, nil
		}
	}
	return false, nil
}

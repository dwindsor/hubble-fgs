// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package utils

import (
	"net"
	"testing"
)

func TestGetOutboundIP(t *testing.T) {
	// Call the GetOutboundIP function
	ip, err := GetOutboundIP()
	if err != nil {
		t.Fatal(err)
	}

	// Validate the IP address format
	if net.ParseIP(ip) == nil {
		t.Errorf("Invalid IP address: %s", ip)
	}
}

func TestGetInterfaces(t *testing.T) {
	interfaces, err := GetInterfaces()
	if err != nil {
		t.Fatal(err)
	}

	if len(interfaces) == 0 {
		t.Error("Expected to find at least one network interface")
	}

	hardwareAddrFound := false
	ipFound := false
	for _, iface := range interfaces {
		if iface.Name == "" {
			t.Error("Interface name should not be empty")
		}
		if iface.Index < 0 {
			t.Error("Interface index should be non-negative")
		}
		if iface.Flags == "" {
			t.Error("Interface flags should not be empty")
		}
		if iface.Mtu < 0 {
			t.Error("Interface MTU should be positive")
		}
		if hardwareAddrFound || iface.HardwareAddr != "" {
			hardwareAddrFound = true
		}
		if ipFound || len(iface.UnicastIpv4Ips) > 0 || len(iface.UnicastIpv6Ips) > 0 || len(iface.MulticastIpv4Ips) > 0 || len(iface.MulticastIpv6Ips) > 0 {
			ipFound = true
		}
	}
	if !hardwareAddrFound {
		t.Error("Expected to find at least one hardware address")
	}
	if !ipFound {
		t.Error("Expected to find at least one IP address")
	}
}

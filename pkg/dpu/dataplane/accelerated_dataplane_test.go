// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package dataplane

import (
	"context"
	"testing"
	"time"

	"fmt"
	"net"
	"os"

	dpAppPolicy "github.com/isovalent/hubble-fgs/pkg/dpu/policy"

	"github.com/isovalent/hubble-fgs/pkg/model/switchpolicy"

	"github.com/isovalent/ipa/l3l4networkpolicy/v1alpha"
	"github.com/stretchr/testify/require"
)

func testSocketLoop(listener net.Listener) {
	defer listener.Close()
	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("Error accepting connection:", err)
			continue
		}
		go handleConnection(conn)
	}
}

func createTestSocket(path string) {
	// Remove the socket file if it already exists
	os.RemoveAll(path)

	listener, err := net.Listen("unix", path)
	if err != nil {
		fmt.Println("Error listening:", err)
		return
	}

	fmt.Println("Test UDS server listening on", path)

	go testSocketLoop(listener)
}

func handleConnection(conn net.Conn) {
	defer conn.Close()
	fmt.Printf("handleConnectoin\n")

	for {
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			fmt.Println("Error reading:", err)
			return
		}

		message := string(buf[:n])
		fmt.Printf("Received: %s\n", message)

		_, err = conn.Write([]byte("{\"code\":0,\"data\":0}"))
		if err != nil {
			fmt.Println("Error writing:", err)
			return
		}
	}
}

func TestPushPolicy(t *testing.T) {
	ctx := context.Background()
	fwop := v1alpha.PolicyOperation_POLICY_OPERATION_UPSERT
	time := time.Now()
	ports := &[]switchpolicy.SmartSwitchNetworkProtocolPorts{}
	src := switchpolicy.DPUSubject{
		Cidr:  "1.1.1.1/32",
		Ports: ports,
		VrfId: 1,
		Vrf:   "red",
	}
	dst := switchpolicy.DPUSubject{
		Cidr:  "1.1.1.2/32",
		Ports: ports,
		VrfId: 1,
		Vrf:   "red",
	}
	rule := &switchpolicy.DPURule{
		K8SResourceVersion: "version",
		K8SUid:             "uid",
		PolicyName:         "name",
		RuleName:           "rule",
		Action:             v1alpha.PolicyAction_POLICY_ACTION_ALLOW,
		Source:             src,
		Destination:        dst,
	}
	policies := []*switchpolicy.DPUPolicyRule{
		&switchpolicy.DPUPolicyRule{
			Oper:      fwop,
			Timestamp: time,
			Policy:    rule,
		},
	}

	dpTestPath := "/tmp/test.sock"
	defer os.RemoveAll(dpTestPath)
	createTestSocket(dpTestPath)
	dp := NewAcceleratedDataplane("dp-app", dpTestPath)
	err := dp.Accelerated.Start(ctx)
	require.NoError(t, err)
	defer dp.Accelerated.Socket.Close()

	// Force the socket down and push policy to test retry
	dp.Accelerated.Socket.Close()
	err = dp.PushPolicy(ctx, fwop, policies)
	require.NoError(t, err)
	dp.Accelerated.Socket.Close()
	err = dp.PushPolicy(ctx, fwop, policies)
	require.NoError(t, err)
}

func TestUpdateFirewall(t *testing.T) {
	ctx := context.Background()

	pv2 := []dpAppPolicy.PortV2{
		{
			PortHigh: 433,
			PortLow:  433,
			Protocol: []string{"TCP"},
		},
	}
	eps := dpAppPolicy.EndpointV2{
		Ip:    "1.1.1.1",
		Ports: pv2,
		Vlan:  0,
		Vrf:   10,
	}
	epd := dpAppPolicy.EndpointV2{
		Ip:    "1.1.1.2",
		Ports: pv2,
		Vlan:  0,
		Vrf:   10,
	}
	policy := dpAppPolicy.FwPolicyV2{
		Id:          "testPolicyId",
		Name:        "testPolicy",
		Operation:   1,
		Effect:      "permit",
		Source:      eps,
		Destination: epd,
	}
	msg := &dpAppPolicy.FwPolicyMsgV2{
		Hash:         "0xabcdef",
		Verification: false,
		Policies: []dpAppPolicy.FwPolicyV2{
			policy,
		},
	}

	dpTestPath := "/tmp/test.sock"
	defer os.RemoveAll(dpTestPath)
	createTestSocket(dpTestPath)
	db := NewAcceleratedDataplane("dp-app", dpTestPath)
	// Connect the socket before use
	err := db.Accelerated.Start(ctx)
	require.NoError(t, err)
	defer db.Accelerated.Socket.Close()

	err = db.Accelerated.UpdateFirewallPolicies(ctx, msg)
	require.NoError(t, err)
	err = db.Accelerated.UpdateFirewallPolicies(ctx, msg)
	require.NoError(t, err)
}

func BenchmarkUpdate(b *testing.B) {
	ctx := context.Background()

	pv2 := []dpAppPolicy.PortV2{
		{
			PortHigh: 433,
			PortLow:  433,
			Protocol: []string{"TCP"},
		},
	}
	eps := dpAppPolicy.EndpointV2{
		Ip:    "1.1.1.1",
		Ports: pv2,
		Vlan:  0,
		Vrf:   10,
	}
	epd := dpAppPolicy.EndpointV2{
		Ip:    "1.1.1.2",
		Ports: pv2,
		Vlan:  0,
		Vrf:   10,
	}
	policy := dpAppPolicy.FwPolicyV2{
		Id:          "testPolicyId",
		Name:        "testPolicy",
		Operation:   1,
		Effect:      "permit",
		Source:      eps,
		Destination: epd,
	}
	msg := &dpAppPolicy.FwPolicyMsgV2{
		Hash:         "0xabcdef",
		Verification: false,
		Policies: []dpAppPolicy.FwPolicyV2{
			policy,
		},
	}

	dpTestPath := "/tmp/test.sock"
	defer os.RemoveAll(dpTestPath)
	createTestSocket(dpTestPath)
	db := NewAcceleratedDataplane("dp-app", dpTestPath)
	err := db.Accelerated.Start(ctx)
	if err != nil {
		b.Fatalf("Failed to start: %v", err)
	}
	defer db.Accelerated.Socket.Close()

	for i := 0; i < b.N; i++ {
		db.Accelerated.UpdateFirewallPolicies(ctx, msg)
	}
}

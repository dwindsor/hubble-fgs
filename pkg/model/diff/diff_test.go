// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package diff

import (
	"context"
	"math"
	"slices"
	"testing"
	"time"

	appModelV1 "github.com/isovalent/ipa/application_model/v1alpha"
	common "github.com/isovalent/ipa/common/k8s/type/v1alpha"
	commonNetV1 "github.com/isovalent/ipa/common/net/v1alpha"
	graphV1 "github.com/isovalent/ipa/graph/v1alpha"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/isovalent/hubble-fgs/pkg/model"
	"github.com/isovalent/hubble-fgs/pkg/node/local"
)

func connStatsA() *appModelV1.ConnectionStats {
	return &appModelV1.ConnectionStats{
		TxBytes:               10,
		RxBytes:               20,
		TxDrops:               30, //nolint:staticcheck // deprecated, populated for backwards compatibility with TxDropBytes
		TxDropBytes:           30,
		TxDropPackets:         3,
		DefaultDropBytes:      15,
		DefaultAllowBytes:     25,
		DefaultDropPackets:    5,
		DefaultAllowPackets:   7,
		RxDropBytes:           40,
		RxDropPackets:         8,
		RxDefaultDropBytes:    12,
		RxDefaultDropPackets:  4,
		RxDefaultAllowBytes:   18,
		RxDefaultAllowPackets: 6,
		Sessions:              7,
	}
}

func connStatsB() *appModelV1.ConnectionStats {
	return &appModelV1.ConnectionStats{
		TxBytes:               1,
		RxBytes:               2,
		TxDrops:               3, //nolint:staticcheck // deprecated, populated for backwards compatibility with TxDropBytes
		TxDropBytes:           3,
		TxDropPackets:         1,
		DefaultDropBytes:      1,
		DefaultAllowBytes:     2,
		DefaultDropPackets:    1,
		DefaultAllowPackets:   2,
		RxDropBytes:           10,
		RxDropPackets:         2,
		RxDefaultDropBytes:    3,
		RxDefaultDropPackets:  1,
		RxDefaultAllowBytes:   5,
		RxDefaultAllowPackets: 2,
		Sessions:              2,
	}
}

func connStatsDiff() *appModelV1.ConnectionStats {
	return &appModelV1.ConnectionStats{
		TxBytes:               9,
		RxBytes:               18,
		TxDrops:               27, //nolint:staticcheck // deprecated, populated for backwards compatibility with TxDropBytes
		TxDropBytes:           27,
		TxDropPackets:         2,
		DefaultDropBytes:      14,
		DefaultAllowBytes:     23,
		DefaultDropPackets:    4,
		DefaultAllowPackets:   5,
		RxDropBytes:           30,
		RxDropPackets:         6,
		RxDefaultDropBytes:    9,
		RxDefaultDropPackets:  3,
		RxDefaultAllowBytes:   13,
		RxDefaultAllowPackets: 4,
		Sessions:              5,
	}
}

func connStatsEqual(t *testing.T, a, b *appModelV1.ConnectionStats) {
	assert.Equal(t, a.TxBytes, b.TxBytes)
	assert.Equal(t, a.RxBytes, b.RxBytes)
	assert.Equal(t, a.TxDropBytes, b.TxDropBytes)
	assert.Equal(t, a.TxDropPackets, b.TxDropPackets)
	assert.Equal(t, a.DefaultDropBytes, b.DefaultDropBytes)
	assert.Equal(t, a.DefaultAllowBytes, b.DefaultAllowBytes)
	assert.Equal(t, a.DefaultDropPackets, b.DefaultDropPackets)
	assert.Equal(t, a.DefaultAllowPackets, b.DefaultAllowPackets)
	assert.Equal(t, a.RxDropBytes, b.RxDropBytes)
	assert.Equal(t, a.RxDropPackets, b.RxDropPackets)
	assert.Equal(t, a.RxDefaultDropBytes, b.RxDefaultDropBytes)
	assert.Equal(t, a.RxDefaultDropPackets, b.RxDefaultDropPackets)
	assert.Equal(t, a.RxDefaultAllowBytes, b.RxDefaultAllowBytes)
	assert.Equal(t, a.RxDefaultAllowPackets, b.RxDefaultAllowPackets)
	assert.Equal(t, a.Sessions, b.Sessions)
}

func TestStatsDiff(t *testing.T) {
	a := connStatsA()
	b := connStatsB()
	abResult := connStatsDiff()

	diff, err := StatsDiff(a, b)
	assert.NoError(t, err)
	connStatsEqual(t, diff, abResult)
}

// TestStatsDiffUnderflow checks that every counter StatsDiff subtracts is
// guarded: a snapshot pair where the older value exceeds the newer one must be
// rejected rather than wrapping around.
func TestStatsDiffUnderflow(t *testing.T) {
	tests := []struct {
		name string
		bump func(*appModelV1.ConnectionStats, uint64)
	}{
		{name: "TxBytes", bump: func(s *appModelV1.ConnectionStats, v uint64) { s.TxBytes = v }},
		{name: "RxBytes", bump: func(s *appModelV1.ConnectionStats, v uint64) { s.RxBytes = v }},
		{name: "TxDropBytes", bump: func(s *appModelV1.ConnectionStats, v uint64) { s.TxDropBytes = v }},
		{name: "DefaultDropBytes", bump: func(s *appModelV1.ConnectionStats, v uint64) { s.DefaultDropBytes = v }},
		{name: "DefaultAllowBytes", bump: func(s *appModelV1.ConnectionStats, v uint64) { s.DefaultAllowBytes = v }},
		{name: "TxDropPackets", bump: func(s *appModelV1.ConnectionStats, v uint64) { s.TxDropPackets = v }},
		{name: "DefaultDropPackets", bump: func(s *appModelV1.ConnectionStats, v uint64) { s.DefaultDropPackets = v }},
		{name: "DefaultAllowPackets", bump: func(s *appModelV1.ConnectionStats, v uint64) { s.DefaultAllowPackets = v }},
		{name: "RxDropBytes", bump: func(s *appModelV1.ConnectionStats, v uint64) { s.RxDropBytes = v }},
		{name: "RxDropPackets", bump: func(s *appModelV1.ConnectionStats, v uint64) { s.RxDropPackets = v }},
		{name: "RxDefaultDropBytes", bump: func(s *appModelV1.ConnectionStats, v uint64) { s.RxDefaultDropBytes = v }},
		{name: "RxDefaultDropPackets", bump: func(s *appModelV1.ConnectionStats, v uint64) { s.RxDefaultDropPackets = v }},
		{name: "RxDefaultAllowBytes", bump: func(s *appModelV1.ConnectionStats, v uint64) { s.RxDefaultAllowBytes = v }},
		{name: "RxDefaultAllowPackets", bump: func(s *appModelV1.ConnectionStats, v uint64) { s.RxDefaultAllowPackets = v }},
		{name: "Sessions", bump: func(s *appModelV1.ConnectionStats, v uint64) { s.Sessions = v }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, b := connStatsA(), connStatsB()
			// b is the older snapshot, so pushing one of its counters above a's
			// is the underflow the guards exist to catch.
			tt.bump(b, math.MaxUint64)

			diff, err := StatsDiff(a, b)
			assert.Error(t, err)
			assert.Nil(t, diff)
		})
	}
}

func destA() *appModelV1.Destination {
	return &appModelV1.Destination{
		Type: &appModelV1.Destination_Ip{
			Ip: &appModelV1.DestinationIP{
				Ip: "10.0.0.1",
			},
		},
		Port: 80,
	}
}

func destB() *appModelV1.Destination {
	return &appModelV1.Destination{
		Type: &appModelV1.Destination_Dns{
			Dns: &appModelV1.DestinationDns{
				DestinationNames: []string{"ebpf.io", "isovalent.io", "cisco.com"},
			},
		},
		Port: 80,
	}
}

func destC() *appModelV1.Destination {
	return &appModelV1.Destination{
		Type: &appModelV1.Destination_Workload{
			Workload: &appModelV1.DestinationWorkload{
				Name:      "foo",
				Namespace: "fooNS",
				Kind:      common.WorkloadKind_WORKLOAD_KIND_POD,
			},
		},
		Port: 80,
	}
}

func policy() *appModelV1.NetworkPolicy {
	return &appModelV1.NetworkPolicy{
		PolicyName: "aTestPolicy",
	}
}

func conns() []*appModelV1.ApplicationConnection {
	a := make([]*appModelV1.ApplicationConnection, 2)

	a[0] = &appModelV1.ApplicationConnection{
		Destination: destA(),
		Stats:       connStatsA(),
		Policy:      policy(),
	}
	a[1] = &appModelV1.ApplicationConnection{
		Destination: destB(),
		Stats:       connStatsB(),
		Policy:      policy(),
	}
	return a
}

func TestConnectionStatsDiff(t *testing.T) {
	a := conns()
	b := conns()

	a[0].Stats.TxBytes++
	a[0].Stats.RxBytes += 2
	a[0].Stats.DefaultDropBytes++
	a[0].Stats.DefaultAllowBytes += 2

	a = append(a, &appModelV1.ApplicationConnection{
		Destination: destC(),
		Stats:       connStatsA(),
		Policy:      policy(),
	})

	d, err := ConnectionDiff(a, b)
	require.NoError(t, err)

	assert.Equal(t, 2, len(d))
	assert.Equal(t, uint64(1), d[0].Stats.TxBytes)
	assert.Equal(t, uint64(2), d[0].Stats.RxBytes)
	assert.Equal(t, uint64(1), d[0].Stats.DefaultDropBytes)
	assert.Equal(t, uint64(2), d[0].Stats.DefaultAllowBytes)
	assert.Equal(t, "aTestPolicy", d[0].Policy.PolicyName)

	assert.Equal(t, uint64(10), d[1].Stats.TxBytes)
	assert.Equal(t, uint64(20), d[1].Stats.RxBytes)
	assert.Equal(t, uint64(15), d[1].Stats.DefaultDropBytes)
	assert.Equal(t, uint64(25), d[1].Stats.DefaultAllowBytes)
	assert.Equal(t, "aTestPolicy", d[1].Policy.PolicyName)
}

func TestConnectionDiffDistinguishesProtocol(t *testing.T) {
	// Use distinct baseline stats for TCP and UDP so that incorrect cross-protocol
	// pairing produces wrong diff values (not just wrong order).
	tcpOld := &appModelV1.ConnectionStats{TxBytes: 10}
	udpOld := &appModelV1.ConnectionStats{TxBytes: 20}
	tcpNew := &appModelV1.ConnectionStats{TxBytes: 100}
	udpNew := &appModelV1.ConnectionStats{TxBytes: 200}

	a := []*appModelV1.ApplicationConnection{
		{Destination: destA(), Stats: tcpNew, Policy: policy(), Protocol: commonNetV1.IPProtocol_IP_PROTOCOL_TCP},
		{Destination: destA(), Stats: udpNew, Policy: policy(), Protocol: commonNetV1.IPProtocol_IP_PROTOCOL_UDP},
	}
	b := []*appModelV1.ApplicationConnection{
		{Destination: destA(), Stats: tcpOld, Policy: policy(), Protocol: commonNetV1.IPProtocol_IP_PROTOCOL_TCP},
		{Destination: destA(), Stats: udpOld, Policy: policy(), Protocol: commonNetV1.IPProtocol_IP_PROTOCOL_UDP},
	}

	d, err := ConnectionDiff(a, b)
	require.NoError(t, err)
	require.Len(t, d, 2)

	byProtocol := make(map[commonNetV1.IPProtocol]*appModelV1.ApplicationConnection)
	for _, conn := range d {
		byProtocol[conn.Protocol] = conn
	}
	require.Contains(t, byProtocol, commonNetV1.IPProtocol_IP_PROTOCOL_TCP)
	require.Contains(t, byProtocol, commonNetV1.IPProtocol_IP_PROTOCOL_UDP)

	// TCP must diff against TCP baseline (100-10=90), not UDP (100-20=80).
	assert.Equal(t, uint64(90), byProtocol[commonNetV1.IPProtocol_IP_PROTOCOL_TCP].Stats.TxBytes)
	// UDP must diff against UDP baseline (200-20=180), not TCP (200-10=190).
	assert.Equal(t, uint64(180), byProtocol[commonNetV1.IPProtocol_IP_PROTOCOL_UDP].Stats.TxBytes)
}

func TestConnectionDiffDistinguishesObservationPoint(t *testing.T) {
	// Use distinct baseline stats for each observation point so that pairing a
	// connection with its opposite-direction twin produces wrong diff values.
	srcOld := &appModelV1.ConnectionStats{TxBytes: 10}
	dstOld := &appModelV1.ConnectionStats{TxBytes: 20}
	srcNew := &appModelV1.ConnectionStats{TxBytes: 100}
	dstNew := &appModelV1.ConnectionStats{TxBytes: 200}

	udp := commonNetV1.IPProtocol_IP_PROTOCOL_UDP
	source := appModelV1.ObservationPoint_OBSERVATION_POINT_SOURCE
	destination := appModelV1.ObservationPoint_OBSERVATION_POINT_DESTINATION

	a := []*appModelV1.ApplicationConnection{
		{Destination: destA(), Stats: srcNew, Policy: policy(), Protocol: udp, ObservationPoint: source},
		{Destination: destA(), Stats: dstNew, Policy: policy(), Protocol: udp, ObservationPoint: destination},
	}
	b := []*appModelV1.ApplicationConnection{
		{Destination: destA(), Stats: srcOld, Policy: policy(), Protocol: udp, ObservationPoint: source},
		{Destination: destA(), Stats: dstOld, Policy: policy(), Protocol: udp, ObservationPoint: destination},
	}

	d, err := ConnectionDiff(a, b)
	require.NoError(t, err)
	require.Len(t, d, 2)

	byObservationPoint := make(map[appModelV1.ObservationPoint]*appModelV1.ApplicationConnection)
	for _, conn := range d {
		byObservationPoint[conn.ObservationPoint] = conn
	}
	require.Contains(t, byObservationPoint, source)
	require.Contains(t, byObservationPoint, destination)

	// SOURCE must diff against the SOURCE baseline (100-10=90).
	assert.Equal(t, uint64(90), byObservationPoint[source].Stats.TxBytes)
	// DESTINATION must diff against the DESTINATION baseline (200-20=180),
	// not SOURCE (200-10=190).
	assert.Equal(t, uint64(180), byObservationPoint[destination].Stats.TxBytes)
}

func TestConnectionDiffPreservesObservationPoint(t *testing.T) {
	// A connection observed at the destination on tick one must still report
	// that on tick two, when it is found in both models rather than freshly
	// appearing.
	a := []*appModelV1.ApplicationConnection{
		{
			Destination:      destA(),
			Stats:            &appModelV1.ConnectionStats{RxBytes: 20},
			Policy:           policy(),
			Protocol:         commonNetV1.IPProtocol_IP_PROTOCOL_UDP,
			ObservationPoint: appModelV1.ObservationPoint_OBSERVATION_POINT_DESTINATION,
		},
	}
	b := []*appModelV1.ApplicationConnection{
		{
			Destination:      destA(),
			Stats:            &appModelV1.ConnectionStats{RxBytes: 10},
			Policy:           policy(),
			Protocol:         commonNetV1.IPProtocol_IP_PROTOCOL_UDP,
			ObservationPoint: appModelV1.ObservationPoint_OBSERVATION_POINT_DESTINATION,
		},
	}

	d, err := ConnectionDiff(a, b)
	require.NoError(t, err)
	require.Len(t, d, 1)
	assert.Equal(t, appModelV1.ObservationPoint_OBSERVATION_POINT_DESTINATION, d[0].ObservationPoint)
}

func psGroup() []*appModelV1.ApplicationProcessGroup {
	a := make([]*appModelV1.ApplicationProcessGroup, 2)

	a[0] = &appModelV1.ApplicationProcessGroup{
		Hash:            "0xabcd",
		Name:            "foolishFish",
		Arguments:       "havingFun",
		Children:        []*appModelV1.ApplicationProcessGroup{},
		SyscallInfo:     nil,
		ProcessCount:    1,
		LatestStartTime: nil,
		ExecutionCount:  2,
		ExitCount:       1,
	}

	a[1] = &appModelV1.ApplicationProcessGroup{
		Hash:            "0x1234",
		Name:            "ci",
		Arguments:       "makesThingsWork",
		Children:        []*appModelV1.ApplicationProcessGroup{},
		SyscallInfo:     nil,
		ProcessCount:    1,
		LatestStartTime: nil,
		ExecutionCount:  3,
		ExitCount:       2,
	}
	return a
}

func TestProcessDiff(t *testing.T) {
	aSet := psGroup()
	bSet := psGroup()

	bSet[1].Name = "ciNew"
	bSet[1].Arguments = "NewCIIsBest"

	network, process, err := ProcessDiff(aSet, bSet)

	assert.NoError(t, err)
	assert.Equal(t, 1, len(process))
	assert.Equal(t, 0, len(network))
}

func TestProcessConnectDiff(t *testing.T) {
	aSet := psGroup()
	bSet := psGroup()

	a := conns()
	b := conns()

	aSet[1].Connections = a
	bSet[1].Connections = b
	bSet[1].Connections[0].Stats.TxBytes = 1

	network, process, err := ProcessDiff(aSet, bSet)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(network))
	assert.Equal(t, 1, len(network[0].Connections))
	assert.Equal(t, uint64(9), network[0].Connections[0].Stats.TxBytes)
	assert.Equal(t, 0, len(process))
}

func TestProcessDiffExecIDs(t *testing.T) {
	aSet := psGroup()
	bSet := psGroup()

	aSet[1].ExecIds = []string{"exec-id-1", "exec-id-2"}

	network, process, err := ProcessDiff(aSet, bSet)

	assert.NoError(t, err)
	assert.Empty(t, network)
	require.Len(t, process, 1)
	assert.Equal(t, []string{"exec-id-1", "exec-id-2"}, process[0].GetExecIds())
}

func TestProcessNetworkConnectDiff(t *testing.T) {
	aSet := psGroup()
	bSet := psGroup()

	a := conns()
	b := conns()

	aSet[1].Connections = a
	aSet[1].Connections[0].Stats.TxBytes = 2
	aSet[1].Connections[1].Stats.TxBytes = 3
	aSet[1].Arguments = "NewCIIsBest"
	bSet[1].Connections = b

	network, process, err := ProcessDiff(aSet, bSet)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(network))
	assert.Equal(t, 2, len(network[0].Connections))
	assert.Equal(t, uint64(2), network[0].Connections[0].Stats.TxBytes)
	assert.Equal(t, uint64(3), network[0].Connections[1].Stats.TxBytes)
	assert.Equal(t, 1, len(process))
	assert.Equal(t, "ci", process[0].Name)
	assert.Equal(t, "NewCIIsBest", process[0].Arguments)
}

func containers() []*appModelV1.ApplicationContainer {
	a := make([]*appModelV1.ApplicationContainer, 2)

	ps0 := psGroup()
	ps1 := psGroup()
	psConns0 := conns()
	psConns1 := conns()

	ps0[1].Connections = psConns0
	ps1[1].Connections = psConns1

	a[0] = &appModelV1.ApplicationContainer{
		Id:        "325790f3086f4",
		Name:      "busybox1",
		Image:     "docker.io/library/busybox:latest",
		Processes: ps0,
	}

	a[1] = &appModelV1.ApplicationContainer{
		Id:        "bd019528d37c2",
		Name:      "busybox2",
		Image:     "docker.io/library/busybox:1.0",
		Processes: ps1,
	}

	return a
}

func workloads() []*appModelV1.ApplicationWorkload {
	a := make([]*appModelV1.ApplicationWorkload, 2)

	cont0 := containers()
	cont1 := containers()

	a[0] = &appModelV1.ApplicationWorkload{
		Name:       "workload2",
		Kind:       common.WorkloadKind_WORKLOAD_KIND_POD,
		Containers: cont0,
	}

	a[1] = &appModelV1.ApplicationWorkload{
		Name:       "workload1",
		Kind:       common.WorkloadKind_WORKLOAD_KIND_POD,
		Containers: cont1,
	}

	return a
}

func TestContainersEqual(t *testing.T) {
	aSet := containers()
	bSet := containers()
	network, process, err := ContainerDiff(aSet, bSet)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(process))
	assert.Equal(t, 0, len(network))
}

func TestContainerDiff(t *testing.T) {
	aSet := containers()
	bSet := containers()

	bSet[0].Processes[1].Connections[0].Stats.TxBytes = 1

	network, process, err := ContainerDiff(aSet, bSet)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(process))
	assert.Equal(t, 1, len(network))
	assert.Equal(t, 1, len(network[0].Processes))
	assert.Equal(t, 1, len(network[0].Processes[0].Connections))
	assert.Equal(t, uint64(9), network[0].Processes[0].Connections[0].Stats.TxBytes)
}

func TestContainerNetProcDiff(t *testing.T) {
	aSet := containers()
	bSet := containers()

	bSet[1].Processes[1].Connections[0].Stats.TxBytes = 1
	aSet[0].Processes[1].Arguments = "changes"

	network, process, err := ContainerDiff(aSet, bSet)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(process))
	assert.Equal(t, 1, len(process[0].Processes))
	assert.Equal(t, 2, len(process[0].Processes[0].Connections))
	assert.Equal(t, "ci", process[0].Processes[0].Name)
	assert.Equal(t, "changes", process[0].Processes[0].Arguments)

	assert.Equal(t, 2, len(network))

	assert.Equal(t, 1, len(network[0].Processes))
	assert.Equal(t, 2, len(network[0].Processes[0].Connections))
	assert.Equal(t, uint64(10), network[0].Processes[0].Connections[0].Stats.TxBytes)
	assert.Equal(t, uint64(1), network[0].Processes[0].Connections[1].Stats.TxBytes)

	assert.Equal(t, 1, len(network[1].Processes))
	assert.Equal(t, 1, len(network[1].Processes[0].Connections))
	assert.Equal(t, uint64(9), network[1].Processes[0].Connections[0].Stats.TxBytes)
}

func TestContainerIdDiff(t *testing.T) {
	aSet := containers()
	bSet := containers()

	aSet[0].Id = "325790f3086f4-changed"

	network, process, err := ContainerDiff(aSet, bSet)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(process))
	assert.Equal(t, 1, len(network))

	// Processes
	assert.Equal(t, 2, len(process[0].Processes))
	assert.Equal(t, 1, len(network[0].Processes))
	// Assert Process is copied through correctly.
	assert.Equal(t, "325790f3086f4-changed", process[0].Id)
	assert.Equal(t, "busybox1", process[0].Name)
	assert.Equal(t, "docker.io/library/busybox:latest", process[0].Image)
	assert.Equal(t, "foolishFish", process[0].Processes[0].Name)
	assert.Equal(t, "havingFun", process[0].Processes[0].Arguments)
	assert.Equal(t, "ci", process[0].Processes[1].Name)
	assert.Equal(t, "makesThingsWork", process[0].Processes[1].Arguments)
	// Assert Network is copied through correctly
	assert.Equal(t, "325790f3086f4-changed", network[0].Id)
	assert.Equal(t, "busybox1", network[0].Name)
	assert.Equal(t, "docker.io/library/busybox:latest", network[0].Image)
	assert.Equal(t, "ci", network[0].Processes[0].Name)
	assert.Equal(t, "makesThingsWork", network[0].Processes[0].Arguments)
	assert.Equal(t, 2, len(network[0].Processes[0].Connections))
	assert.Equal(t, uint64(10), network[0].Processes[0].Connections[0].Stats.TxBytes)
	assert.Equal(t, uint64(1), network[0].Processes[0].Connections[1].Stats.TxBytes)
}

func TestWorkloadEqual(t *testing.T) {
	aSet := workloads()
	bSet := workloads()
	network, process, err := WorkloadDiff(aSet, bSet)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(process))
	assert.Equal(t, 0, len(network))
}

func TestWorkloadDiff(t *testing.T) {
	aSet := workloads()
	bSet := workloads()

	bSet[0].Name = "workload2-changed"

	network, process, err := WorkloadDiff(aSet, bSet)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(network))
	assert.Equal(t, 1, len(process))
	assert.Equal(t, "workload2", process[0].Name)
	// Assert Process is copied through correctly
	assert.Equal(t, 2, len(process[0].Containers))
	assert.Equal(t, "325790f3086f4", process[0].Containers[0].Id)
	assert.Equal(t, "busybox1", process[0].Containers[0].Name)
	assert.Equal(t, "docker.io/library/busybox:latest", process[0].Containers[0].Image)
	assert.Equal(t, 2, len(process[0].Containers[0].Processes))
	assert.Equal(t, "bd019528d37c2", process[0].Containers[1].Id)
	assert.Equal(t, "busybox2", process[0].Containers[1].Name)
	assert.Equal(t, "docker.io/library/busybox:1.0", process[0].Containers[1].Image)
	assert.Equal(t, 2, len(process[0].Containers[1].Processes))

	// Assert Network is copied through correctly
	assert.Equal(t, 2, len(network[0].Containers))
	assert.Equal(t, "325790f3086f4", network[0].Containers[0].Id)
	assert.Equal(t, "busybox1", network[0].Containers[0].Name)
	assert.Equal(t, "docker.io/library/busybox:latest", network[0].Containers[0].Image)
	assert.Equal(t, 1, len(network[0].Containers[0].Processes))
	assert.Equal(t, uint64(10), network[0].Containers[0].Processes[0].Connections[0].Stats.TxBytes)
	assert.Equal(t, uint64(1), network[0].Containers[0].Processes[0].Connections[1].Stats.TxBytes)
	assert.Equal(t, "bd019528d37c2", network[0].Containers[1].Id)
	assert.Equal(t, "busybox2", network[0].Containers[1].Name)
	assert.Equal(t, "docker.io/library/busybox:1.0", network[0].Containers[1].Image)
	assert.Equal(t, 1, len(network[0].Containers[1].Processes))
	assert.Equal(t, uint64(10), network[0].Containers[1].Processes[0].Connections[0].Stats.TxBytes)
	assert.Equal(t, uint64(1), network[0].Containers[1].Processes[0].Connections[1].Stats.TxBytes)
}

func TestWorkloadDiffDistinguishesRecreatedWorkload(t *testing.T) {
	current := []*appModelV1.ApplicationWorkload{{
		Name: "api",
		Uid:  "new-uid",
	}}
	previous := []*appModelV1.ApplicationWorkload{{
		Name: "api",
		Uid:  "old-uid",
	}}

	_, process, err := WorkloadDiff(current, previous)
	require.NoError(t, err)
	require.Len(t, process, 1)
	assert.Equal(t, "new-uid", process[0].Uid)
}

func TestWorkloadNetProcDiff(t *testing.T) {
	aSet := workloads()
	bSet := workloads()

	bSet[1].Containers[0].Processes[1].Connections[0].Stats.TxBytes = 1
	aSet[0].Containers[1].Processes[0].Arguments = "changes"

	network, process, err := WorkloadDiff(aSet, bSet)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(process))
	assert.Equal(t, "workload2", process[0].Name)
	assert.Equal(t, 1, len(process[0].Containers))
	assert.Equal(t, "bd019528d37c2", process[0].Containers[0].Id)
	assert.Equal(t, 1, len(process[0].Containers[0].Processes))
	assert.Equal(t, 0, len(process[0].Containers[0].Processes[0].Connections))
	assert.Equal(t, "foolishFish", process[0].Containers[0].Processes[0].Name)
	assert.Equal(t, "changes", process[0].Containers[0].Processes[0].Arguments)

	assert.Equal(t, 1, len(network))
	assert.Equal(t, "workload1", network[0].Name)
	assert.Equal(t, 1, len(network[0].Containers))
	assert.Equal(t, "325790f3086f4", network[0].Containers[0].Id)
	assert.Equal(t, 1, len(network[0].Containers[0].Processes))
	assert.Equal(t, 1, len(network[0].Containers[0].Processes[0].Connections))
	assert.Equal(t, "ci", network[0].Containers[0].Processes[0].Name)
	assert.Equal(t, uint64(9), network[0].Containers[0].Processes[0].Connections[0].Stats.TxBytes)
}

func hostModel() *appModelV1.ApplicationHost {
	aSet := psGroup()

	a := conns()
	aSet[1].Connections = a

	return &appModelV1.ApplicationHost{
		Processes: aSet,
	}
}

func appModel() *appModelV1.ApplicationModel {
	wl1 := workloads()
	wl2 := workloads()

	ns1 := &appModelV1.ApplicationNamespace{
		Name:      "ns1",
		Workloads: wl1,
	}
	ns2 := &appModelV1.ApplicationNamespace{
		Name:      "ns2",
		Workloads: wl2,
	}
	ns := []*appModelV1.ApplicationNamespace{ns1, ns2}

	model := &appModelV1.ApplicationModel{
		Namespaces: ns,
	}

	return model
}

func TestApplicationModelEqual(t *testing.T) {
	aModel := appModel()
	bModel := appModel()

	_, d, err := ApplicationModelDiff(aModel, bModel)
	assert.NoError(t, err)
	assert.Nil(t, d)
}

func TestApplicationModelDiff(t *testing.T) {
	aModel := appModel()
	bModel := appModel()
	bModel.Namespaces[0].Workloads[0].Containers[0].Processes[1].Connections[0].Stats.TxBytes = 1

	network, process, err := ApplicationModelDiff(aModel, bModel)
	assert.NoError(t, err)
	assert.Nil(t, process)
	assert.Equal(t, 1, len(network.Namespaces))
	assert.Equal(t, 1, len(network.Namespaces[0].Workloads))
	assert.Equal(t, 1, len(network.Namespaces[0].Workloads[0].Containers[0].Processes))
	assert.Equal(t, 1, len(network.Namespaces[0].Workloads[0].Containers[0].Processes[0].Connections))
	assert.Equal(t, uint64(9), network.Namespaces[0].Workloads[0].Containers[0].Processes[0].Connections[0].Stats.TxBytes)
}

func TestApplicationModelProcNetDiff(t *testing.T) {
	aModel := appModel()
	bModel := appModel()
	bModel.Namespaces[0].Workloads[0].Containers[0].Processes[1].Connections[0].Stats.TxBytes = 1
	aModel.Namespaces[1].Workloads[1].Containers[0].Processes[1].Arguments = "changes"

	network, process, err := ApplicationModelDiff(aModel, bModel)
	assert.NoError(t, err)
	assert.NotNil(t, network)
	assert.NotNil(t, process)

	assert.Equal(t, 1, len(process.Namespaces))
	assert.Equal(t, 2, len(network.Namespaces))

	// TxBytes inc adds a single process Connection to network
	assert.Equal(t, 1, len(network.Namespaces[0].Workloads))
	assert.Equal(t, 1, len(network.Namespaces[0].Workloads[0].Containers))
	assert.Equal(t, 1, len(network.Namespaces[0].Workloads[0].Containers[0].Processes))
	assert.Equal(t, 1, len(network.Namespaces[0].Workloads[0].Containers[0].Processes[0].Connections))
	assert.Equal(t, uint64(9), network.Namespaces[0].Workloads[0].Containers[0].Processes[0].Connections[0].Stats.TxBytes)
	// Args change adds two new process Connections to network
	assert.Equal(t, 1, len(network.Namespaces[1].Workloads))
	assert.Equal(t, 1, len(network.Namespaces[0].Workloads[0].Containers))
	assert.Equal(t, 1, len(network.Namespaces[1].Workloads[0].Containers[0].Processes))
	assert.Equal(t, 2, len(network.Namespaces[1].Workloads[0].Containers[0].Processes[0].Connections))
	assert.Equal(t, uint64(10), network.Namespaces[1].Workloads[0].Containers[0].Processes[0].Connections[0].Stats.TxBytes)
	assert.Equal(t, uint64(1), network.Namespaces[1].Workloads[0].Containers[0].Processes[0].Connections[1].Stats.TxBytes)
	// Arguments impact to process
	assert.Equal(t, 1, len(process.Namespaces[0].Workloads))
	assert.Equal(t, 1, len(process.Namespaces[0].Workloads[0].Containers))
	assert.Equal(t, 1, len(process.Namespaces[0].Workloads[0].Containers[0].Processes))
	assert.Equal(t, "ci", process.Namespaces[0].Workloads[0].Containers[0].Processes[0].Name)
	assert.Equal(t, "changes", process.Namespaces[0].Workloads[0].Containers[0].Processes[0].Arguments)
}

func TestApplicationModelNSDiff(t *testing.T) {
	aModel := appModel()
	bModel := appModel()

	aModel.Namespaces[0].Name = "new-ns"

	network, process, err := ApplicationModelDiff(aModel, bModel)
	assert.NoError(t, err)
	assert.NotNil(t, network)
	assert.NotNil(t, process)

	assert.Equal(t, 1, len(process.Namespaces))
	assert.Equal(t, 1, len(network.Namespaces))

	assert.Equal(t, 2, len(network.Namespaces[0].Workloads))
	assert.Equal(t, 2, len(network.Namespaces[0].Workloads[0].Containers))
	assert.Equal(t, 1, len(network.Namespaces[0].Workloads[0].Containers[0].Processes))
	assert.Equal(t, 2, len(network.Namespaces[0].Workloads[0].Containers[0].Processes[0].Connections))
	assert.Equal(t, uint64(10), network.Namespaces[0].Workloads[0].Containers[0].Processes[0].Connections[0].Stats.TxBytes)
	assert.Equal(t, uint64(1), network.Namespaces[0].Workloads[0].Containers[0].Processes[0].Connections[1].Stats.TxBytes)
	assert.Equal(t, 1, len(network.Namespaces[0].Workloads[0].Containers[1].Processes))
	assert.Equal(t, 2, len(network.Namespaces[0].Workloads[0].Containers[1].Processes[0].Connections))
	assert.Equal(t, uint64(10), network.Namespaces[0].Workloads[0].Containers[1].Processes[0].Connections[0].Stats.TxBytes)
	assert.Equal(t, uint64(1), network.Namespaces[0].Workloads[0].Containers[1].Processes[0].Connections[1].Stats.TxBytes)
	assert.Equal(t, 2, len(network.Namespaces[0].Workloads[1].Containers))
	assert.Equal(t, 1, len(network.Namespaces[0].Workloads[1].Containers[0].Processes))
	assert.Equal(t, 2, len(network.Namespaces[0].Workloads[1].Containers[0].Processes[0].Connections))
	assert.Equal(t, uint64(10), network.Namespaces[0].Workloads[1].Containers[0].Processes[0].Connections[0].Stats.TxBytes)
	assert.Equal(t, uint64(1), network.Namespaces[0].Workloads[1].Containers[0].Processes[0].Connections[1].Stats.TxBytes)
	assert.Equal(t, 1, len(network.Namespaces[0].Workloads[1].Containers[1].Processes))
	assert.Equal(t, 2, len(network.Namespaces[0].Workloads[1].Containers[1].Processes[0].Connections))
	assert.Equal(t, uint64(10), network.Namespaces[0].Workloads[1].Containers[1].Processes[0].Connections[0].Stats.TxBytes)
	assert.Equal(t, uint64(1), network.Namespaces[0].Workloads[1].Containers[1].Processes[0].Connections[1].Stats.TxBytes)

	assert.Equal(t, 2, len(process.Namespaces[0].Workloads))
	assert.Equal(t, 2, len(process.Namespaces[0].Workloads[0].Containers))
	assert.Equal(t, 2, len(process.Namespaces[0].Workloads[0].Containers[0].Processes))
	assert.Equal(t, 0, len(process.Namespaces[0].Workloads[0].Containers[0].Processes[0].Connections))
	assert.Equal(t, 2, len(process.Namespaces[0].Workloads[0].Containers[0].Processes[1].Connections))
	assert.Equal(t, uint64(10), process.Namespaces[0].Workloads[0].Containers[0].Processes[1].Connections[0].Stats.TxBytes)
	assert.Equal(t, uint64(1), process.Namespaces[0].Workloads[0].Containers[0].Processes[1].Connections[1].Stats.TxBytes)
	assert.Equal(t, 2, len(process.Namespaces[0].Workloads[0].Containers[1].Processes))
	assert.Equal(t, 0, len(process.Namespaces[0].Workloads[0].Containers[1].Processes[0].Connections))
	assert.Equal(t, 2, len(process.Namespaces[0].Workloads[0].Containers[1].Processes[1].Connections))
	assert.Equal(t, uint64(10), process.Namespaces[0].Workloads[0].Containers[1].Processes[1].Connections[0].Stats.TxBytes)
	assert.Equal(t, uint64(1), process.Namespaces[0].Workloads[0].Containers[1].Processes[1].Connections[1].Stats.TxBytes)
	assert.Equal(t, 2, len(process.Namespaces[0].Workloads[1].Containers))
	assert.Equal(t, 2, len(process.Namespaces[0].Workloads[1].Containers[0].Processes))
	assert.Equal(t, 0, len(process.Namespaces[0].Workloads[1].Containers[0].Processes[0].Connections))
	assert.Equal(t, 2, len(process.Namespaces[0].Workloads[1].Containers[0].Processes[1].Connections))
	assert.Equal(t, uint64(10), process.Namespaces[0].Workloads[1].Containers[0].Processes[1].Connections[0].Stats.TxBytes)
	assert.Equal(t, uint64(1), process.Namespaces[0].Workloads[1].Containers[0].Processes[1].Connections[1].Stats.TxBytes)
	assert.Equal(t, 2, len(process.Namespaces[0].Workloads[1].Containers[1].Processes))
	assert.Equal(t, 0, len(process.Namespaces[0].Workloads[1].Containers[1].Processes[0].Connections))
	assert.Equal(t, 2, len(process.Namespaces[0].Workloads[1].Containers[1].Processes[1].Connections))
	assert.Equal(t, uint64(10), process.Namespaces[0].Workloads[1].Containers[1].Processes[1].Connections[0].Stats.TxBytes)
	assert.Equal(t, uint64(1), process.Namespaces[0].Workloads[1].Containers[1].Processes[1].Connections[1].Stats.TxBytes)
	assert.Equal(t, "new-ns", process.Namespaces[0].Name)
}

func TestToNetworkFlat(t *testing.T) {
	ctx := context.Background()

	aModel := appModel()
	aModel.Id = "u-u-i-d"
	bModel := appModel()
	bModel.Namespaces[0].Workloads[0].Containers[0].Processes[1].Connections[0].Stats.TxBytes = 1
	bModel.Namespaces[1].Workloads[1].Containers[1].Processes[1].Connections[1].Stats.RxBytes = 1
	// Drop the byte and packet baselines by different amounts so the flattened
	// values distinguish the two units.
	bModel.Namespaces[0].Workloads[0].Containers[0].Processes[1].Connections[0].Stats.TxDropBytes = 10
	bModel.Namespaces[0].Workloads[0].Containers[0].Processes[1].Connections[0].Stats.TxDropPackets = 1
	// Every default-action counter gets its own delta, so a field wired to the
	// wrong source reads a value that belongs to another counter.
	bModel.Namespaces[0].Workloads[0].Containers[0].Processes[1].Connections[0].Stats.DefaultDropBytes = 5
	bModel.Namespaces[0].Workloads[0].Containers[0].Processes[1].Connections[0].Stats.DefaultAllowBytes = 10
	bModel.Namespaces[0].Workloads[0].Containers[0].Processes[1].Connections[0].Stats.DefaultDropPackets = 2
	bModel.Namespaces[0].Workloads[0].Containers[0].Processes[1].Connections[0].Stats.DefaultAllowPackets = 3

	network, process, err := ApplicationModelDiff(aModel, bModel)
	assert.NoError(t, err)

	assert.Nil(t, process)
	assert.Equal(t, 2, len(network.Namespaces))

	f, err := ApplicationModelToNetworkFlat(ctx, network, &local.NoopMetadataService{})
	assert.NoError(t, err)
	assert.Equal(t, "ns1", f[0].KubernetesNamespace)
	assert.Equal(t, "ns2", f[1].KubernetesNamespace)
	assert.Equal(t, "workload2", f[0].KubernetesWorkloadName)
	assert.Equal(t, "workload1", f[1].KubernetesWorkloadName)
	assert.Equal(t, "325790f3086f4", f[0].Container.Id)
	assert.Equal(t, "bd019528d37c2", f[1].Container.Id)
	assert.Equal(t, "ci", f[0].ProcessName)
	assert.Equal(t, "ci", f[1].ProcessName)
	assert.Equal(t, "makesThingsWork", f[0].ProcessArguments)
	assert.Equal(t, "makesThingsWork", f[1].ProcessArguments)
	assert.Equal(t, "10.0.0.1", f[0].DestinationName)
	assert.Equal(t, "cisco.com", f[1].DestinationName)
	assert.Equal(t, appModelV1.DestinationType_DESTINATION_TYPE_CIDR, f[0].DestinationType)
	assert.Equal(t, appModelV1.DestinationType_DESTINATION_TYPE_DNS, f[1].DestinationType)
	assert.Equal(t, uint32(80), f[0].DestinationPort)
	assert.Equal(t, uint32(80), f[1].DestinationPort)
	assert.Equal(t, uint64(9), f[0].TxBytes)
	assert.Equal(t, uint64(0), f[1].TxBytes)
	assert.Equal(t, uint64(0), f[0].RxBytes)
	assert.Equal(t, uint64(1), f[1].RxBytes)
	assert.Equal(t, uint64(20), f[0].TxDropBytes)
	assert.Equal(t, uint64(2), f[0].TxDropPackets)
	assert.Equal(t, uint64(10), f[0].DefaultDropBytes)
	assert.Equal(t, uint64(15), f[0].DefaultAllowBytes)
	assert.Equal(t, uint64(3), f[0].DefaultDropPackets)
	assert.Equal(t, uint64(4), f[0].DefaultAllowPackets)
	// TxDrops is deprecated and still mirrors the byte count.
	assert.Equal(t, uint64(20), f[0].TxDrops) //nolint:staticcheck
	assert.Equal(t, aModel.Id, f[0].ApplicationModelId)
	assert.Equal(t, aModel.Id, f[1].ApplicationModelId)

	// Verify Id field is populated with unique UUIDs
	assert.NotEmpty(t, f[0].Id, "network telemetry Id should not be empty")
	assert.NotEmpty(t, f[1].Id, "network telemetry Id should not be empty")
	assert.NotEqual(t, f[0].Id, f[1].Id, "network telemetry Ids should be unique")
}

// TestToNetworkFlatSessions checks that a session count increment is the only
// change needed to produce a telemetry entry, and that the exported value is the
// delta rather than the cumulative count held in the model.
func TestToNetworkFlatSessions(t *testing.T) {
	ctx := context.Background()

	aModel := appModel()
	aModel.Id = "u-u-i-d"
	bModel := appModel()

	conn := aModel.Namespaces[0].Workloads[0].Containers[0].Processes[1].Connections[0]
	old := bModel.Namespaces[0].Workloads[0].Containers[0].Processes[1].Connections[0]
	conn.Stats.Sessions = old.Stats.Sessions + 3

	network, process, err := ApplicationModelDiff(aModel, bModel)
	require.NoError(t, err)
	assert.Nil(t, process)
	require.NotNil(t, network)

	f, err := ApplicationModelToNetworkFlat(ctx, network, &local.NoopMetadataService{})
	require.NoError(t, err)
	require.Len(t, f, 1)
	assert.Equal(t, uint64(3), f[0].Sessions)
}

func TestToNetworkFlatHost(t *testing.T) {
	ctx := context.Background()

	aHost := hostModel()
	bHost := hostModel()
	bHost.Processes[1].Connections[0].Stats.TxBytes = 1
	// Drop the byte and packet baselines by different amounts so the flattened
	// values distinguish the two units.
	bHost.Processes[1].Connections[0].Stats.TxDropBytes = 10
	bHost.Processes[1].Connections[0].Stats.TxDropPackets = 1
	// Every default-action counter gets its own delta, so a field wired to the
	// wrong source reads a value that belongs to another counter.
	bHost.Processes[1].Connections[0].Stats.DefaultDropBytes = 5
	bHost.Processes[1].Connections[0].Stats.DefaultAllowBytes = 10
	bHost.Processes[1].Connections[0].Stats.DefaultDropPackets = 2
	bHost.Processes[1].Connections[0].Stats.DefaultAllowPackets = 3

	aModel := &appModelV1.ApplicationModel{
		Namespaces: []*appModelV1.ApplicationNamespace{},
		Host:       aHost,
		Id:         "u-u-i-d",
	}
	bModel := &appModelV1.ApplicationModel{
		Namespaces: []*appModelV1.ApplicationNamespace{},
		Host:       bHost,
	}

	network, process, err := ApplicationModelDiff(aModel, bModel)
	assert.NoError(t, err)
	assert.Nil(t, process)

	f, err := ApplicationModelToNetworkFlat(ctx, network, &local.NoopMetadataService{})
	assert.NoError(t, err)
	assert.Equal(t, "", f[0].KubernetesNamespace)
	assert.Equal(t, "", f[0].KubernetesWorkloadName)
	assert.Equal(t, "ci", f[0].ProcessName)
	assert.Equal(t, "makesThingsWork", f[0].ProcessArguments)
	assert.Equal(t, "10.0.0.1", f[0].DestinationName)
	assert.Equal(t, appModelV1.DestinationType_DESTINATION_TYPE_CIDR, f[0].DestinationType)
	assert.Equal(t, uint32(80), f[0].DestinationPort)
	assert.Equal(t, uint64(9), f[0].TxBytes)
	assert.Equal(t, uint64(0), f[0].RxBytes)
	assert.Equal(t, uint64(20), f[0].TxDropBytes)
	assert.Equal(t, uint64(2), f[0].TxDropPackets)
	assert.Equal(t, uint64(10), f[0].DefaultDropBytes)
	assert.Equal(t, uint64(15), f[0].DefaultAllowBytes)
	assert.Equal(t, uint64(3), f[0].DefaultDropPackets)
	assert.Equal(t, uint64(4), f[0].DefaultAllowPackets)
	// TxDrops is deprecated and still mirrors the byte count.
	assert.Equal(t, uint64(20), f[0].TxDrops) //nolint:staticcheck
	assert.Equal(t, aModel.Id, f[0].ApplicationModelId)

	// Verify Id field is populated
	assert.NotEmpty(t, f[0].Id, "network telemetry Id should not be empty")
}

func TestToNetworkFlatProtocol(t *testing.T) {
	ctx := context.Background()

	ps := []*appModelV1.ApplicationProcessGroup{{
		Name: "test",
		Connections: []*appModelV1.ApplicationConnection{
			{
				Destination: destA(),
				Stats:       connStatsA(),
				Policy:      policy(),
				Protocol:    commonNetV1.IPProtocol_IP_PROTOCOL_TCP,
			},
			{
				Destination: destB(),
				Stats:       connStatsB(),
				Policy:      policy(),
				Protocol:    commonNetV1.IPProtocol_IP_PROTOCOL_UDP,
			},
		},
	}}
	m := &appModelV1.ApplicationModel{
		Id:   "proto-test",
		Host: &appModelV1.ApplicationHost{Processes: ps},
	}

	f, err := ApplicationModelToNetworkFlat(ctx, m, &local.NoopMetadataService{})
	require.NoError(t, err)
	require.Len(t, f, 2)

	byDest := make(map[string]*appModelV1.NetworkConnectTelemetry)
	for _, entry := range f {
		byDest[entry.DestinationName] = entry
	}

	assert.Equal(t, commonNetV1.IPProtocol_IP_PROTOCOL_TCP,
		byDest["10.0.0.1"].Protocol)
	assert.Equal(t, commonNetV1.IPProtocol_IP_PROTOCOL_UDP,
		byDest["ebpf.io"].Protocol)
}

// This is broken after IPA upgrades the UNSPECIFIED should be a service.
func Test_getDestination(t *testing.T) {
	dest := appModelV1.Destination{
		Type: &appModelV1.Destination_Workload{
			Workload: &appModelV1.DestinationWorkload{
				Name:         "kubernetes",
				Namespace:    "default",
				Kind:         common.WorkloadKind_WORKLOAD_KIND_UNSPECIFIED,
				ResourceKind: common.ResourceKind_RESOURCE_KIND_SERVICE,
				Uid:          "service-uid",
			},
		},
		Port: 1234,
	}
	name, namespace, workloadName, workloadKind, resourceKind, uid := getDestination(&dest)
	assert.Equal(t, "default:WORKLOAD_KIND_UNSPECIFIED:kubernetes", name)
	assert.Equal(t, dest.GetWorkload().GetNamespace(), namespace)
	assert.Equal(t, dest.GetWorkload().GetName(), workloadName)
	assert.Equal(t, dest.GetWorkload().GetKind(), workloadKind)
	assert.Equal(t, dest.GetWorkload().GetResourceKind(), resourceKind)
	assert.Equal(t, "service-uid", uid)
}

func TestNetworkFlatIncludesResourceIdentity(t *testing.T) {
	applicationModel := &appModelV1.ApplicationModel{
		Namespaces: []*appModelV1.ApplicationNamespace{{
			Name: "client",
			Workloads: []*appModelV1.ApplicationWorkload{{
				Name: "api",
				Uid:  "source-uid",
				Containers: []*appModelV1.ApplicationContainer{{
					Processes: []*appModelV1.ApplicationProcessGroup{{
						Connections: []*appModelV1.ApplicationConnection{{
							Destination: &appModelV1.Destination{
								Type: &appModelV1.Destination_Workload{
									Workload: &appModelV1.DestinationWorkload{
										Name:      "server",
										Namespace: "backend",
										Uid:       "destination-uid",
									},
								},
							},
							Stats:  &appModelV1.ConnectionStats{},
							Policy: &appModelV1.NetworkPolicy{},
						}},
					}},
				}},
			}},
		}},
	}

	telemetry, err := ApplicationModelToNetworkFlat(
		context.Background(), applicationModel, &local.NoopMetadataService{})
	require.NoError(t, err)
	require.Len(t, telemetry, 1)
	assert.Equal(t, "source-uid", telemetry[0].KubernetesWorkloadUid)
	assert.Equal(t, "destination-uid", telemetry[0].DestinationKubernetesResourceUid)
}

func TestTelemetryToConnection(t *testing.T) {
	tests := []struct {
		name      string
		telemetry *appModelV1.NetworkConnectTelemetry
		expected  *graphV1.Connection
	}{
		{
			name: "DNS destination type",
			telemetry: &appModelV1.NetworkConnectTelemetry{
				EventType:                         appModelV1.TelemetryType_TELEMETRY_TYPE_NETWORK_CONNECT,
				ClusterName:                       "my-cluster",
				NodeName:                          "my-node",
				KubernetesNamespace:               "tetragon",
				KubernetesWorkloadKind:            common.WorkloadKind_WORKLOAD_KIND_DEPLOYMENT,
				DestinationKubernetesResourceKind: common.ResourceKind_RESOURCE_KIND_WORKLOAD,
				KubernetesWorkloadName:            "tetragon-grafana",
				DestinationName:                   "grafana.com",
				DestinationType:                   appModelV1.DestinationType_DESTINATION_TYPE_DNS,
				DestinationPort:                   443,
				TxBytes:                           1234,
				ApplicationModelId:                "u-u-i-d",
				Protocol:                          commonNetV1.IPProtocol_IP_PROTOCOL_TCP,
			},
			expected: &graphV1.Connection{
				Source: &graphV1.Vertex{
					Family: &graphV1.Vertex_Kubernetes{
						Kubernetes: &graphV1.VertexFamilyKubernetes{
							ResourceName:         "tetragon-grafana",
							ResourceKind:         common.ResourceKind_RESOURCE_KIND_WORKLOAD,
							ClusterName:          "my-cluster",
							Namespace:            "tetragon",
							NodeName:             "my-node",
							WorkloadKind:         common.WorkloadKind_WORKLOAD_KIND_DEPLOYMENT,
							IpProtocol:           commonNetV1.IPProtocol_IP_PROTOCOL_TCP,
							ApplicationModelUuid: "u-u-i-d",
						},
					},
				},
				Destination: &graphV1.Vertex{
					Family: &graphV1.Vertex_WorldEntity{
						WorldEntity: &graphV1.VertexFamilyWorldEntity{
							DnsName:    "grafana.com",
							Port:       443,
							IpProtocol: commonNetV1.IPProtocol_IP_PROTOCOL_TCP,
						},
					},
				},
				Links: []*graphV1.Edge{
					{
						Type: &graphV1.Edge_NetworkTelemetry{
							NetworkTelemetry: &graphV1.EdgeTypeNetworkTelemetry{
								NetworkTransmitBytesTotal: 1234,
							},
						},
					},
				},
				ObservationPoint: graphV1.ObservationPoint_OBSERVATION_POINT_SOURCE,
			},
		},
		{
			name: "CIDR destination type",
			telemetry: &appModelV1.NetworkConnectTelemetry{
				EventType:              appModelV1.TelemetryType_TELEMETRY_TYPE_NETWORK_CONNECT,
				ClusterName:            "my-cluster",
				NodeName:               "my-node",
				KubernetesNamespace:    "tetragon",
				KubernetesWorkloadKind: common.WorkloadKind_WORKLOAD_KIND_DEPLOYMENT,
				KubernetesWorkloadName: "tetragon-grafana",
				DestinationName:        "192.168.0.2",
				DestinationType:        appModelV1.DestinationType_DESTINATION_TYPE_CIDR,
				DestinationPort:        443,
				TxBytes:                1234,
				ApplicationModelId:     "u-u-i-d",
			},
			expected: &graphV1.Connection{
				Source: &graphV1.Vertex{
					Family: &graphV1.Vertex_Kubernetes{
						Kubernetes: &graphV1.VertexFamilyKubernetes{
							ResourceName:         "tetragon-grafana",
							ResourceKind:         common.ResourceKind_RESOURCE_KIND_WORKLOAD,
							ClusterName:          "my-cluster",
							Namespace:            "tetragon",
							NodeName:             "my-node",
							WorkloadKind:         common.WorkloadKind_WORKLOAD_KIND_DEPLOYMENT,
							ApplicationModelUuid: "u-u-i-d",
						},
					},
				},
				Destination: &graphV1.Vertex{
					Family: &graphV1.Vertex_WorldEntity{
						WorldEntity: &graphV1.VertexFamilyWorldEntity{
							Ip:   "192.168.0.2",
							Port: 443,
						},
					},
				},
				Links: []*graphV1.Edge{
					{
						Type: &graphV1.Edge_NetworkTelemetry{
							NetworkTelemetry: &graphV1.EdgeTypeNetworkTelemetry{
								NetworkTransmitBytesTotal: 1234,
							},
						},
					},
				},
				ObservationPoint: graphV1.ObservationPoint_OBSERVATION_POINT_SOURCE,
			},
		},
		{
			name: "k8s destination type",
			telemetry: &appModelV1.NetworkConnectTelemetry{
				EventType:                         appModelV1.TelemetryType_TELEMETRY_TYPE_NETWORK_CONNECT,
				ClusterName:                       "my-cluster",
				NodeName:                          "my-node",
				KubernetesNamespace:               "tetragon",
				KubernetesWorkloadKind:            common.WorkloadKind_WORKLOAD_KIND_DEPLOYMENT,
				KubernetesWorkloadName:            "tetragon-grafana",
				KubernetesWorkloadUid:             "source-uid",
				DestinationName:                   "192.168.0.2",
				DestinationType:                   appModelV1.DestinationType_DESTINATION_TYPE_KUBERNETES,
				DestinationKubernetesResourceKind: common.ResourceKind_RESOURCE_KIND_SERVICE,
				DestinationKubernetesNamespace:    "another-namespace",
				DestinationKubernetesResourceName: "another-service",
				DestinationKubernetesServiceKind:  common.ServiceKind_SERVICE_KIND_CLUSTER_IP,
				DestinationKubernetesWorkloadKind: common.WorkloadKind_WORKLOAD_KIND_DEPLOYMENT,
				DestinationKubernetesResourceUid:  "destination-uid",
				DestinationPort:                   443,
				TxBytes:                           1234,
				ApplicationModelId:                "u-u-i-d",
				Protocol:                          commonNetV1.IPProtocol_IP_PROTOCOL_UDP,
			},
			expected: &graphV1.Connection{
				Source: &graphV1.Vertex{
					Family: &graphV1.Vertex_Kubernetes{
						Kubernetes: &graphV1.VertexFamilyKubernetes{
							Uid:                  "source-uid",
							ResourceName:         "tetragon-grafana",
							ResourceKind:         common.ResourceKind_RESOURCE_KIND_WORKLOAD,
							ClusterName:          "my-cluster",
							Namespace:            "tetragon",
							NodeName:             "my-node",
							WorkloadKind:         common.WorkloadKind_WORKLOAD_KIND_DEPLOYMENT,
							IpProtocol:           commonNetV1.IPProtocol_IP_PROTOCOL_UDP,
							ApplicationModelUuid: "u-u-i-d",
						},
					},
				},
				Destination: &graphV1.Vertex{
					Family: &graphV1.Vertex_Kubernetes{
						Kubernetes: &graphV1.VertexFamilyKubernetes{
							Uid:          "destination-uid",
							ResourceKind: common.ResourceKind_RESOURCE_KIND_SERVICE,
							ResourceName: "another-service",
							ClusterName:  "my-cluster",
							Namespace:    "another-namespace",
							ServiceKind:  common.ServiceKind_SERVICE_KIND_CLUSTER_IP,
							WorkloadKind: common.WorkloadKind_WORKLOAD_KIND_DEPLOYMENT,
							Port:         443,
							IpProtocol:   commonNetV1.IPProtocol_IP_PROTOCOL_UDP,
						},
					},
				},
				Links: []*graphV1.Edge{
					{
						Type: &graphV1.Edge_NetworkTelemetry{
							NetworkTelemetry: &graphV1.EdgeTypeNetworkTelemetry{
								NetworkTransmitBytesTotal: 1234,
							},
						},
					},
				},
				ObservationPoint: graphV1.ObservationPoint_OBSERVATION_POINT_SOURCE,
			},
		},
		{
			name: "UDP receiver observed at destination",
			telemetry: &appModelV1.NetworkConnectTelemetry{
				EventType:              appModelV1.TelemetryType_TELEMETRY_TYPE_NETWORK_CONNECT,
				ClusterName:            "my-cluster",
				NodeName:               "my-node",
				KubernetesNamespace:    "tetragon",
				KubernetesWorkloadKind: common.WorkloadKind_WORKLOAD_KIND_DEPLOYMENT,
				KubernetesWorkloadName: "tetragon-grafana",
				DestinationName:        "192.168.0.2",
				DestinationType:        appModelV1.DestinationType_DESTINATION_TYPE_CIDR,
				DestinationPort:        443,
				TxBytes:                5678,
				RxBytes:                1234,
				TxDropPackets:          3,
				RxDropPackets:          7,
				ApplicationModelId:     "u-u-i-d",
				Protocol:               commonNetV1.IPProtocol_IP_PROTOCOL_UDP,
				ObservationPoint:       appModelV1.ObservationPoint_OBSERVATION_POINT_DESTINATION,
			},
			expected: &graphV1.Connection{
				Source: &graphV1.Vertex{
					Family: &graphV1.Vertex_WorldEntity{
						WorldEntity: &graphV1.VertexFamilyWorldEntity{
							Ip:         "192.168.0.2",
							Port:       443,
							IpProtocol: commonNetV1.IPProtocol_IP_PROTOCOL_UDP,
						},
					},
				},
				Destination: &graphV1.Vertex{
					Family: &graphV1.Vertex_Kubernetes{
						Kubernetes: &graphV1.VertexFamilyKubernetes{
							ResourceName:         "tetragon-grafana",
							ResourceKind:         common.ResourceKind_RESOURCE_KIND_WORKLOAD,
							ClusterName:          "my-cluster",
							Namespace:            "tetragon",
							NodeName:             "my-node",
							WorkloadKind:         common.WorkloadKind_WORKLOAD_KIND_DEPLOYMENT,
							IpProtocol:           commonNetV1.IPProtocol_IP_PROTOCOL_UDP,
							ApplicationModelUuid: "u-u-i-d",
						},
					},
				},
				Links: []*graphV1.Edge{
					{
						Type: &graphV1.Edge_NetworkTelemetry{
							NetworkTelemetry: &graphV1.EdgeTypeNetworkTelemetry{
								NetworkTransmitBytesTotal:      1234,
								NetworkTransmitDropTotal:       7,
								NetworkTransmitDropPolicyTotal: 7,
								NetworkReceiveBytesTotal:       5678,
								NetworkReceiveDropTotal:        3,
								NetworkReceiveDropPolicyTotal:  3,
							},
						},
					},
				},
				ObservationPoint: graphV1.ObservationPoint_OBSERVATION_POINT_DESTINATION,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			connection := TelemetryToConnection(tt.telemetry)
			assert.EqualExportedValues(t, tt.expected, connection)
		})
	}
}

// TestTelemetryToConnectionDropPackets guards against regressing the bug
// fixed by issue #8210: network_transmit_drop_total is documented as a packet
// count, so it must be fed TxDropPackets and not the byte count TxDrops.
func TestTelemetryToConnectionDropPackets(t *testing.T) {
	// All three drop fields hold distinct values, so reading any of the two
	// byte-denominated ones instead of the packet count is detectable.
	const (
		deprecatedBytes = 4400
		explicitBytes   = 5500
	)
	telemetry := &appModelV1.NetworkConnectTelemetry{
		EventType:       appModelV1.TelemetryType_TELEMETRY_TYPE_NETWORK_CONNECT,
		DestinationName: "192.168.0.2",
		DestinationType: appModelV1.DestinationType_DESTINATION_TYPE_CIDR,
		DestinationPort: 443,
		TxBytes:         1234,
		TxDrops:         deprecatedBytes, //nolint:staticcheck // deprecated, populated for backwards compatibility with TxDropBytes
		TxDropBytes:     explicitBytes,
		TxDropPackets:   7,
	}

	connection := TelemetryToConnection(telemetry)
	edge := connection.Links[0].GetNetworkTelemetry()
	assert.Equal(t, uint64(7), edge.NetworkTransmitDropTotal, "must report packet count")
	assert.NotEqual(t, uint64(deprecatedBytes), edge.NetworkTransmitDropTotal, "must not report deprecated byte count")
	assert.NotEqual(t, uint64(explicitBytes), edge.NetworkTransmitDropTotal, "must not report byte count")
	assert.Equal(t, uint64(1234), edge.NetworkTransmitBytesTotal)
}

// TestTelemetryToConnectionDropPolicyTotal checks that the policy drop total on
// the edge reads the transmit drop count under both deny shapes and stays a
// subset of the overall total. The subset is the network_transmit_drop_policy_subset
// CEL rule on EdgeTypeNetworkTelemetry, and no protovalidate runtime is vendored,
// so the rule is asserted here by hand.
func TestTelemetryToConnectionDropPolicyTotal(t *testing.T) {
	t.Run("fallthrough deny", func(t *testing.T) {
		// Distinct values, so reading either field from the other's source shows up.
		const (
			txDropPackets      = 9
			defaultDropPackets = 4
		)
		telemetry := &appModelV1.NetworkConnectTelemetry{
			EventType:          appModelV1.TelemetryType_TELEMETRY_TYPE_NETWORK_CONNECT,
			DestinationName:    "192.168.0.2",
			DestinationType:    appModelV1.DestinationType_DESTINATION_TYPE_CIDR,
			DestinationPort:    443,
			TxDropBytes:        5500,
			TxDropPackets:      txDropPackets,
			DefaultDropBytes:   2200,
			DefaultDropPackets: defaultDropPackets,
		}

		edge := TelemetryToConnection(telemetry).Links[0].GetNetworkTelemetry()
		assert.Equal(t, uint64(txDropPackets), edge.NetworkTransmitDropTotal)
		assert.Equal(t, uint64(txDropPackets), edge.NetworkTransmitDropPolicyTotal)
		assert.NotEqual(t, uint64(defaultDropPackets), edge.NetworkTransmitDropPolicyTotal,
			"must not report the default-action subset as the policy total")
		assert.LessOrEqual(t, edge.NetworkTransmitDropPolicyTotal, edge.NetworkTransmitDropTotal,
			"network_transmit_drop_policy_total must be <= network_transmit_drop_total")
	})

	// An explicit deny rule sets no fallthrough bit, so send() charges the packet
	// to tx_drop_packets alone. Reading DefaultDropPackets then reports no policy
	// drop against a nonzero total.
	t.Run("explicit deny", func(t *testing.T) {
		telemetry := &appModelV1.NetworkConnectTelemetry{
			EventType:       appModelV1.TelemetryType_TELEMETRY_TYPE_NETWORK_CONNECT,
			DestinationName: "192.168.0.2",
			DestinationType: appModelV1.DestinationType_DESTINATION_TYPE_CIDR,
			DestinationPort: 443,
			TxDropBytes:     700,
			TxDropPackets:   7,
		}

		edge := TelemetryToConnection(telemetry).Links[0].GetNetworkTelemetry()
		assert.Equal(t, uint64(7), edge.NetworkTransmitDropPolicyTotal)
		assert.LessOrEqual(t, edge.NetworkTransmitDropPolicyTotal, edge.NetworkTransmitDropTotal,
			"network_transmit_drop_policy_total must be <= network_transmit_drop_total")
	})
}

// TestTelemetryToConnectionReceiveDrop checks that the receive drop edge fields
// read the received drop packet count and stay within their subset. The
// network_receive_drop_policy_subset CEL rule on EdgeTypeNetworkTelemetry is
// asserted here by hand, as no protovalidate runtime is vendored.
func TestTelemetryToConnectionReceiveDrop(t *testing.T) {
	const (
		rxDropPackets = 6
		rxDropBytes   = 3300
	)
	telemetry := &appModelV1.NetworkConnectTelemetry{
		EventType:          appModelV1.TelemetryType_TELEMETRY_TYPE_NETWORK_CONNECT,
		DestinationName:    "192.168.0.2",
		DestinationType:    appModelV1.DestinationType_DESTINATION_TYPE_CIDR,
		DestinationPort:    443,
		RxDropBytes:        rxDropBytes,
		RxDropPackets:      rxDropPackets,
		RxDefaultDropBytes: 1100,
	}

	edge := TelemetryToConnection(telemetry).Links[0].GetNetworkTelemetry()
	assert.Equal(t, uint64(rxDropPackets), edge.NetworkReceiveDropTotal, "must report packet count")
	assert.Equal(t, uint64(rxDropPackets), edge.NetworkReceiveDropPolicyTotal)
	assert.NotEqual(t, uint64(rxDropBytes), edge.NetworkReceiveDropTotal, "must not report byte count")
	assert.LessOrEqual(t, edge.NetworkReceiveDropPolicyTotal, edge.NetworkReceiveDropTotal,
		"network_receive_drop_policy_total must be <= network_receive_drop_total")
}

func TestApplicationModelToProcessFlat(t *testing.T) {
	tests := []struct {
		name         string
		model        *appModelV1.ApplicationModel
		telemetryMap model.TelemetryMap
		expected     []*appModelV1.ProcessTelemetry
		wantErr      bool
	}{
		{
			name: "host processes with telemetry map",
			model: &appModelV1.ApplicationModel{
				Id: "test-model-123",
				Host: &appModelV1.ApplicationHost{
					Processes: []*appModelV1.ApplicationProcessGroup{
						{
							Hash:      "hash-exa-la",
							Name:      "exa",
							Arguments: "-la",
						},
						{
							Hash:      "hash-grep-test",
							Name:      "grep",
							Arguments: "test",
						},
					},
				},
			},
			telemetryMap: model.TelemetryMap{
				"exa-la":   {Parents: []string{"bash", "zsh"}},
				"greptest": {Parents: []string{"bash"}},
			},
			expected: []*appModelV1.ProcessTelemetry{
				{
					ProcessName:        "exa",
					ProcessArguments:   "-la",
					ProcessHash:        "hash-exa-la",
					ParentNames:        []string{"bash", "zsh"},
					ApplicationModelId: "test-model-123",
				},
				{
					ProcessName:        "grep",
					ProcessArguments:   "test",
					ProcessHash:        "hash-grep-test",
					ParentNames:        []string{"bash"},
					ApplicationModelId: "test-model-123",
				},
			},
		},
		{
			name: "workload processes with telemetry map",
			model: &appModelV1.ApplicationModel{
				Id: "test-model-456",
				Namespaces: []*appModelV1.ApplicationNamespace{
					{
						Name: "default",
						Workloads: []*appModelV1.ApplicationWorkload{
							{
								Name: "my-app",
								Kind: common.WorkloadKind_WORKLOAD_KIND_DEPLOYMENT,
								Uid:  "deployment-uid",
								Containers: []*appModelV1.ApplicationContainer{
									{
										Id:    "14a2e26a8763a",
										Name:  "my-hash-app",
										Image: "docker.io/library/hasher:latest",
										Processes: []*appModelV1.ApplicationProcessGroup{
											{
												Hash:      "hash-app-config",
												Name:      "app",
												Arguments: "--config=/etc/app.conf",
											},
										},
									},
								},
							},
						},
					},
				},
			},
			telemetryMap: model.TelemetryMap{
				"app--config=/etc/app.conf": {Parents: []string{"systemd"}},
			},
			expected: []*appModelV1.ProcessTelemetry{
				{
					KubernetesNamespace:    "default",
					KubernetesWorkloadName: "my-app",
					KubernetesWorkloadKind: common.WorkloadKind_WORKLOAD_KIND_DEPLOYMENT,
					KubernetesWorkloadUid:  "deployment-uid",
					Container: &appModelV1.ApplicationContainer{
						Id:    "14a2e26a8763a",
						Name:  "my-hash-app",
						Image: "docker.io/library/hasher:latest",
					},
					ProcessName:        "app",
					ProcessArguments:   "--config=/etc/app.conf",
					ProcessHash:        "hash-app-config",
					ParentNames:        []string{"systemd"},
					ApplicationModelId: "test-model-456",
				},
			},
		},
		{
			name: "empty telemetry map",
			model: &appModelV1.ApplicationModel{
				Id: "test-model-789",
				Host: &appModelV1.ApplicationHost{
					Processes: []*appModelV1.ApplicationProcessGroup{
						{
							Name:      "init",
							Arguments: "",
						},
					},
				},
			},
			telemetryMap: model.TelemetryMap{},
			expected: []*appModelV1.ProcessTelemetry{
				{
					ProcessName:        "init",
					ProcessArguments:   "",
					ParentNames:        nil, // Should be nil when no parents in map
					ApplicationModelId: "test-model-789",
				},
			},
		},
		{
			name: "nil telemetry map",
			model: &appModelV1.ApplicationModel{
				Id: "test-model-nil",
				Host: &appModelV1.ApplicationHost{
					Processes: []*appModelV1.ApplicationProcessGroup{
						{
							Name:      "test",
							Arguments: "",
						},
					},
				},
			},
			telemetryMap: nil,
			expected: []*appModelV1.ProcessTelemetry{
				{
					ProcessName:        "test",
					ProcessArguments:   "",
					ParentNames:        nil,
					ApplicationModelId: "test-model-nil",
				},
			},
		},
		{
			name: "process key not in telemetry map",
			model: &appModelV1.ApplicationModel{
				Id: "test-model-missing",
				Host: &appModelV1.ApplicationHost{
					Processes: []*appModelV1.ApplicationProcessGroup{
						{
							Name:      "orphan",
							Arguments: "process",
						},
					},
				},
			},
			telemetryMap: model.TelemetryMap{
				"different-process": {Parents: []string{"parent"}},
			},
			expected: []*appModelV1.ProcessTelemetry{
				{
					ProcessName:        "orphan",
					ProcessArguments:   "process",
					ParentNames:        nil, // Should be nil when key not found
					ApplicationModelId: "test-model-missing",
				},
			},
		},
		{
			name: "empty model",
			model: &appModelV1.ApplicationModel{
				Id: "empty-model",
			},
			telemetryMap: model.TelemetryMap{},
			expected:     []*appModelV1.ProcessTelemetry{},
		},
		{
			name: "both host and workload processes",
			model: &appModelV1.ApplicationModel{
				Id: "mixed-model",
				Host: &appModelV1.ApplicationHost{
					Processes: []*appModelV1.ApplicationProcessGroup{
						{
							Name:      "curl",
							Arguments: "https://api.github.com",
						},
					},
				},
				Namespaces: []*appModelV1.ApplicationNamespace{
					{
						Name: "kube-system",
						Workloads: []*appModelV1.ApplicationWorkload{
							{
								Name: "kube-proxy",
								Kind: common.WorkloadKind_WORKLOAD_KIND_DAEMONSET,
								Containers: []*appModelV1.ApplicationContainer{
									{
										Id:    "ffe0e62cbc365",
										Name:  "kube-proxy-container",
										Image: "k8s.gcr.io/kube-proxy:v1.20.0",
										Processes: []*appModelV1.ApplicationProcessGroup{
											{
												Name:      "kube-proxy",
												Arguments: "--config=/var/lib/kube-proxy/config.conf",
											},
										},
									},
								},
							},
						},
					},
				},
			},
			telemetryMap: model.TelemetryMap{
				"curlhttps://api.github.com":                         {Parents: []string{"bash"}},
				"kube-proxy--config=/var/lib/kube-proxy/config.conf": {Parents: []string{"systemd"}},
			},
			expected: []*appModelV1.ProcessTelemetry{
				{
					ProcessName:        "curl",
					ProcessArguments:   "https://api.github.com",
					ParentNames:        []string{"bash"},
					ApplicationModelId: "mixed-model",
				},
				{
					KubernetesNamespace:    "kube-system",
					KubernetesWorkloadName: "kube-proxy",
					KubernetesWorkloadKind: common.WorkloadKind_WORKLOAD_KIND_DAEMONSET,
					Container: &appModelV1.ApplicationContainer{
						Id:    "ffe0e62cbc365",
						Name:  "kube-proxy-container",
						Image: "k8s.gcr.io/kube-proxy:v1.20.0",
					},
					ProcessName:        "kube-proxy",
					ProcessArguments:   "--config=/var/lib/kube-proxy/config.conf",
					ParentNames:        []string{"systemd"},
					ApplicationModelId: "mixed-model",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			result, err := ApplicationModelToProcessFlat(ctx, tt.model, tt.telemetryMap, &local.NoopMetadataService{})

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.Equal(t, len(tt.expected), len(result), "unexpected number of telemetry entries")

			// Sort both slices for comparison since order may vary
			sortTelemetry := func(t []*appModelV1.ProcessTelemetry) {
				// Sort by a combination of fields to ensure deterministic comparison
				slices.SortFunc(t, func(a, b *appModelV1.ProcessTelemetry) int {
					// Compare by namespace, workload, process name, then args
					if a.KubernetesNamespace != b.KubernetesNamespace {
						if a.KubernetesNamespace < b.KubernetesNamespace {
							return -1
						}
						return 1
					}
					if a.KubernetesWorkloadName != b.KubernetesWorkloadName {
						if a.KubernetesWorkloadName < b.KubernetesWorkloadName {
							return -1
						}
						return 1
					}
					if a.Container == nil && b.Container != nil {
						return -1
					} else if a.Container != nil && b.Container == nil {
						return 1
					} else if a.Container != nil && b.Container != nil {
						if a.Container.Id != b.Container.Id {
							if a.Container.Id < b.Container.Id {
								return -1
							}
							return 1
						}
					}
					if a.ProcessName != b.ProcessName {
						if a.ProcessName < b.ProcessName {
							return -1
						}
						return 1
					}
					if a.ProcessArguments < b.ProcessArguments {
						return -1
					}
					if a.ProcessArguments > b.ProcessArguments {
						return 1
					}
					return 0
				})
			}

			sortTelemetry(result)
			sortTelemetry(tt.expected)

			for i, expected := range tt.expected {
				actual := result[i]

				// Check core fields
				assert.Equal(t, expected.ProcessName, actual.ProcessName, "process name mismatch at index %d", i)
				assert.Equal(t, expected.ProcessArguments, actual.ProcessArguments, "process arguments mismatch at index %d", i)
				assert.Equal(t, expected.ProcessHash, actual.ProcessHash, "process hash mismatch at index %d", i)
				assert.Equal(t, expected.Container, actual.Container, "container mismatch at index %d", i)
				assert.Equal(t, expected.KubernetesNamespace, actual.KubernetesNamespace, "kubernetes namespace mismatch at index %d", i)
				assert.Equal(t, expected.KubernetesWorkloadName, actual.KubernetesWorkloadName, "kubernetes workload name mismatch at index %d", i)
				assert.Equal(t, expected.KubernetesWorkloadKind, actual.KubernetesWorkloadKind, "kubernetes workload kind mismatch at index %d", i)
				assert.Equal(t, expected.KubernetesWorkloadUid, actual.KubernetesWorkloadUid, "kubernetes workload UID mismatch at index %d", i)
				assert.Equal(t, expected.ApplicationModelId, actual.ApplicationModelId, "application model id mismatch at index %d", i)

				// Check ParentNames (the main new field we're testing)
				assert.Equal(t, expected.ParentNames, actual.ParentNames, "parent names mismatch at index %d", i)

				// Sanity check that auto-populated fields are present (but don't require specific values in tests)
				// ClusterName and NodeName may be empty in test environments
				assert.NotNil(t, actual.ClusterName, "cluster name should not be nil")
				assert.NotNil(t, actual.NodeName, "node name should not be nil")

				// Verify Id field is populated with a non-empty UUID
				assert.NotEmpty(t, actual.Id, "telemetry Id should not be empty at index %d", i)
			}
		})
	}
}

func TestApplicationModelToProcessFlat_WithTimeFields(t *testing.T) {
	// Test that timestamp fields are properly propagated
	firstTime := timestamppb.New(time.Unix(1000, 0))
	latestTime := timestamppb.New(time.Unix(2000, 0))

	appModel := &appModelV1.ApplicationModel{
		Id: "time-test",
		Host: &appModelV1.ApplicationHost{
			Processes: []*appModelV1.ApplicationProcessGroup{
				{
					Name:            "timestamped-process",
					Arguments:       "",
					FirstStartTime:  firstTime,
					LatestStartTime: latestTime,
				},
			},
		},
	}

	// Create telemetry map for the process with time fields
	telemetryMap := model.TelemetryMap{
		"timestamped-process": {
			FirstStartTime:  new(time.Unix(1000, 0)),
			LatestStartTime: new(time.Unix(2000, 0)),
		},
	}

	result, err := ApplicationModelToProcessFlat(context.Background(), appModel, telemetryMap, &local.NoopMetadataService{})
	require.NoError(t, err)
	require.Len(t, result, 1)

	telemetry := result[0]
	assert.Equal(t, firstTime, telemetry.FirstStartTime, "first start time should be propagated")
	assert.Equal(t, latestTime, telemetry.LatestStartTime, "latest start time should be propagated")
}

func TestApplicationModelToProcessFlat_UniqueIds(t *testing.T) {
	// Test that each ProcessTelemetry entry gets a unique Id
	appModel := &appModelV1.ApplicationModel{
		Id: "unique-id-test",
		Host: &appModelV1.ApplicationHost{
			Processes: []*appModelV1.ApplicationProcessGroup{
				{Name: "process1", Arguments: ""},
				{Name: "process2", Arguments: ""},
				{Name: "process3", Arguments: ""},
			},
		},
		Namespaces: []*appModelV1.ApplicationNamespace{
			{
				Name: "default",
				Workloads: []*appModelV1.ApplicationWorkload{
					{
						Name: "workload1",
						Kind: common.WorkloadKind_WORKLOAD_KIND_DEPLOYMENT,
						Containers: []*appModelV1.ApplicationContainer{
							{
								Id:    "325790f3086f4",
								Name:  "my-app-container",
								Image: "docker.io/library/someapp:latest",
								Processes: []*appModelV1.ApplicationProcessGroup{
									{Name: "app1", Arguments: ""},
									{Name: "app2", Arguments: ""},
								},
							},
						},
					},
				},
			},
		},
	}

	result, err := ApplicationModelToProcessFlat(context.Background(), appModel, nil, &local.NoopMetadataService{})
	require.NoError(t, err)
	require.Len(t, result, 5, "should have 5 process telemetry entries")

	// Collect all Ids and verify they are unique
	seenIds := make(map[string]bool)
	for i, telemetry := range result {
		assert.NotEmpty(t, telemetry.Id, "telemetry Id should not be empty at index %d", i)
		assert.False(t, seenIds[telemetry.Id], "duplicate Id found: %s at index %d", telemetry.Id, i)
		seenIds[telemetry.Id] = true
	}
}

func TestApplicationModelToProcessFlat_ExecutionCount(t *testing.T) {
	// Test that ExecutionCount is properly propagated from telemetryMap
	appModel := &appModelV1.ApplicationModel{
		Id: "exec-count-test",
		Host: &appModelV1.ApplicationHost{
			Processes: []*appModelV1.ApplicationProcessGroup{
				{Name: "process1", Arguments: "-arg1"},
				{Name: "process2", Arguments: ""},
				{Name: "process3", Arguments: "-verbose"},
			},
		},
		Namespaces: []*appModelV1.ApplicationNamespace{
			{
				Name: "default",
				Workloads: []*appModelV1.ApplicationWorkload{
					{
						Name: "workload1",
						Kind: common.WorkloadKind_WORKLOAD_KIND_DEPLOYMENT,
						Containers: []*appModelV1.ApplicationContainer{
							{
								Id:    "325790f3086f4",
								Name:  "my-app-container",
								Image: "docker.io/library/someapp:latest",
								Processes: []*appModelV1.ApplicationProcessGroup{
									{Name: "app1", Arguments: "--config=/etc/app.conf"},
								},
							},
						},
					},
				},
			},
		},
	}

	telemetryMap := model.TelemetryMap{
		"process1-arg1":              {ExecCount: 5, ExitCount: 4},
		"process2":                   {ExecCount: 10, ExitCount: 8},
		"process3-verbose":           {ExecCount: 1, ExitCount: 0},
		"app1--config=/etc/app.conf": {ExecCount: 42, ExitCount: 13},
	}

	result, err := ApplicationModelToProcessFlat(context.Background(), appModel, telemetryMap, &local.NoopMetadataService{})
	require.NoError(t, err)
	require.Len(t, result, 4, "should have 4 process telemetry entries")

	// Build a map of process key to execution count from results
	resultExecCounts := make(map[string]uint64)
	resultExitCounts := make(map[string]uint64)
	for _, telemetry := range result {
		key := telemetry.ProcessName + telemetry.ProcessArguments
		resultExecCounts[key] = telemetry.ExecutionCount
		resultExitCounts[key] = telemetry.ExitCount
	}

	// Verify execution counts match
	assert.Equal(t, uint64(5), resultExecCounts["process1-arg1"], "process1 execution count mismatch")
	assert.Equal(t, uint64(10), resultExecCounts["process2"], "process2 execution count mismatch")
	assert.Equal(t, uint64(1), resultExecCounts["process3-verbose"], "process3 execution count mismatch")
	assert.Equal(t, uint64(42), resultExecCounts["app1--config=/etc/app.conf"], "app1 execution count mismatch")

	assert.Equal(t, uint64(4), resultExitCounts["process1-arg1"], "process1 exit count mismatch")
	assert.Equal(t, uint64(8), resultExitCounts["process2"], "process2 exit count mismatch")
	assert.Equal(t, uint64(0), resultExitCounts["process3-verbose"], "process3 exit count mismatch")
	assert.Equal(t, uint64(13), resultExitCounts["app1--config=/etc/app.conf"], "app1 exit count mismatch")
}

func TestApplicationModelToProcessFlat_ExecutionCountNilMap(t *testing.T) {
	// Test that nil telemetryMap results in zero ExecutionCount values
	appModel := &appModelV1.ApplicationModel{
		Id: "nil-exec-count-test",
		Host: &appModelV1.ApplicationHost{
			Processes: []*appModelV1.ApplicationProcessGroup{
				{Name: "process1", Arguments: ""},
			},
		},
	}

	result, err := ApplicationModelToProcessFlat(context.Background(), appModel, nil, &local.NoopMetadataService{})
	require.NoError(t, err)
	require.Len(t, result, 1)

	// ExecutionCount should be 0 when no execCountMap is provided
	assert.Equal(t, uint64(0), result[0].ExecutionCount, "execution count should be 0 when map is nil")
	assert.Equal(t, uint64(0), result[0].ExitCount, "exit count should be 0 when map is nil")
}

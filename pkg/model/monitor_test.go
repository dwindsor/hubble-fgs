// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package model

import (
	"testing"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/stretchr/testify/assert"
)

func TestNetworkMonitorKey_String(t *testing.T) {
	key := NetworkMonitorKey{
		SourceNamespace: HostNamespace,
		DestinationName: "cisco.com",
		DestinationPort: 443,
	}
	assert.Equal(t, "host > cisco.com:443", key.String())
	key.SourceNamespace = "kube-system"
	key.SourceWorkloadKind = "Deployment"
	key.SourceWorkloadName = "nginx"
	assert.Equal(t, "kube-system/Deployment:nginx > cisco.com:443", key.String())
}

func TestNetworkMonitorValue_String(t *testing.T) {
	val := NetworkMonitorValue{
		TXBytes: 24 * 1024 * 1024,
		RXBytes: 145 * 1024 * 1024 * 1024,
	}
	assert.Equal(t, "24MB sent 145GB received", val.String())
}

func TestConvertToNetworkMonitorData(t *testing.T) {
	res := tetragon.GetProcessModelResponse{
		Processes: []*tetragon.ProcessModel{
			{
				Namespace: HostNamespace,
				Binary:    "curl",
				Dest: []*tetragon.Destination{
					{
						DestinationNames: []string{"cisco.com."},
						Port:             443,
						Stats:            &tetragon.DestinationStats{TxBytes: 10, RxBytes: 20},
					},
				},
			},
			{
				Namespace: HostNamespace,
				Binary:    "wget",
				Dest: []*tetragon.Destination{
					{
						DestinationNames: []string{"cisco.com."},
						Port:             443,
						Stats:            &tetragon.DestinationStats{TxBytes: 30, RxBytes: 40},
					},
				},
			},
			{
				Namespace: HostNamespace,
				Binary:    "wget",
				Dest: []*tetragon.Destination{
					{
						DestinationNames: []string{"cisco.com."},
						Port:             80,
						Stats:            &tetragon.DestinationStats{TxBytes: 100, RxBytes: 200},
					},
				},
			},
			{
				Binary:    "wget",
				Namespace: "client",
				Workload:  &tetragon.Workload{Kind: "Deployment", Name: "my-app"},
				Dest: []*tetragon.Destination{
					{
						DestinationPod: &tetragon.Pod{
							Namespace:    "server",
							WorkloadKind: "Deployment",
							Workload:     "nginx",
						},
						Port:  8080,
						Stats: &tetragon.DestinationStats{TxBytes: 200, RxBytes: 400},
					},
				},
			}},
	}
	data := ConvertToNetworkMonitorData(&res)
	expected := NetworkMonitorData{
		NetworkMonitorKey{
			SourceNamespace: HostNamespace,
			DestinationName: "cisco.com",
			DestinationPort: 443,
		}: NetworkMonitorValue{
			TXBytes: 40,
			RXBytes: 60,
		},
		NetworkMonitorKey{
			SourceNamespace: HostNamespace,
			DestinationName: "cisco.com",
			DestinationPort: 80,
		}: NetworkMonitorValue{
			TXBytes: 100,
			RXBytes: 200,
		},
		NetworkMonitorKey{
			SourceNamespace:    "client",
			SourceWorkloadKind: "Deployment",
			SourceWorkloadName: "my-app",
			DestinationName:    "server/Deployment:nginx",
			DestinationPort:    8080,
		}: NetworkMonitorValue{
			TXBytes: 200,
			RXBytes: 400,
		},
	}
	assert.Equal(t, expected, data)
}

func TestDiff(t *testing.T) {
	currentData := NetworkMonitorData{
		NetworkMonitorKey{
			SourceNamespace: HostNamespace,
			DestinationName: "cisco.com",
			DestinationPort: 443,
		}: NetworkMonitorValue{
			TXBytes: 10,
			RXBytes: 20,
		},
		NetworkMonitorKey{
			SourceNamespace:    "client",
			SourceWorkloadKind: "Deployment",
			SourceWorkloadName: "my-app",
			DestinationName:    "server/Deployment:nginx",
			DestinationPort:    8080,
		}: NetworkMonitorValue{
			TXBytes: 100,
			RXBytes: 200,
		},
	}
	newData := NetworkMonitorData{
		// no change
		NetworkMonitorKey{
			SourceNamespace: HostNamespace,
			DestinationName: "cisco.com",
			DestinationPort: 443,
		}: NetworkMonitorValue{
			TXBytes: 10,
			RXBytes: 20,
		},
		// an existing entry with updated stats
		NetworkMonitorKey{
			SourceNamespace:    "client",
			SourceWorkloadKind: "Deployment",
			SourceWorkloadName: "my-app",
			DestinationName:    "server/Deployment:nginx",
			DestinationPort:    8080,
		}: NetworkMonitorValue{
			TXBytes: 1000,
			RXBytes: 2000,
		},
		// new entry
		NetworkMonitorKey{
			SourceNamespace:    "client",
			SourceWorkloadKind: "Deployment",
			SourceWorkloadName: "another-app",
			DestinationName:    "isovalent.com",
			DestinationPort:    80,
		}: NetworkMonitorValue{
			TXBytes: 10000,
			RXBytes: 20000,
		},
	}
	diff := Diff(currentData, newData)
	assert.Equal(t, NetworkMonitorData{
		NetworkMonitorKey{
			SourceNamespace:    "client",
			SourceWorkloadKind: "Deployment",
			SourceWorkloadName: "my-app",
			DestinationName:    "server/Deployment:nginx",
			DestinationPort:    8080,
		}: NetworkMonitorValue{
			TXBytes: 900,
			RXBytes: 1800,
		},
		NetworkMonitorKey{
			SourceNamespace:    "client",
			SourceWorkloadKind: "Deployment",
			SourceWorkloadName: "another-app",
			DestinationName:    "isovalent.com",
			DestinationPort:    80,
		}: NetworkMonitorValue{
			TXBytes: 10000,
			RXBytes: 20000,
		}}, diff)
}

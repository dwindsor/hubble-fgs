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
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestNetworkMonitorKey_String(t *testing.T) {
	key := NetworkKey{
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
			},
			// This is quota
			{
				Namespace: "client",
				Workload:  &tetragon.Workload{Kind: "Deployment", Name: "my-app"},
				Dest: []*tetragon.Destination{
					{
						DestinationPod: &tetragon.Pod{
							Namespace:    "server",
							WorkloadKind: "Deployment",
							Workload:     "nginx",
						},
						Stats: &tetragon.DestinationStats{
							TxBytes:      200,
							RxBytes:      400,
							TxDrops:      600,
							TxLimit:      800,
							TxQuota:      1000,
							KtimeTxReset: &timestamppb.Timestamp{Seconds: 1200, Nanos: 1400},
						},
					},
				},
			},
		},
	}
	data, quota := ConvertToNetworkData(&res)
	expected := NetworkMonitorData{
		NetworkKey{
			SourceNamespace: HostNamespace,
			DestinationName: "cisco.com",
			DestinationPort: 443,
		}: NetworkMonitorValue{
			TXBytes: 40,
			RXBytes: 60,
		},
		NetworkKey{
			SourceNamespace: HostNamespace,
			DestinationName: "cisco.com",
			DestinationPort: 80,
		}: NetworkMonitorValue{
			TXBytes: 100,
			RXBytes: 200,
		},
		NetworkKey{
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
	expectedQuota := NetworkQuotaData{
		NetworkKey{
			SourceNamespace:    "client",
			SourceWorkloadKind: "Deployment",
			SourceWorkloadName: "my-app",
			DestinationName:    "server/Deployment:nginx",
		}: NetworkQuotaValue{
			TXBytes: 200,
			RXBytes: 400,
			TXDrops: 600,
			TXQuota: 800,
			TXUsage: 1000,
			Reset:   time.Unix(1200, 1400).UTC(),
		},
	}
	assert.Equal(t, expected, data)
	assert.Equal(t, expectedQuota, quota)
}

func TestDiff(t *testing.T) {
	currentData := NetworkMonitorData{
		NetworkKey{
			SourceNamespace: HostNamespace,
			DestinationName: "cisco.com",
			DestinationPort: 443,
		}: NetworkMonitorValue{
			TXBytes: 10,
			RXBytes: 20,
		},
		NetworkKey{
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
		NetworkKey{
			SourceNamespace: HostNamespace,
			DestinationName: "cisco.com",
			DestinationPort: 443,
		}: NetworkMonitorValue{
			TXBytes: 10,
			RXBytes: 20,
		},
		// an existing entry with updated stats
		NetworkKey{
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
		NetworkKey{
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
		NetworkKey{
			SourceNamespace:    "client",
			SourceWorkloadKind: "Deployment",
			SourceWorkloadName: "my-app",
			DestinationName:    "server/Deployment:nginx",
			DestinationPort:    8080,
		}: NetworkMonitorValue{
			TXBytes: 900,
			RXBytes: 1800,
		},
		NetworkKey{
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

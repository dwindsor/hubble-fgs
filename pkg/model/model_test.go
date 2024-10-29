package model

import (
	"encoding/json"
	"testing"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/stretchr/testify/assert"
)

func TestProcessModelToApplicationModel(t *testing.T) {
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
			{
				Binary:    "ping",
				Namespace: "client",
				Workload:  &tetragon.Workload{Kind: "Deployment", Name: "my-app"},
				Dest: []*tetragon.Destination{
					{
						DestinationPod: &tetragon.Pod{
							Namespace:    "cilium",
							WorkloadKind: "Daemonset",
							Workload:     "cilium",
						},
						Port: 4321,
						Stats: &tetragon.DestinationStats{
							TxBytes: 200,
							RxBytes: 400,
						},
					},
				},
			},
			{
				Binary:    "nc",
				Namespace: "client-a",
				Workload:  &tetragon.Workload{Kind: "Deployment", Name: "my-app"},
				Dest: []*tetragon.Destination{
					{
						DestinationPod: &tetragon.Pod{
							Namespace:    "server",
							WorkloadKind: "Deployment",
							Workload:     "nginx",
						},
						Port: 8080,
						Stats: &tetragon.DestinationStats{
							TxBytes: 200,
							RxBytes: 400,
						},
					},
				},
			},
		},
	}
	appModel := ProcessModelToApplicationModel(&res)
	jsonData, err := json.MarshalIndent(appModel.ApplicationModel, "", "  ")
	assert.NoError(t, err)
	expected := `
{
  "namespaces": [
    {
      "name": "client",
      "workloads": [
        {
          "name": "my-app",
          "kind": "Deployment",
          "processes": [
            {
              "name": "ping",
              "connections": [
                {
                  "destination_name": "cilium/Daemonset:cilium",
                  "destination_port": 4321,
                  "bytes_sent": 200,
                  "bytes_received": 400
                }
              ]
            },
            {
              "name": "wget",
              "connections": [
                {
                  "destination_name": "server/Deployment:nginx",
                  "destination_port": 8080,
                  "bytes_sent": 200,
                  "bytes_received": 400
                }
              ]
            }
          ]
        }
      ]
    },
    {
      "name": "client-a",
      "workloads": [
        {
          "name": "my-app",
          "kind": "Deployment",
          "processes": [
            {
              "name": "nc",
              "connections": [
                {
                  "destination_name": "server/Deployment:nginx",
                  "destination_port": 8080,
                  "bytes_sent": 200,
                  "bytes_received": 400
                }
              ]
            }
          ]
        }
      ]
    }
  ],
  "host": {
    "processes": [
      {
        "name": "curl",
        "connections": [
          {
            "destination_name": "cisco.com",
            "destination_port": 443,
            "bytes_sent": 10,
            "bytes_received": 20
          }
        ]
      },
      {
        "name": "wget",
        "connections": [
          {
            "destination_name": "cisco.com",
            "destination_port": 80,
            "bytes_sent": 100,
            "bytes_received": 200
          },
          {
            "destination_name": "cisco.com",
            "destination_port": 443,
            "bytes_sent": 30,
            "bytes_received": 40
          }
        ]
      }
    ]
  }
}
`
	assert.JSONEq(t, expected, string(jsonData))
}

// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package encoder

import (
	"bytes"
	"io"
	"testing"

	"github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/api/v1/observer"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/cilium/tetragon/api/v1/tetragon"
)

func TestJSONEncoder_EncodeWithoutHubble(t *testing.T) {
	var b bytes.Buffer
	e := NewJSONEncoder(&b, nil, nil, "", false, false, false, make(map[string]struct{}))
	event := tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessConnect{},
	}
	proto.Equal(&event, &event)
	assert.NoError(t, e.Encode(&event))
	res := tetragon.GetEventsResponse{}
	assert.NoError(t, protojson.Unmarshal(b.Bytes(), &res))
	assert.True(t, proto.Equal(&event, &res))
	b.Reset()

	event = tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessExec{},
	}
	assert.NoError(t, e.Encode(&event))
	assert.NoError(t, protojson.Unmarshal(b.Bytes(), &res))
	assert.True(t, proto.Equal(&event, &res))
}

func TestJSONEncoder_EncodeWithHubble(t *testing.T) {
	var b, flowBuffer bytes.Buffer
	e := NewJSONEncoder(&b, nil, &flowBuffer, "", false, false, true, make(map[string]struct{}))
	event := tetragon.GetEventsResponse{
		Event:       &tetragon.GetEventsResponse_ProcessConnect{},
		ClusterName: "my-cluster",
		NodeName:    "my-node",
		Time:        &timestamppb.Timestamp{Seconds: 1, Nanos: 2},
	}
	assert.NoError(t, e.Encode(&event))
	res := tetragon.GetEventsResponse{}

	expectedFlow := observer.GetFlowsResponse{
		ResponseTypes: &observer.GetFlowsResponse_Flow{
			Flow: &flow.Flow{
				Verdict:          flow.Verdict_TRACED,
				IP:               nil,
				Source:           &flow.Endpoint{Labels: labels.LabelWorld.GetModel(), Identity: uint32(identity.ReservedIdentityWorld)},
				Destination:      &flow.Endpoint{Labels: labels.LabelWorld.GetModel(), Identity: uint32(identity.ReservedIdentityWorld)},
				IsReply:          &wrappers.BoolValue{Value: false},
				NodeName:         "my-cluster/my-node",
				Time:             &timestamppb.Timestamp{Seconds: 1, Nanos: 2},
				TrafficDirection: flow.TrafficDirection_EGRESS,
				Type:             observer.FlowType_L3_L4,
			},
		},
		NodeName: "my-cluster/my-node",
		Time:     &timestamppb.Timestamp{Seconds: 1, Nanos: 2},
	}
	actualFlow := observer.GetFlowsResponse{}
	assert.NoError(t, protojson.Unmarshal(flowBuffer.Bytes(), &actualFlow))
	assert.True(t, proto.Equal(&expectedFlow, &actualFlow))

	assert.NoError(t, protojson.Unmarshal(b.Bytes(), &res))
	assert.True(t, proto.Equal(&event, &res))

	b.Reset()
	event = tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessExec{},
	}
	assert.NoError(t, e.Encode(&event))
	assert.NoError(t, protojson.Unmarshal(b.Bytes(), &res))
	assert.True(t, proto.Equal(&event, &res))
}

func TestJSONEncoder_processConnectToFlow(t *testing.T) {
	option.Config.ClusterName = "test-cluster"
	defer func() { option.Config.ClusterName = "" }()
	nodeIPs := map[string]struct{}{
		"10.0.0.1": {},
		"10.0.0.2": {},
	}
	e := NewJSONEncoder(io.Discard, io.Discard, io.Discard, "", false, false, true, nodeIPs)

	// Empty connect event
	event := tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessConnect{
			ProcessConnect: &tetragon.ProcessConnect{},
		},
	}
	actualFlow := e.processConnectToFlow(event.GetProcessConnect())
	expectedFlow := &flow.Flow{
		Verdict:          flow.Verdict_TRACED,
		IP:               nil,
		Source:           &flow.Endpoint{Labels: labels.LabelWorld.GetModel(), Identity: uint32(identity.ReservedIdentityWorld)},
		Destination:      &flow.Endpoint{Labels: labels.LabelWorld.GetModel(), Identity: uint32(identity.ReservedIdentityWorld)},
		Type:             observer.FlowType_L3_L4,
		TrafficDirection: flow.TrafficDirection_EGRESS,
		IsReply:          &wrappers.BoolValue{Value: false},
	}
	assert.Equal(t, expectedFlow, actualFlow)

	// With TCP info
	event = tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessConnect{
			ProcessConnect: &tetragon.ProcessConnect{
				SourceIp:        "1.1.1.1",
				SourcePort:      &wrappers.UInt32Value{Value: 54321},
				DestinationIp:   "2.2.2.2",
				DestinationPort: &wrappers.UInt32Value{Value: 80},
				SockCookie:      12345,
				Protocol:        tetragon.SocketProtocol_TCP,
			},
		},
	}
	event.GetProcessConnect().DestinationService = &tetragon.Service{
		Namespace: "ns-2",
		Name:      "svc-2",
	}
	actualFlow = e.processConnectToFlow(event.GetProcessConnect())
	expectedFlow = &flow.Flow{
		Verdict: flow.Verdict_TRACED,
		IP: &flow.IP{
			IpVersion:   flow.IPVersion_IPv4,
			Source:      "1.1.1.1",
			Destination: "2.2.2.2",
		},
		L4: &flow.Layer4{
			Protocol: &flow.Layer4_TCP{
				TCP: &flow.TCP{
					SourcePort:      54321,
					DestinationPort: 80,
				},
			},
		},
		Source: &flow.Endpoint{Labels: labels.LabelWorld.GetModel(), Identity: uint32(identity.ReservedIdentityWorld)},
		Destination: &flow.Endpoint{
			ClusterName: option.Config.ClusterName,
			Namespace:   "ns-2",
			Identity:    1565,
			Labels:      []string{},
		},
		DestinationService: &flow.Service{
			Name:      "svc-2",
			Namespace: "ns-2",
		},
		Type:             observer.FlowType_L3_L4,
		TrafficDirection: flow.TrafficDirection_EGRESS,
		IsReply:          &wrappers.BoolValue{Value: false},
		SocketCookie:     12345,
	}
	assert.Equal(t, expectedFlow, actualFlow)

	// With source pod
	event.GetProcessConnect().Process = &tetragon.Process{
		Pod: &tetragon.Pod{
			Namespace: "ns-1",
			Name:      "pod-1",
			PodLabels: map[string]string{
				"key1": "val1",
				"key2": "val2",
			},
		},
	}
	event.GetProcessConnect().DestinationService = &tetragon.Service{
		Namespace: "ns-2",
		Name:      "svc-2",
	}
	actualFlow = e.processConnectToFlow(event.GetProcessConnect())
	expectedFlow = &flow.Flow{
		Verdict: flow.Verdict_TRACED,
		IP: &flow.IP{
			IpVersion:   flow.IPVersion_IPv4,
			Source:      "1.1.1.1",
			Destination: "2.2.2.2",
		},
		L4: &flow.Layer4{
			Protocol: &flow.Layer4_TCP{
				TCP: &flow.TCP{
					SourcePort:      54321,
					DestinationPort: 80,
				},
			},
		},
		Source: &flow.Endpoint{
			ClusterName: option.Config.ClusterName,
			Namespace:   "ns-1",
			Labels:      []string{"k8s:key1=val1", "k8s:key2=val2"},
			PodName:     "pod-1",
		},
		Destination: &flow.Endpoint{
			ClusterName: option.Config.ClusterName,
			Namespace:   "ns-2",
			Identity:    1565,
			Labels:      []string{},
		},
		DestinationService: &flow.Service{
			Name:      "svc-2",
			Namespace: "ns-2",
		},
		Type:             observer.FlowType_L3_L4,
		TrafficDirection: flow.TrafficDirection_EGRESS,
		IsReply:          &wrappers.BoolValue{Value: false},
		SocketCookie:     12345,
	}
	assert.Equal(t, expectedFlow, actualFlow)

	// UDP
	event.GetProcessConnect().Protocol = tetragon.SocketProtocol_UDP
	actualFlow = e.processConnectToFlow(event.GetProcessConnect())
	expectedFlow = &flow.Flow{
		Verdict: flow.Verdict_TRACED,
		IP: &flow.IP{
			IpVersion:   flow.IPVersion_IPv4,
			Source:      "1.1.1.1",
			Destination: "2.2.2.2",
		},
		L4: &flow.Layer4{
			Protocol: &flow.Layer4_UDP{
				UDP: &flow.UDP{
					SourcePort:      54321,
					DestinationPort: 80,
				},
			},
		},
		Source: &flow.Endpoint{
			ClusterName: option.Config.ClusterName,
			Namespace:   "ns-1",
			Labels:      []string{"k8s:key1=val1", "k8s:key2=val2"},
			PodName:     "pod-1",
		},
		Destination: &flow.Endpoint{
			ClusterName: option.Config.ClusterName,
			Namespace:   "ns-2",
			Identity:    1565,
			Labels:      []string{},
		},
		DestinationService: &flow.Service{
			Name:      "svc-2",
			Namespace: "ns-2",
		},
		Type:             observer.FlowType_L3_L4,
		TrafficDirection: flow.TrafficDirection_EGRESS,
		IsReply:          &wrappers.BoolValue{Value: false},
		SocketCookie:     12345,
	}
	assert.Equal(t, expectedFlow, actualFlow)

	// With a DNS name and service selector labels
	event.GetProcessConnect().DestinationNames = []string{"isovalent.com"}
	event.GetProcessConnect().DestinationService.SelectorLabels = map[string]string{"app": "myapp"}
	actualFlow = e.processConnectToFlow(event.GetProcessConnect())
	expectedFlow = &flow.Flow{
		Verdict: flow.Verdict_TRACED,
		IP: &flow.IP{
			IpVersion:   flow.IPVersion_IPv4,
			Source:      "1.1.1.1",
			Destination: "2.2.2.2",
		},
		L4: &flow.Layer4{
			Protocol: &flow.Layer4_UDP{
				UDP: &flow.UDP{
					SourcePort:      54321,
					DestinationPort: 80,
				},
			},
		},
		Source: &flow.Endpoint{
			ClusterName: option.Config.ClusterName,
			Namespace:   "ns-1",
			Labels:      []string{"k8s:key1=val1", "k8s:key2=val2"},
			PodName:     "pod-1",
		},
		Destination: &flow.Endpoint{
			ClusterName: option.Config.ClusterName,
			Namespace:   "ns-2",
			Identity:    1565,
			Labels:      []string{"k8s:app=myapp"},
		},
		DestinationNames: []string{"isovalent.com"},
		DestinationService: &flow.Service{
			Name:      "svc-2",
			Namespace: "ns-2",
		},
		Type:             observer.FlowType_L3_L4,
		TrafficDirection: flow.TrafficDirection_EGRESS,
		IsReply:          &wrappers.BoolValue{Value: false},
		SocketCookie:     12345,
	}
	assert.Equal(t, expectedFlow, actualFlow)

	// With workload info
	event.GetProcessConnect().GetProcess().GetPod().WorkloadKind = "DaemonSet"
	event.GetProcessConnect().GetProcess().GetPod().Workload = "my-daemonset"
	event.GetProcessConnect().DestinationPod = &tetragon.Pod{
		Namespace:    "ns-1",
		Name:         "dst-pod-1",
		WorkloadKind: "Deployment",
		Workload:     "my-deployment",
	}
	expectedFlow = &flow.Flow{
		Verdict: flow.Verdict_TRACED,
		IP: &flow.IP{
			IpVersion:   flow.IPVersion_IPv4,
			Source:      "1.1.1.1",
			Destination: "2.2.2.2",
		},
		L4: &flow.Layer4{
			Protocol: &flow.Layer4_UDP{
				UDP: &flow.UDP{
					SourcePort:      54321,
					DestinationPort: 80,
				},
			},
		},
		Source: &flow.Endpoint{
			ClusterName: option.Config.ClusterName,
			Namespace:   "ns-1",
			Labels:      []string{"k8s:key1=val1", "k8s:key2=val2"},
			PodName:     "pod-1",
			Workloads:   []*flow.Workload{{Kind: "DaemonSet", Name: "my-daemonset"}},
			Identity:    uint32(2515),
		},
		Destination: &flow.Endpoint{
			ClusterName: option.Config.ClusterName,
			Namespace:   "ns-1",
			PodName:     "dst-pod-1",
			Labels:      []string{},
			Workloads:   []*flow.Workload{{Kind: "Deployment", Name: "my-deployment"}},
			Identity:    uint32(2805),
		},
		DestinationNames: []string{"isovalent.com"},
		Type:             observer.FlowType_L3_L4,
		TrafficDirection: flow.TrafficDirection_EGRESS,
		IsReply:          &wrappers.BoolValue{Value: false},
		SocketCookie:     12345,
	}
	actualFlow = e.processConnectToFlow(event.GetProcessConnect())
	assert.Equal(t, expectedFlow, actualFlow)

	// With IPv6
	event.GetProcessConnect().SourceIp = "9889:550b:e6f4:0e1c:4d26:063a:e248:675f"
	event.GetProcessConnect().DestinationIp = "f23b:2837:2f2a:f4aa:cc1d:3360:f3c2:41d5"
	expectedFlow = &flow.Flow{
		Verdict: flow.Verdict_TRACED,
		IP: &flow.IP{
			IpVersion:   flow.IPVersion_IPv6,
			Source:      "9889:550b:e6f4:0e1c:4d26:063a:e248:675f",
			Destination: "f23b:2837:2f2a:f4aa:cc1d:3360:f3c2:41d5",
		},
		L4: &flow.Layer4{
			Protocol: &flow.Layer4_UDP{
				UDP: &flow.UDP{
					SourcePort:      54321,
					DestinationPort: 80,
				},
			},
		},
		Source: &flow.Endpoint{
			ClusterName: option.Config.ClusterName,
			Namespace:   "ns-1",
			Labels:      []string{"k8s:key1=val1", "k8s:key2=val2"},
			PodName:     "pod-1",
			Workloads:   []*flow.Workload{{Kind: "DaemonSet", Name: "my-daemonset"}},
			Identity:    uint32(2515),
		},
		Destination: &flow.Endpoint{
			ClusterName: option.Config.ClusterName,
			Namespace:   "ns-1",
			PodName:     "dst-pod-1",
			Labels:      []string{},
			Workloads:   []*flow.Workload{{Kind: "Deployment", Name: "my-deployment"}},
			Identity:    uint32(2805),
		},
		DestinationNames: []string{"isovalent.com"},
		Type:             observer.FlowType_L3_L4,
		TrafficDirection: flow.TrafficDirection_EGRESS,
		IsReply:          &wrappers.BoolValue{Value: false},
		SocketCookie:     12345,
	}
	actualFlow = e.processConnectToFlow(event.GetProcessConnect())
	assert.Equal(t, expectedFlow, actualFlow)

	// With IPv4-mapped IPv6 addresses
	event.GetProcessConnect().SourceIp = "::ffff:1.1.1.1"
	event.GetProcessConnect().DestinationIp = "::ffff:2.2.2.2"
	expectedFlow = &flow.Flow{
		Verdict: flow.Verdict_TRACED,
		IP: &flow.IP{
			IpVersion:   flow.IPVersion_IPv6,
			Source:      "::ffff:1.1.1.1",
			Destination: "::ffff:2.2.2.2",
		},
		L4: &flow.Layer4{
			Protocol: &flow.Layer4_UDP{
				UDP: &flow.UDP{
					SourcePort:      54321,
					DestinationPort: 80,
				},
			},
		},
		Source: &flow.Endpoint{
			ClusterName: option.Config.ClusterName,
			Namespace:   "ns-1",
			Labels:      []string{"k8s:key1=val1", "k8s:key2=val2"},
			PodName:     "pod-1",
			Workloads:   []*flow.Workload{{Kind: "DaemonSet", Name: "my-daemonset"}},
			Identity:    uint32(2515),
		},
		Destination: &flow.Endpoint{
			ClusterName: option.Config.ClusterName,
			Namespace:   "ns-1",
			PodName:     "dst-pod-1",
			Labels:      []string{},
			Workloads:   []*flow.Workload{{Kind: "Deployment", Name: "my-deployment"}},
			Identity:    uint32(2805),
		},
		DestinationNames: []string{"isovalent.com"},
		Type:             observer.FlowType_L3_L4,
		TrafficDirection: flow.TrafficDirection_EGRESS,
		IsReply:          &wrappers.BoolValue{Value: false},
		SocketCookie:     12345,
	}
	actualFlow = e.processConnectToFlow(event.GetProcessConnect())
	assert.Equal(t, expectedFlow, actualFlow)

	// With node IPs
	event = tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessConnect{
			ProcessConnect: &tetragon.ProcessConnect{
				SourceIp:        "10.0.0.1",
				SourcePort:      &wrappers.UInt32Value{Value: 54321},
				DestinationIp:   "10.0.0.2",
				DestinationPort: &wrappers.UInt32Value{Value: 80},
				SockCookie:      12345,
				Protocol:        tetragon.SocketProtocol_TCP,
			},
		},
	}
	expectedFlow = &flow.Flow{
		Verdict: flow.Verdict_TRACED,
		IP: &flow.IP{
			IpVersion:   flow.IPVersion_IPv4,
			Source:      "10.0.0.1",
			Destination: "10.0.0.2",
		},
		L4: &flow.Layer4{
			Protocol: &flow.Layer4_TCP{
				TCP: &flow.TCP{
					SourcePort:      54321,
					DestinationPort: 80,
				},
			},
		},
		Source:           &flow.Endpoint{Labels: labels.LabelHost.GetModel(), Identity: uint32(identity.ReservedIdentityHost)},
		Destination:      &flow.Endpoint{Labels: labels.LabelHost.GetModel(), Identity: uint32(identity.ReservedIdentityHost)},
		Type:             observer.FlowType_L3_L4,
		TrafficDirection: flow.TrafficDirection_EGRESS,
		IsReply:          &wrappers.BoolValue{Value: false},
		SocketCookie:     12345,
	}
	actualFlow = e.processConnectToFlow(event.GetProcessConnect())
	assert.Equal(t, expectedFlow, actualFlow)
}

func TestGetNodeIPs(t *testing.T) {
	nodeIPs := GetNodeIPs()
	assert.Contains(t, nodeIPs, "127.0.0.1")
	assert.Contains(t, nodeIPs, "::1")
}

func TestJSONEncoder_processConnectToFlowKubeAPIServer(t *testing.T) {
	nodeIPs := map[string]struct{}{"10.0.0.1": {}}
	e := NewJSONEncoder(io.Discard, io.Discard, io.Discard, "", false, false, true, nodeIPs)
	event := tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessConnect{
			ProcessConnect: &tetragon.ProcessConnect{
				SourceIp:           "10.0.0.1",
				SourcePort:         &wrappers.UInt32Value{Value: 54321},
				DestinationIp:      "10.0.0.2",
				DestinationService: &tetragon.Service{Name: "kubernetes", Namespace: "default"},
				DestinationPort:    &wrappers.UInt32Value{Value: 443},
				SockCookie:         12345,
				Protocol:           tetragon.SocketProtocol_TCP,
			},
		},
	}
	expectedFlow := &flow.Flow{
		Verdict: flow.Verdict_TRACED,
		IP: &flow.IP{
			IpVersion:   flow.IPVersion_IPv4,
			Source:      "10.0.0.1",
			Destination: "10.0.0.2",
		},
		L4: &flow.Layer4{
			Protocol: &flow.Layer4_TCP{
				TCP: &flow.TCP{
					SourcePort:      54321,
					DestinationPort: 443,
				},
			},
		},
		Source: &flow.Endpoint{
			Labels:   labels.LabelHost.GetModel(),
			Identity: uint32(identity.ReservedIdentityHost),
		},
		Destination: &flow.Endpoint{
			Labels:   labels.LabelKubeAPIServer.GetModel(),
			Identity: uint32(identity.ReservedIdentityKubeAPIServer),
		},
		Type:             observer.FlowType_L3_L4,
		TrafficDirection: flow.TrafficDirection_EGRESS,
		IsReply:          &wrappers.BoolValue{Value: false},
		SocketCookie:     12345,
	}
	actualFlow := e.processConnectToFlow(event.GetProcessConnect())
	assert.Equal(t, expectedFlow, actualFlow)
}

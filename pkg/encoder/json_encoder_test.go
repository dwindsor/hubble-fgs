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
	"bufio"
	"bytes"
	"io"
	"testing"

	"github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/api/v1/observer"
	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/watcher"
	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestJSONEncoder_EncodeWithoutHubble(t *testing.T) {
	var b bytes.Buffer
	e := NewJSONEncoder(&b, watcher.NewFakeK8sWatcher(nil), false)
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
	var b bytes.Buffer
	e := NewJSONEncoder(&b, watcher.NewFakeK8sWatcher(nil), true)
	event := tetragon.GetEventsResponse{
		Event:    &tetragon.GetEventsResponse_ProcessConnect{},
		NodeName: "my-node",
		Time:     &timestamppb.Timestamp{Seconds: 1, Nanos: 2},
	}
	assert.NoError(t, e.Encode(&event))
	res := tetragon.GetEventsResponse{}

	reader := bufio.NewReader(bytes.NewReader(b.Bytes()))
	jsonBytes, err := reader.ReadBytes('\n')
	assert.NoError(t, err)
	expectedFlow := observer.GetFlowsResponse{
		ResponseTypes: &observer.GetFlowsResponse_Flow{
			Flow: &flow.Flow{
				IP:               &flow.IP{},
				Source:           &flow.Endpoint{},
				Destination:      &flow.Endpoint{},
				IsReply:          &wrappers.BoolValue{Value: false},
				NodeName:         "my-node",
				Time:             &timestamppb.Timestamp{Seconds: 1, Nanos: 2},
				TrafficDirection: flow.TrafficDirection_EGRESS,
				Type:             observer.FlowType_L3_L4,
			},
		},
		NodeName: "my-node",
		Time:     &timestamppb.Timestamp{Seconds: 1, Nanos: 2},
	}
	actualFlow := observer.GetFlowsResponse{}
	assert.NoError(t, protojson.Unmarshal(jsonBytes, &actualFlow))
	assert.True(t, proto.Equal(&expectedFlow, &actualFlow))

	jsonBytes, err = reader.ReadBytes('\n')
	assert.NoError(t, err)
	assert.NoError(t, protojson.Unmarshal(jsonBytes, &res))
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
	services := []interface{}{
		&corev1.Service{
			ObjectMeta: v1.ObjectMeta{Name: "svc-1", Namespace: "ns-1"},
			Spec: corev1.ServiceSpec{
				ClusterIPs: []string{"1.1.1.1"},
			},
		},
		&corev1.Service{
			ObjectMeta: v1.ObjectMeta{Name: "svc-2", Namespace: "ns-2"},
			Spec: corev1.ServiceSpec{
				ClusterIPs: []string{"2.2.2.2"},
			},
		},
	}
	k8sWatcher := watcher.NewFakeK8sWatcherWithPodsAndServices(nil, services)
	e := NewJSONEncoder(io.Discard, k8sWatcher, true)

	// Empty connect event
	event := tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessConnect{
			ProcessConnect: &tetragon.ProcessConnect{},
		},
	}
	actualFlow := e.processConnectToFlow(event.GetProcessConnect())
	expectedFlow := &flow.Flow{
		IP:               &flow.IP{},
		Source:           &flow.Endpoint{},
		Destination:      &flow.Endpoint{},
		Type:             observer.FlowType_L3_L4,
		TrafficDirection: flow.TrafficDirection_EGRESS,
		IsReply:          &wrappers.BoolValue{Value: false},
	}
	assert.True(t, proto.Equal(expectedFlow, actualFlow))

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
	actualFlow = e.processConnectToFlow(event.GetProcessConnect())
	expectedFlow = &flow.Flow{
		IP: &flow.IP{
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
		Source: &flow.Endpoint{},
		Destination: &flow.Endpoint{
			Namespace: "ns-2",
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
	assert.True(t, proto.Equal(expectedFlow, actualFlow))

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
	actualFlow = e.processConnectToFlow(event.GetProcessConnect())
	expectedFlow = &flow.Flow{
		IP: &flow.IP{
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
			Namespace: "ns-1",
			Labels:    []string{"k8s:key1=val1", "k8s:key2=val2"},
			PodName:   "pod-1",
		},
		Destination: &flow.Endpoint{
			Namespace: "ns-2",
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
	assert.True(t, proto.Equal(expectedFlow, actualFlow))

	// UDP
	event.GetProcessConnect().Protocol = tetragon.SocketProtocol_UDP
	actualFlow = e.processConnectToFlow(event.GetProcessConnect())
	expectedFlow = &flow.Flow{
		IP: &flow.IP{
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
			Namespace: "ns-1",
			Labels:    []string{"k8s:key1=val1", "k8s:key2=val2"},
			PodName:   "pod-1",
		},
		Destination: &flow.Endpoint{
			Namespace: "ns-2",
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
	assert.True(t, proto.Equal(expectedFlow, actualFlow))

	// With a DNS name
	event.GetProcessConnect().DestinationNames = []string{"isovalent.com"}
	actualFlow = e.processConnectToFlow(event.GetProcessConnect())
	expectedFlow = &flow.Flow{
		IP: &flow.IP{
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
			Namespace: "ns-1",
			Labels:    []string{"k8s:key1=val1", "k8s:key2=val2"},
			PodName:   "pod-1",
		},
		Destination: &flow.Endpoint{
			Namespace: "ns-2",
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
	assert.True(t, proto.Equal(expectedFlow, actualFlow))
}

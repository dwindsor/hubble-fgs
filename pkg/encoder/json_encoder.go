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
	"encoding/json"
	"errors"
	"io"
	"sort"

	"github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/api/v1/observer"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/tetragon/api/v1/tetragon"
	jsonEncoder "github.com/cilium/tetragon/pkg/encoder"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/watcher"
	"github.com/golang/protobuf/ptypes/wrappers"
)

// JSONEncoder is a shim encoder that wraps ProtoJsonEncoder.
// If --enable-hubble-flow-export is false, it delegates encoding of all the event types to
// ProtoJsonEncoder.
// If --enable-hubble-flow-export is true, it encodes ProcessConnect events both as process_connect
// and Hubble flow, while delegating encoding of all the other event types to ProtoJsonEncoder.
type JSONEncoder struct {
	flowEncoder      *json.Encoder
	protoJSONEncoder *jsonEncoder.ProtojsonEncoder
	watcher          watcher.K8sResourceWatcher
	enableFlowExport bool
}

func NewJSONEncoder(writer io.Writer, flowWriter io.Writer, watcher watcher.K8sResourceWatcher, enableFlowExport bool) *JSONEncoder {
	encoder := JSONEncoder{
		protoJSONEncoder: jsonEncoder.NewProtojsonEncoder(writer),
		watcher:          watcher,
	}
	if enableFlowExport {
		encoder.enableFlowExport = true
		encoder.flowEncoder = json.NewEncoder(flowWriter)
	}
	return &encoder
}

// Encode implements EventEncoder.Encode.
func (h *JSONEncoder) Encode(v interface{}) error {
	response, ok := v.(*tetragon.GetEventsResponse)
	if !ok {
		logger.GetLogger().WithField("event", v).Warn("invalid event")
		return nil
	}
	var flowError error
	if _, ok := response.GetEvent().(*tetragon.GetEventsResponse_ProcessConnect); ok && h.enableFlowExport {
		f := h.processConnectToFlow(response.GetProcessConnect())
		f.NodeName = response.NodeName
		f.Time = response.Time
		res := &observer.GetFlowsResponse{
			ResponseTypes: &observer.GetFlowsResponse_Flow{Flow: f},
			NodeName:      response.NodeName,
			Time:          response.Time,
		}
		flowError = h.flowEncoder.Encode(res)
	}
	return errors.Join(flowError, h.protoJSONEncoder.Encode(response))
}

func (h *JSONEncoder) processConnectToFlow(pc *tetragon.ProcessConnect) *flow.Flow {
	ip := flow.IP{
		Source:      pc.GetSourceIp(),
		Destination: pc.GetDestinationIp(),
	}
	var l4 *flow.Layer4
	switch pc.GetProtocol() {
	case tetragon.SocketProtocol_TCP:
		l4 = &flow.Layer4{
			Protocol: &flow.Layer4_TCP{
				TCP: &flow.TCP{
					SourcePort:      pc.GetSourcePort().GetValue(),
					DestinationPort: pc.GetDestinationPort().GetValue(),
				},
			},
		}
	case tetragon.SocketProtocol_UDP:
		l4 = &flow.Layer4{
			Protocol: &flow.Layer4_UDP{
				UDP: &flow.UDP{
					SourcePort:      pc.GetSourcePort().GetValue(),
					DestinationPort: pc.GetDestinationPort().GetValue(),
				},
			},
		}
	}
	var source, destination flow.Endpoint
	sourcePod := pc.GetProcess().GetPod()
	if sourcePod != nil {
		source.Namespace = sourcePod.Namespace
		source.PodName = sourcePod.Name
		sourceLabels := labels.Map2Labels(sourcePod.PodLabels, labels.LabelSourceK8s).GetModel()
		sort.Strings(sourceLabels)
		source.Labels = sourceLabels
	}
	k8sDestinationServices, err := h.watcher.FindServiceByIP(ip.Destination)
	var destinationService *flow.Service
	if err == nil {
		destination.Namespace = k8sDestinationServices[0].Namespace
		destinationService = &flow.Service{
			Name:      k8sDestinationServices[0].Name,
			Namespace: k8sDestinationServices[0].Namespace,
		}
	}
	return &flow.Flow{
		IP:                 &ip,
		L4:                 l4,
		Source:             &source,
		Destination:        &destination,
		Type:               observer.FlowType_L3_L4,
		DestinationNames:   pc.GetDestinationNames(),
		DestinationService: destinationService,
		TrafficDirection:   flow.TrafficDirection_EGRESS,
		IsReply:            &wrappers.BoolValue{Value: false},
		SocketCookie:       pc.GetSockCookie(),
	}
}

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
	"fmt"
	"io"
	"net"
	"net/netip"
	"sort"

	"github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/api/v1/observer"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/tetragon/api/v1/tetragon"
	jsonEncoder "github.com/cilium/tetragon/pkg/encoder"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/reader/node"
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
	enableFlowExport bool
	nodeIPs          map[string]struct{}
}

func NewJSONEncoder(writer io.Writer, flowWriter io.Writer, enableFlowExport bool, nodeIPs map[string]struct{}) *JSONEncoder {
	encoder := JSONEncoder{
		protoJSONEncoder: jsonEncoder.NewProtojsonEncoder(writer),
		nodeIPs:          nodeIPs,
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
		if response.ClusterName != "" {
			f.NodeName = fmt.Sprintf("%s/%s", response.ClusterName, response.NodeName)
		} else {
			f.NodeName = response.NodeName
		}
		f.Time = response.Time
		res := &observer.GetFlowsResponse{
			ResponseTypes: &observer.GetFlowsResponse_Flow{Flow: f},
			NodeName:      f.NodeName,
			Time:          response.Time,
		}
		flowError = h.flowEncoder.Encode(res)
	}
	return errors.Join(flowError, h.protoJSONEncoder.Encode(response))
}

func (h *JSONEncoder) processConnectToFlow(pc *tetragon.ProcessConnect) *flow.Flow {
	var ip *flow.IP
	switch addr, _ := netip.ParseAddr(pc.GetSourceIp()); {
	case addr.Is4():
		ip = &flow.IP{
			Source:      pc.GetSourceIp(),
			Destination: pc.GetDestinationIp(),
			IpVersion:   flow.IPVersion_IPv4,
		}
	case addr.Is6():
		ip = &flow.IP{
			Source:      pc.GetSourceIp(),
			Destination: pc.GetDestinationIp(),
			IpVersion:   flow.IPVersion_IPv6,
		}
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
		source.ClusterName = option.Config.ClusterName
		source.Namespace = sourcePod.Namespace
		source.PodName = sourcePod.Name
		sourceLabels := labels.Map2Labels(sourcePod.PodLabels, labels.LabelSourceK8s).GetModel()
		sort.Strings(sourceLabels)
		source.Labels = sourceLabels
		if sourcePod.Workload != "" && sourcePod.WorkloadKind != "" {
			source.Workloads = []*flow.Workload{{Name: sourcePod.Workload, Kind: sourcePod.WorkloadKind}}
		}
	} else if _, ok := h.nodeIPs[pc.GetSourceIp()]; ok {
		source.Labels = labels.LabelHost.GetModel()
	} else {
		source.Labels = labels.LabelWorld.GetModel()
	}
	destinationPod := pc.GetDestinationPod()
	destinationSvc := pc.GetDestinationService()
	var destinationService *flow.Service
	if destinationPod != nil {
		destination.ClusterName = option.Config.ClusterName
		destination.Namespace = destinationPod.Namespace
		destination.PodName = destinationPod.Name
		destinationLabels := labels.Map2Labels(destinationPod.PodLabels, labels.LabelSourceK8s).GetModel()
		sort.Strings(destinationLabels)
		destination.Labels = destinationLabels
		if destinationPod.Workload != "" && destinationPod.WorkloadKind != "" {
			destination.Workloads = []*flow.Workload{{Name: destinationPod.Workload, Kind: destinationPod.WorkloadKind}}
		}
	} else if destinationSvc != nil {
		destination.ClusterName = option.Config.ClusterName
		destination.Namespace = destinationSvc.Namespace
		destinationService = &flow.Service{
			Name:      destinationSvc.Name,
			Namespace: destinationSvc.Namespace,
		}
	} else if _, ok := h.nodeIPs[pc.GetDestinationIp()]; ok {
		destination.Labels = labels.LabelHost.GetModel()
	} else {
		destination.Labels = labels.LabelWorld.GetModel()
	}
	return &flow.Flow{
		Verdict:            flow.Verdict_TRACED,
		IP:                 ip,
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

func GetNodeIPs() map[string]struct{} {
	nodeIPs := make(map[string]struct{})
	nodeName := node.GetNodeNameForExport()
	ips, err := net.LookupIP(nodeName)
	if err != nil {
		logger.GetLogger().WithError(err).WithField("hostname", nodeName).
			Warn("Failed to get host IP. Hubble flows to/from the host will be classified as 'reserved:world' instead of 'reserved:host'")
		return nodeIPs
	}
	for _, ip := range ips {
		nodeIPs[ip.String()] = struct{}{}
	}
	return nodeIPs
}

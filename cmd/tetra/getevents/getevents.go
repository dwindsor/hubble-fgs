// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package getevents

import (
	"fmt"
	"io"

	"github.com/cilium/tetragon/api/v1/tetragon"
	ossGetevents "github.com/cilium/tetragon/cmd/tetra/getevents"
	ossEncoder "github.com/cilium/tetragon/pkg/encoder"
	"github.com/isovalent/hubble-fgs/pkg/encoder"

	// append enterprise filters
	_ "github.com/isovalent/hubble-fgs/pkg/filters"
	"github.com/spf13/cobra"
)

// GetEncoder returns an encoder for an event stream based on configuration options.
var GetEncoder = func(w io.Writer, colorMode ossEncoder.ColorMode, timestamps bool, compact bool, tty string, stackTraces bool) ossEncoder.EventEncoder {
	if compact {
		return encoder.NewEnterpriseEncoder(w, colorMode, timestamps)
	}
	if tty != "" {
		return ossEncoder.NewTtyEncoder(w, tty)
	}
	return ossEncoder.NewProtojsonEncoder(w)
}

var (
	host       bool
	namespaces []string
	processes  []string
	pods       []string
	ips        []string
	sourceIPs  []string
	destIPs    []string
	destNames  []string
	sniNames   []string
	uris       []string
	destPods   []string
)

// GetFilter returns a filter for an event stream based on configuration options.
var GetFilter = func() *tetragon.Filter {
	namespaces = ossGetevents.Options.Namespaces
	processes = ossGetevents.Options.Processes
	pods = ossGetevents.Options.Pods

	if host {
		// Host events can be matched by an empty namespace string.
		namespaces = append(namespaces, "")
	}

	// Only set these filters if they are not empty. We currently rely on Protobuf to
	// marshal empty lists as nil for filters to function properly. It doesn't work with
	// stdin mode since it doesn't go over the wire, causing all events to get filtered
	// out because empty allowlist does not match anything.
	filter := tetragon.Filter{}
	if len(namespaces) > 0 {
		filter.Namespace = namespaces
	}
	if len(processes) > 0 {
		filter.BinaryRegex = processes
	}
	if len(pods) > 0 {
		filter.PodRegex = pods
	}
	if len(ips) > 0 {
		filter.IpCidr = ips
	}
	if len(sourceIPs) > 0 {
		filter.SourceIpCidr = sourceIPs
	}
	if len(destIPs) > 0 {
		filter.DestinationIpCidr = destIPs
	}
	if len(destNames) > 0 {
		filter.DestinationNamesRegex = destNames
	}
	if len(sniNames) > 0 {
		filter.SniRegex = sniNames
	}
	if len(uris) > 0 {
		filter.UriRegex = uris
	}
	if len(destPods) > 0 {
		filter.DestinationPodRegex = destPods
	}
	// Is used to filter on the event types i.e. PROCESS_EXEC, PROCESS_EXIT etc.
	if len(ossGetevents.Options.EventTypes) > 0 {
		var eventType tetragon.EventType

		for _, v := range ossGetevents.Options.EventTypes {
			eventType = tetragon.EventType(tetragon.EventType_value[v])
			filter.EventSet = append(filter.EventSet, eventType)
		}
	}

	return &filter
}

func New() *cobra.Command {
	ossGetevents.GetEncoder = GetEncoder
	ossGetevents.GetFilter = GetFilter
	cmd := ossGetevents.New()
	cmd.Long = fmt.Sprintf(ossGetevents.DocLong, "hubble-enterprise")

	flags := cmd.Flags()
	flags.StringSliceVar(&ips, "ip-cidr", nil, "Get ProcessListen events by IP CIDR")
	flags.StringSliceVar(&sourceIPs, "source-ip-cidr", nil, "Get network events by source IP CIDR")
	flags.StringSliceVar(&destIPs, "dest-ip-cidr", nil, "Get network events by destination IP CIDR")
	flags.StringSliceVar(&destNames, "dest-name", nil, "Get network events by destination names field regex")
	flags.StringSliceVar(&sniNames, "sni-name", nil, "Get network events by SNI name field regex")
	flags.StringSliceVar(&uris, "uri", nil, "Get network events by URI field regex")
	flags.StringSliceVar(&destPods, "dest-pod", nil, "Get network events by destination pod field regex")

	return cmd
}

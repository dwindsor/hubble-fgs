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
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/cmd/tetra/common"
	ossEncoder "github.com/cilium/tetragon/pkg/encoder"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/isovalent/hubble-fgs/pkg/encoder"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
)

// GetEncoder returns an encoder for an event stream based on configuration options.
var GetEncoder = func(w io.Writer, colorMode ossEncoder.ColorMode, timestamps bool, compact bool) ossEncoder.EventEncoder {
	if compact {
		return encoder.NewEnterpriseEncoder(w, colorMode, timestamps)
	}
	return json.NewEncoder(w)
}

func getRequest(includeFields, excludeFields []string, namespaces []string, host bool, processes, pods, IPs, sourceIPs, destIPs, destNames, SNINames, URIs, destPods []string) *tetragon.GetEventsRequest {
	if host {
		// Host events can be matched by an empty namespace string.
		namespaces = append(namespaces, "")
	}

	var fieldFilters []*tetragon.FieldFilter
	if len(includeFields) > 0 {
		fieldFilters = append(fieldFilters, &tetragon.FieldFilter{
			EventSet: []tetragon.EventType{},
			Fields: &fieldmaskpb.FieldMask{
				Paths: includeFields,
			},
			Action: tetragon.FieldFilterAction_INCLUDE,
		})
	}
	if len(excludeFields) > 0 {
		fieldFilters = append(fieldFilters, &tetragon.FieldFilter{
			EventSet: []tetragon.EventType{},
			Fields: &fieldmaskpb.FieldMask{
				Paths: excludeFields,
			},
			Action: tetragon.FieldFilterAction_EXCLUDE,
		})
	}

	return &tetragon.GetEventsRequest{
		AllowList: []*tetragon.Filter{{
			BinaryRegex:           processes,
			Namespace:             namespaces,
			PodRegex:              pods,
			IpCidr:                IPs,
			SourceIpCidr:          sourceIPs,
			DestinationIpCidr:     destIPs,
			DesintationNamesRegex: destNames,
			SniRegex:              SNINames,
			UriRegex:              URIs,
			DestinationPodRegex:   destPods,
		}},
		FieldFilters: fieldFilters,
	}
}

var (
	host          bool
	namespaces    []string
	processes     []string
	pods          []string
	IPs           []string
	sourceIPs     []string
	destIPs       []string
	destNames     []string
	SNINames      []string
	URIs          []string
	destPods      []string
	timestamps    bool
	output        string
	color         string
	includeFields []string
	excludeFields []string
)

func getEvents(ctx context.Context, client tetragon.FineGuidanceSensorsClient) {
	compact := output == "compact"
	colorMode := ossEncoder.ColorMode(color)

	request := getRequest(includeFields, excludeFields, namespaces, host, processes, pods, IPs, sourceIPs, destIPs, destNames, SNINames, URIs, destPods)
	stream, err := client.GetEvents(ctx, request)
	if err != nil {
		logger.GetLogger().WithError(err).Fatal("Failed to call GetEvents")
	}
	eventEncoder := GetEncoder(os.Stdout, colorMode, timestamps, compact)
	for {
		res, err := stream.Recv()
		if err != nil {
			if !errors.Is(err, context.Canceled) && status.Code(err) != codes.Canceled {
				logger.GetLogger().WithError(err).Fatal("Failed to receive events")
			}
			return
		}
		if err = eventEncoder.Encode(res); err != nil {
			logger.GetLogger().WithError(err).WithField("event", res).Debug("Failed to encode event")
		}
	}
}

func New() *cobra.Command {
	cmd := cobra.Command{
		Use:   "getevents",
		Short: "Print events",
		Run: func(cmd *cobra.Command, args []string) {
			common.CliRun(getEvents)
		},
	}

	flags := cmd.Flags()
	flags.StringVarP(&output, "output", "o", "json", "Output format. json or compact")
	flags.StringVar(&color, "color", "auto", "Colorize compact output. auto, always, or never")
	flags.StringSliceVarP(&includeFields, "include-fields", "f", nil, "Include fields in events")
	flags.StringSliceVarP(&excludeFields, "exclude-fields", "F", nil, "Exclude fields from events")
	flags.StringSliceVarP(&namespaces, "namespace", "n", nil, "Get events by Kubernetes namespaces")
	flags.StringSliceVar(&processes, "process", nil, "Get events by process name regex")
	flags.StringSliceVar(&pods, "pod", nil, "Get events by pod name regex")
	flags.StringSliceVar(&IPs, "ip-cidr", nil, "Get ProcessListen events by IP CIDR")
	flags.StringSliceVar(&sourceIPs, "source-ip-cidr", nil, "Get network events by source IP CIDR")
	flags.StringSliceVar(&destIPs, "dest-ip-cidr", nil, "Get network events by destination IP CIDR")
	flags.StringSliceVar(&destNames, "dest-name", nil, "Get network events by destination names field regex")
	flags.StringSliceVar(&SNINames, "sni-name", nil, "Get network events by SNI name field regex")
	flags.StringSliceVar(&URIs, "uri", nil, "Get network events by URI field regex")
	flags.StringSliceVar(&destPods, "dest-pod", nil, "Get network events by destination pod field regex")
	flags.BoolVar(&host, "host", false, "Get host events")
	flags.BoolVar(&timestamps, "timestamps", false, "Include timestamps in compact output")
	viper.BindPFlags(flags)

	return &cmd
}

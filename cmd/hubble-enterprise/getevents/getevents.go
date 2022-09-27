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
)

// GetEncoder returns an encoder for an event stream based on configuration options.
var GetEncoder = func(w io.Writer, colorMode ossEncoder.ColorMode, timestamps bool, compact bool) ossEncoder.EventEncoder {
	if compact {
		return encoder.NewEnterpriseEncoder(w, colorMode, timestamps)
	}
	return json.NewEncoder(w)
}

func getRequest(namespaces []string, host bool, processes, pods, IPs, sourceIPs, destIPs, destNames, SNINames, URIs, destPods []string) *tetragon.GetEventsRequest {
	if host {
		// Host events can be matched by an empty namespace string.
		namespaces = append(namespaces, "")
	}
	return &tetragon.GetEventsRequest{
		AllowList: []*tetragon.Filter{{
			BinaryRegex: processes,
			Namespace:   namespaces,
			PodRegex:    pods,
			IpCidr: []*tetragon.IPFilter{{
				EventSet: []tetragon.EventType{},
				Cidr:     IPs,
			}},
			SourceIpCidr: []*tetragon.IPFilter{{
				EventSet: []tetragon.EventType{},
				Cidr:     sourceIPs,
			}},
			DestinationIpCidr: []*tetragon.IPFilter{{
				EventSet: []tetragon.EventType{},
				Cidr:     destIPs,
			}},
			DesintationNamesRegex: destNames,
			SniRegex:              SNINames,
			UriRegex:              URIs,
			DestinationPodRegex:   destPods,
		}},
	}
}

func getEvents(ctx context.Context, client tetragon.FineGuidanceSensorsClient) {
	host := viper.GetBool("host")
	namespaces := viper.GetStringSlice("namespace")
	processes := viper.GetStringSlice("process")
	pods := viper.GetStringSlice("pod")
	IPs := viper.GetStringSlice("ip-cidr")
	sourceIPs := viper.GetStringSlice("source-ip-cidr")
	destIPs := viper.GetStringSlice("dest-ip-cidr")
	destNames := viper.GetStringSlice("dest-name")
	SNINames := viper.GetStringSlice("sni-name")
	URIs := viper.GetStringSlice("uri")
	destPods := viper.GetStringSlice("dest-pod")
	timestamps := viper.GetBool("timestamps")
	compact := viper.GetString(common.KeyOutput) == "compact"
	colorMode := ossEncoder.ColorMode(viper.GetString(common.KeyColor))

	request := getRequest(namespaces, host, processes, pods, IPs, sourceIPs, destIPs, destNames, SNINames, URIs, destPods)
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
	flags.StringP("output", "o", "json", "Output format. json or compact")
	flags.String("color", "auto", "Colorize compact output. auto, always, or never")
	flags.StringSliceP("namespace", "n", nil, "Get events by Kubernetes namespaces")
	flags.StringSlice("process", nil, "Get events by process name regex")
	flags.StringSlice("pod", nil, "Get events by pod name regex")
	flags.StringSlice("ip-cidr", nil, "Get ProcessListen events by IP CIDR")
	flags.StringSlice("source-ip-cidr", nil, "Get network events by source IP CIDR")
	flags.StringSlice("dest-ip-cidr", nil, "Get network events by destination IP CIDR")
	flags.StringSlice("dest-name", nil, "Get network events by destination names field regex")
	flags.StringSlice("sni-name", nil, "Get network events by SNI name field regex")
	flags.StringSlice("uri", nil, "Get network events by URI field regex")
	flags.StringSlice("dest-pod", nil, "Get network events by destination pod field regex")
	flags.Bool("host", false, "Get host events")
	flags.Bool("timestamps", false, "Include timestamps in compact output")
	viper.BindPFlags(flags)

	return &cmd
}

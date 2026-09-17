// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package splunk

import (
	"context"
	"fmt"

	protovalidate "buf.build/go/protovalidate"
	"github.com/cilium/tetragon/cmd/tetra/common"
	"github.com/spf13/cobra"

	splunkV1 "github.com/isovalent/ipa/splunk/v1alpha"
)

type SplunkClient struct {
	common.ConnWithContext
	Client splunkV1.SplunkServiceClient
}

func New() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "splunk",
		Short: "Configure Splunk integrations",
	}

	cmd.AddCommand(newHECCommand())
	return cmd
}

// NewSplunkClient return a connected client to a tetragon server, caller
// must call Close() on the client. On failure to connect, this function calls
// Fatal() thus stopping execution.
func NewClient(ctx context.Context) (*SplunkClient, error) {
	ret, err := common.NewConnWithContext(ctx, common.ResolveServerAddress(), common.Timeout, "splunk.v1alpha.SplunkService")
	if err != nil {
		return nil, err
	}

	c := &SplunkClient{
		ConnWithContext: *ret,
		Client:          splunkV1.NewSplunkServiceClient(ret.Conn),
	}

	return c, nil
}

func updateSplunkHecSettings(ctx context.Context, client splunkV1.SplunkServiceClient, endpoint, token string, sourceTypes []string) (*splunkV1.SetHecSettingsResponse, error) {
	request := &splunkV1.SetHecSettingsRequest{
		Endpoint:    endpoint,
		Token:       token,
		SourceTypes: sourceTypes,
	}
	if err := protovalidate.GlobalValidator.Validate(request); err != nil {
		return nil, fmt.Errorf("invalid Splunk HEC settings: %w", err)
	}

	resp, err := client.SetHecSettings(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("failed to update Splunk HEC settings: %w", err)
	}

	return resp, nil
}

func newHECCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "hec",
		Short: "Configure Splunk HEC export",
	}

	cmd.AddCommand(newHECGetCommand(), newHECSetCommand())
	return cmd
}

func newHECGetCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "get",
		Short: "Get Splunk HEC settings",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, err := NewClient(cmd.Context())
			if err != nil {
				return fmt.Errorf("failed to create Splunk client: %w", err)
			}
			defer client.Close()

			settings, err := client.Client.GetHecSettings(client.Ctx, &splunkV1.GetHecSettingsRequest{})
			if err != nil {
				return fmt.Errorf("failed to get Splunk HEC settings: %w", err)
			}
			cmd.Println(settings)
			return nil
		},
	}
}

func mergeHecSettings(current *splunkV1.GetHecSettingsResponse, endpoint, token string, sourceTypes []string, endpointChanged, tokenChanged, sourceTypesChanged bool) *splunkV1.SetHecSettingsRequest {
	settings := &splunkV1.SetHecSettingsRequest{
		Endpoint:    current.GetEndpoint(),
		Token:       current.GetToken(),
		SourceTypes: append([]string{}, current.GetSourceTypes()...),
	}
	if endpointChanged {
		settings.Endpoint = endpoint
	}
	if tokenChanged {
		settings.Token = token
	}
	if sourceTypesChanged {
		settings.SourceTypes = append([]string{}, sourceTypes...)
	}
	return settings
}

func newHECSetCommand() *cobra.Command {
	var endpoint string
	var token string
	var sources []string

	cmd := &cobra.Command{
		Use:   "set",
		Short: "Set Splunk HEC settings",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			flags := cmd.Flags()
			if !flags.Changed("endpoint") && !flags.Changed("token") && !flags.Changed("source") {
				return cmd.Usage()
			}

			client, err := NewClient(cmd.Context())
			if err != nil {
				return fmt.Errorf("failed to create Splunk client: %w", err)
			}
			defer client.Close()

			current, err := client.Client.GetHecSettings(client.Ctx, &splunkV1.GetHecSettingsRequest{})
			if err != nil {
				return fmt.Errorf("failed to get Splunk HEC settings: %w", err)
			}

			settings := mergeHecSettings(
				current,
				endpoint,
				token,
				sources,
				flags.Changed("endpoint"),
				flags.Changed("token"),
				flags.Changed("source"),
			)
			_, err = updateSplunkHecSettings(client.Ctx, client.Client, settings.Endpoint, settings.Token, settings.SourceTypes)
			if err != nil {
				return fmt.Errorf("failed to update Splunk HEC settings: %w", err)
			}
			fmt.Println("Successfully updated Splunk HEC settings", "endpoint", settings.Endpoint, "token", settings.Token, "sourcetypes", settings.SourceTypes)
			return nil
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&endpoint, "endpoint", "", "Splunk HEC endpoint URL")
	flags.StringVar(&token, "token", "", "Splunk HEC token")
	flags.StringArrayVar(&sources, "source", nil, "Splunk HEC source (may be provided multiple times)")

	return cmd
}

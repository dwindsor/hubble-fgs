// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package network

import (
	"fmt"
	"io"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/cilium/tetragon/api/v1/tetragon"
)

func New() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "netpol",
		Short: "Manage Tetragon network policy",
	}

	addCmd := &cobra.Command{
		Use:   "add <yaml_file>",
		Short: "add Tetragon network policy",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := NewClient()
			if err != nil {
				return fmt.Errorf("failed to create client: %w", err)
			}
			defer c.Close()

			yamlb, err := os.ReadFile(args[0])
			if err != nil {
				return fmt.Errorf("failed to read yaml file %s: %w", args[0], err)
			}

			_, err = c.Client.AddNetworkPolicyFromYAML(c.ctx, &tetragon.AddNetworkPolicyFromYAMLRequest{
				Yaml: string(yamlb),
			})
			if err != nil {
				return fmt.Errorf("failed to add network policy: %w", err)
			}
			cmd.Printf("network policy %q added\n", args[0])

			return nil
		},
	}

	delCmd := &cobra.Command{
		Use:   "delete <name>",
		Short: "delete Tetragon network policy",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := NewClient()
			if err != nil {
				return fmt.Errorf("failed to create client: %w", err)
			}
			defer c.Close()

			_, err = c.Client.DeleteNetworkPolicy(c.ctx, &tetragon.DeleteNetworkPolicyRequest{
				Name: args[0],
			})
			if err != nil {
				return fmt.Errorf("failed to delete network policy: %w", err)
			}
			cmd.Printf("network policy %q deleted\n", args[0])

			return nil
		},
	}

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "list loaded Tetragon network policy",
		Args:  cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, _ []string) error {
			return ListNetworkPolicy(
				cmd, "text",
				func(n string) (string, bool) { return n, true },
			)
		},
	}

	getCmd := &cobra.Command{
		Use:   "get <name>",
		Short: "get Tetragon network policy",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := NewClient()
			if err != nil {
				return fmt.Errorf("failed to create client: %w", err)
			}
			defer c.Close()

			res, err := c.Client.GetNetworkPolicy(c.ctx, &tetragon.GetNetworkPolicyRequest{
				Name: args[0],
			})
			if err != nil || res == nil {
				return fmt.Errorf("failed to get network policy rule: %w", err)
			}

			cmd.Printf("%s\n", res.Yaml)

			return nil
		},
	}

	cmd.AddCommand(
		addCmd,
		delCmd,
		listCmd,
		getCmd,
	)

	return cmd
}

func PrintNetworkPolicy(
	output io.Writer,
	info []*tetragon.NetworkPolicyInfo,
) {
	w := tabwriter.NewWriter(output, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "NAME")
	for _, e := range info {
		fmt.Fprintf(w, "%s\n", e.Name)
	}
	w.Flush()
}

func ListNetworkPolicy(
	cmd *cobra.Command,
	output string,
	mapName func(name string) (string, bool), // mapName filters and renames policies
) error {
	res, err := ListNetworkPolicies()
	if err != nil {
		return err
	}

	// keep only the rules we want in the list, and change their name
	for i := 0; i < len(res.Info); i++ {
		entry := res.Info[i]
		name, ok := mapName(entry.Name)
		if !ok {
			res.Info = append(res.Info[:i], res.Info[i+1:]...)
			i--
		}
		entry.Name = name
	}

	switch output {
	case "json":
		b, err := res.MarshalJSON()
		if err != nil {
			return fmt.Errorf("failed to generate json: %w", err)
		}
		cmd.Println(string(b))
	case "text":
		PrintNetworkPolicy(cmd.OutOrStdout(), res.Info)
	}
	return nil
}

func ListNetworkPolicies() (*tetragon.ListNetworkPolicyResponse, error) {
	c, err := NewClient()
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC client: %w", err)
	}
	defer c.Close()

	res, err := c.Client.ListNetworkPolicy(c.ctx, &tetragon.ListNetworkPolicyRequest{})
	if err != nil || res == nil {
		return nil, fmt.Errorf("failed to list network policy: %w", err)
	}
	return res, nil
}

// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.
package rules

import (
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/spf13/cobra"
)

func New() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "rules",
		Aliases: []string{"rule"},
		Short:   "Manage rules",
	}

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "list loaded rules",
		Args:  cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, _ []string) error {
			res, err := ListRules()
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 3, ' ', 0)
			fmt.Fprintln(w, "PATH\tVERSION\tTYPE\tMODE\tLOADED\tCOUNTER\tPOD_SELECTOR_LABELS")
			for _, r := range res.Rules.Rules {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%t\t%d\t%v\n",
					strings.Join(r.Path, "-"),
					r.Version,
					r.Type.String(),
					r.Status.Mode.String(),
					r.Status.Loaded,
					r.Counter,
					r.PodSelectorLabels)
			}
			w.Flush()
			return nil
		},
	}

	cmd.AddCommand(
		listCmd,
	)

	return cmd
}

func ListRules() (*tetragon.ListRulesResponse, error) {
	c, err := NewClient()
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC client: %w", err)
	}
	defer c.Close()

	res, err := c.Client.ListRules(c.Ctx, &tetragon.ListRulesRequest{})
	if err != nil || res == nil {
		return nil, fmt.Errorf("failed to list alert rules: %w", err)
	}
	return res, nil
}

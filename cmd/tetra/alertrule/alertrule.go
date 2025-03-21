// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package alertrule

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/cilium/tetragon/api/v1/tetragon"
)

func New() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "alertrule",
		Short: "Manage alert rules",
	}

	addCmd := &cobra.Command{
		Use:   "add <yaml_file>",
		Short: "add/update alert rule",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newClient()
			if err != nil {
				return fmt.Errorf("failed to create client: %w", err)
			}
			defer c.close()

			yamlb, err := os.ReadFile(args[0])
			if err != nil {
				return fmt.Errorf("failed to read yaml file %s: %w", args[0], err)
			}

			_, err = c.client.AddAlertRuleFromYAML(c.ctx, &tetragon.AddAlertRuleFromYAMLRequest{
				Yaml: string(yamlb),
			})
			if err != nil {
				return fmt.Errorf("failed to add alert rule: %w", err)
			}
			cmd.Printf("alert rule %q added\n", args[0])

			return nil
		},
	}

	delCmd := &cobra.Command{
		Use:   "delete <name>",
		Short: "delete alert rule",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newClient()
			if err != nil {
				return fmt.Errorf("failed to create client: %w", err)
			}
			defer c.close()

			_, err = c.client.DeleteAlertRule(c.ctx, &tetragon.DeleteAlertRuleRequest{
				Name: args[0],
			})
			if err != nil {
				return fmt.Errorf("failed to delete alert rule: %w", err)
			}
			cmd.Printf("alert rule %q deleted\n", args[0])

			return nil
		},
	}

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "list loaded alert rules",
		Args:  cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := newClient()
			if err != nil {
				return fmt.Errorf("failed to create client: %w", err)
			}
			defer c.close()

			res, err := c.client.ListAlertRules(c.ctx, &tetragon.ListAlertRulesRequest{})
			if err != nil || res == nil {
				return fmt.Errorf("failed to list alert rules: %w", err)
			}

			for _, rule := range res.Rules {
				cmd.Printf("%s\n", rule.Meta.GetName())
			}

			return nil
		},
	}

	getCmd := &cobra.Command{
		Use:   "get <name>",
		Short: "get alert rule",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newClient()
			if err != nil {
				return fmt.Errorf("failed to create client: %w", err)
			}
			defer c.close()

			res, err := c.client.GetAlertRule(c.ctx, &tetragon.GetAlertRuleRequest{
				Name: args[0],
			})
			if err != nil || res == nil {
				return fmt.Errorf("failed to get alert rule: %w", err)
			}

			cmd.Printf("%+v\n", res.Rule.Meta)

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

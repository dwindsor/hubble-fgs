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
	"io"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/cilium/tetragon/api/v1/tetragon"
)

func New() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "alertrule",
		Short: "Manage alert rules",
	}

	var domain string

	addCmd := &cobra.Command{
		Use:   "add <yaml_file>",
		Short: "add/update alert rule",
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

			_, err = c.Client.AddAlertRuleFromYAML(c.ctx, &tetragon.AddAlertRuleFromYAMLRequest{
				Yaml:   string(yamlb),
				Domain: domain,
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
			c, err := NewClient()
			if err != nil {
				return fmt.Errorf("failed to create client: %w", err)
			}
			defer c.Close()

			_, err = c.Client.DeleteAlertRule(c.ctx, &tetragon.DeleteAlertRuleRequest{
				Name:   args[0],
				Domain: domain,
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
			return ListAlerts(
				cmd, "text", domain)
		},
	}

	getCmd := &cobra.Command{
		Use:   "get <name>",
		Short: "get alert rule",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := NewClient()
			if err != nil {
				return fmt.Errorf("failed to create client: %w", err)
			}
			defer c.Close()

			res, err := c.Client.GetAlertRule(c.ctx, &tetragon.GetAlertRuleRequest{
				Name:   args[0],
				Domain: domain,
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

	cmd.Flags().StringVarP(&domain, "domain", "", "", "Domain to be used. Use k8s to act on CRD alerts. By default only acts against grpc domain.")

	testCmd := testCommand()
	if testCmd != nil {
		cmd.AddCommand(testCmd)
	}

	return cmd
}

func printAlertRules(
	output io.Writer,
	rules []*tetragon.AlertRule,
) {
	w := tabwriter.NewWriter(output, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "NAME\tDOMAIN\tSEVERITY\tTAGS\tMESSAGE")
	for _, rule := range rules {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			rule.Meta.Name,
			rule.Meta.Domain,
			rule.Meta.Severity,
			rule.Meta.Tags,
			rule.Meta.Message)
	}
	w.Flush()
}

// ListAlerts is a helper to list a subset of the alert rules
func ListAlerts(
	cmd *cobra.Command,
	output string,
	domain string,
) error {
	res, err := ListAlertRules(domain)
	if err != nil {
		return err
	}

	switch output {
	case "json":
		b, err := res.MarshalJSON()
		if err != nil {
			return fmt.Errorf("failed to generate json: %w", err)
		}
		cmd.Println(string(b))
	case "text":
		printAlertRules(cmd.OutOrStdout(), res.Rules)
	}
	return nil
}

func ListAlertRules(domain string) (*tetragon.ListAlertRulesResponse, error) {
	c, err := NewClient()
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC client: %w", err)
	}
	defer c.Close()

	res, err := c.Client.ListAlertRules(c.ctx, &tetragon.ListAlertRulesRequest{Domain: domain})
	if err != nil || res == nil {
		return nil, fmt.Errorf("failed to list alert rules: %w", err)
	}
	return res, nil
}

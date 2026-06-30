// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package policies

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/cmd/tetra/common"
	tetragonv1alpha1 "github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	ipav1alpha1 "github.com/isovalent/ipa/k8s/apis/cilium.io/v1alpha1"
	"github.com/spf13/cobra"
	grpcCodes "google.golang.org/grpc/codes"
	grpcStatus "google.golang.org/grpc/status"

	"github.com/isovalent/hubble-fgs/cmd/tetra/alertrule"
	common2 "github.com/isovalent/hubble-fgs/cmd/tetra/common"
	"github.com/isovalent/hubble-fgs/cmd/tetra/network"
	"github.com/isovalent/hubble-fgs/pkg/policies"
	"github.com/isovalent/hubble-fgs/pkg/sandboxpolicy"
)

func addCmd(domain *string) *cobra.Command {
	ret := &cobra.Command{
		Use:   "add [file|folder]",
		Short: "add a policy or a list of policies of any kind",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			alertClient, err := alertrule.NewClient()
			if err != nil {
				return err
			}
			defer alertClient.Close()

			networkClient, err := network.NewClient()
			if err != nil {
				return err
			}
			defer networkClient.Close()

			tracingClient, err := common.NewClientWithDefaultContextAndAddress()
			if err != nil {
				return err
			}
			defer tracingClient.Close()

			loader := policies.NewRemoteLoader(alertClient.Client, networkClient.Client, tracingClient.Client, *domain)

			fname := args[0]
			// check if it is a yaml file or directory
			info, err := os.Stat(fname)
			if err != nil {
				return err
			}

			if info.IsDir() {
				err = policies.LoadFromDir(context.Background(), fname, loader)
			} else {
				err = policies.LoadFromFile(context.Background(), fname, loader)
			}
			return err
		},
	}
	return ret
}

func isUnimplemented(err error) bool {
	for err != nil {
		if grpcStatus.Code(err) == grpcCodes.Unimplemented {
			return true
		}
		err = errors.Unwrap(err)
	}
	return false
}

func listCmd(domain *string) *cobra.Command {
	ret := &cobra.Command{
		Use:   "list",
		Short: "list all policies of any kind",
		RunE: func(cmd *cobra.Command, _ []string) error {
			alertRules, err := alertrule.ListAlertRules(*domain)
			if err != nil {
				return err
			}
			// List all domains policies
			tracingPolicies, err := common2.ListTetragonPolicies(*domain)
			if err != nil {
				return err
			}
			networkPolicies, err := network.ListNetworkPolicies()
			// if get an Unimplemented gRPC error, don't fail.
			// This allows tetra policies to work in the nok8s build.
			if err != nil && !isUnimplemented(err) {
				return err
			}

			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 3, ' ', 0)
			header := "ID\tKIND\tDOMAIN\tNAME\tNAMESPACE\tTAGS"
			fmt.Fprintln(w, header)
			for _, pol := range tracingPolicies.GetPolicies() {
				namespace := pol.Namespace
				if namespace == "" {
					namespace = "(global)"
				}
				policyKind := tetragonv1alpha1.TPKindDefinition
				policyName := pol.Name
				if pol.Domain == sandboxpolicy.SandboxDomain {
					policyKind = "SandboxPolicy"
				}
				fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%s\n",
					pol.Id,
					policyKind,
					pol.Domain,
					policyName,
					namespace,
					"NONE",
				)
			}

			for _, pol := range networkPolicies.GetInfo() {
				fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%s\n",
					-1,
					ipav1alpha1.TNPKindDefinition,
					"",
					pol.Name,
					"NONE",
					"NONE",
				)
			}

			for _, pol := range alertRules.GetRules() {
				meta := pol.GetMeta()
				fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%s\n",
					-1,
					"AlertRule",
					"",
					meta.Name,
					"NONE",
					strings.Join(meta.Tags, ","),
				)
			}
			return w.Flush()
		},
	}
	return ret
}

func getNameAndNamespace(s string) (string, string) {
	policyName := s
	policyNamespace := ""
	names := strings.Split(policyName, "@")
	policyName = names[0]
	if len(names) > 1 {
		policyNamespace = names[1]
	}
	return policyName, policyNamespace
}

func getCmd(domain *string) *cobra.Command {
	ret := &cobra.Command{
		Use:   "get <name>",
		Short: "get a policy of any kind",
		Long:  "Get a policy of any kind; for namespaced policies, use name@namespace.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			policyName, policyNamespace := getNameAndNamespace(args[0])

			alertClient, err := alertrule.NewClient()
			if err != nil {
				return err
			}
			defer alertClient.Close()

			networkClient, err := network.NewClient()
			if err != nil {
				return err
			}
			defer networkClient.Close()

			tracingClient, err := common.NewClientWithDefaultContextAndAddress()
			if err != nil {
				return err
			}
			defer tracingClient.Close()

			resTracing, _ := tracingClient.Client.ListTracingPolicies(context.Background(), &tetragon.ListTracingPoliciesRequest{Domain: *domain})
			if resTracing != nil {
				for _, pol := range resTracing.GetPolicies() {
					if pol.Name == policyName && pol.Namespace == policyNamespace {
						json, err := pol.MarshalJSON()
						if err != nil {
							return err
						}
						cmd.Printf("%s\n", json)
						return nil
					}
				}
			}

			resNetwork, _ := networkClient.Client.GetNetworkPolicy(context.Background(), &tetragon.GetNetworkPolicyRequest{Name: policyName})
			if resNetwork != nil {
				cmd.Printf("%s\n", resNetwork.Yaml)
				return nil
			}
			resAlert, _ := alertClient.Client.GetAlertRule(context.Background(), &tetragon.GetAlertRuleRequest{Name: policyName, Domain: *domain})
			if resAlert != nil {
				cmd.Printf("%+v\n", resAlert.Rule.Meta)
				return nil
			}
			return fmt.Errorf("no policy found with name %q (namespace %q)", policyName, policyNamespace)
		},
	}
	return ret
}

func delCmd(domain *string) *cobra.Command {
	ret := &cobra.Command{
		Use:   "delete <name>",
		Short: "delete a policy of any kind",
		Long:  "Delete a policy of any kind; for namespaced policies, use name@namespace.",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			policyName, policyNamespace := getNameAndNamespace(args[0])

			alertClient, err := alertrule.NewClient()
			if err != nil {
				return err
			}
			defer alertClient.Close()

			networkClient, err := network.NewClient()
			if err != nil {
				return err
			}
			defer networkClient.Close()

			tracingClient, err := common.NewClientWithDefaultContextAndAddress()
			if err != nil {
				return err
			}
			defer tracingClient.Close()

			_, err = tracingClient.Client.DeleteTracingPolicy(context.Background(), &tetragon.DeleteTracingPolicyRequest{Name: policyName, Namespace: policyNamespace, Domain: *domain})
			if err == nil {
				return nil
			}
			_, err = networkClient.Client.DeleteNetworkPolicy(context.Background(), &tetragon.DeleteNetworkPolicyRequest{Name: policyName})
			if err == nil {
				return nil
			}
			_, err = alertClient.Client.DeleteAlertRule(context.Background(), &tetragon.DeleteAlertRuleRequest{Name: policyName, Domain: *domain})
			if err == nil {
				return nil
			}
			return fmt.Errorf("no policy found with name %q (namespace %q)", policyName, policyNamespace)
		},
	}
	return ret
}

func New() *cobra.Command {
	ret := &cobra.Command{
		Use:     "policies",
		Aliases: []string{"policy"},
		Short:   "manage policies of any kind",
	}

	var domain string
	ret.PersistentFlags().StringVarP(&domain, "domain", "", "", "Domain to be used. Use k8s to act on CRD tracing policies or alerts. By default only acts against grpc domain.")

	ret.AddCommand(
		addCmd(&domain),
		listCmd(&domain),
		getCmd(&domain),
		delCmd(&domain),
	)

	return ret
}

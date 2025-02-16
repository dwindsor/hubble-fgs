// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package sandboxpolicy

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"sigs.k8s.io/yaml"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/cmd/tetra/common"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/isovalent/hubble-fgs/pkg/sandboxpolicy"
)

func listCmd() *cobra.Command {
	var spListOutputFlag string

	cmd := &cobra.Command{
		Use:   "list",
		Short: "list loaded sandbox policies",
		Long:  "List loaded sandbox policies, use the JSON output format for full output.",
		Args:  cobra.ExactArgs(0),
		PreRunE: func(_ *cobra.Command, _ []string) error {
			if spListOutputFlag != "json" && spListOutputFlag != "text" {
				return fmt.Errorf("invalid value for %q flag: %s", common.KeyOutput, spListOutputFlag)
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := common.NewClientWithDefaultContextAndAddress()
			if err != nil {
				return fmt.Errorf("failed to create gRPC client: %w", err)
			}
			defer c.Close()

			res, err := c.Client.ListTracingPolicies(c.Ctx, &tetragon.ListTracingPoliciesRequest{})
			if err != nil || res == nil {
				return fmt.Errorf("failed to list tracing policies: %w", err)
			}

			// keep only sandbox policies in the list
			for i := 0; i < len(res.Policies); i++ {
				pol := res.Policies[i]
				name := sandboxpolicy.NameFromTPName(pol.Name)
				if name == "" {
					res.Policies = append(res.Policies[:i], res.Policies[i+1:]...)
					i--
				}
				pol.Name = name
			}

			switch spListOutputFlag {
			case "json":
				b, err := res.MarshalJSON()
				if err != nil {
					return fmt.Errorf("failed to generate json: %w", err)
				}
				cmd.Println(string(b))
			case "text":
				// tabwriter config imitates kubectl default output, i.e. 3 spaces padding
				w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 3, ' ', 0)
				fmt.Fprintln(w, "ID\tNAME\tSTATE\tFILTERID\tNAMESPACE\tSENSORS")

				for _, pol := range res.Policies {
					namespace := pol.Namespace
					if namespace == "" {
						namespace = "(global)"
					}

					sensors := strings.Join(pol.Sensors, ",")

					// From v0.11 and before, enabled, filterID and error were
					// bundled in a string. To have a retro-compatible tetra
					// command, we scan the string. If the scan fails, it means
					// something else might be in Info and we print it.
					//
					// we can drop the following block (and comment) when we
					// feel tetra should support only version after v0.11
					if pol.Info != "" {
						var parsedEnabled bool
						var parsedFilterID uint64
						var parsedError string
						var parsedName string
						str := strings.NewReader(pol.Info)
						_, err := fmt.Fscanf(str, "%253s enabled:%t filterID:%d error:%512s", &parsedName, &parsedEnabled, &parsedFilterID, &parsedError)
						if err == nil {
							if parsedEnabled {
								pol.State = tetragon.TracingPolicyState_TP_STATE_ENABLED
							}
							pol.FilterId = parsedFilterID
							pol.Error = parsedError
							pol.Info = ""
						}
					}

					fmt.Fprintf(w, "%d\t%s\t%s\t%d\t%s\t%s\t\n",
						pol.Id,
						pol.Name,
						strings.TrimPrefix(strings.ToLower(pol.State.String()), "tp_state_"),
						pol.FilterId,
						namespace,
						sensors,
					)
				}
				w.Flush()
			}

			return nil
		},
	}
	flags := cmd.Flags()
	flags.StringVarP(&spListOutputFlag, common.KeyOutput, "o", "text", "Output format. text or json")

	return cmd
}

func convertCmd() *cobra.Command {
	var useMulti bool
	ret := &cobra.Command{
		Use:   "convert [file]",
		Short: "convert a sandbox policy to a tracing policy (intended for testing)",
		Long:  "Convert a sandbox policy to a tracing policy (intended for testing).\nPipe it over \"yq 'del(.spec.parser) | del(.spec.file) | del(.spec.loader)'\" for better results",
		Args:  cobra.ExactArgs(1),
		Run: func(_ *cobra.Command, args []string) {
			fname := args[0]
			data, err := os.ReadFile(fname)
			if err != nil {
				log.Fatalf("failed to read %s: %v", fname, err)
			}

			pol, err := sandboxpolicy.FromYAML(string(data))
			if err != nil {
				log.Fatalf("failed to parse %s: %v", fname, err)
			}

			var tp interface{}
			switch sp := pol.(type) {
			case *v1alpha1.SandboxPolicy:
				tp, err = sandboxpolicy.ToTracingPolicy(sp)
				if err != nil {
					log.Fatalf("failed to convert %s: %v", fname, err)
				}
			case *v1alpha1.SandboxPolicyNamespaced:
				tp, err = sandboxpolicy.ToTracingPolicyNamespaced(sp)
				if err != nil {
					log.Fatalf("failed to convert %s: %v", fname, err)
				}
			default:
				log.Fatalf("unexpected parsing result of %s", fname)
			}

			out, err := yaml.Marshal(tp)
			if err != nil {
				log.Fatalf("failed to convert %s: %v", fname, err)
			}

			_, err = os.Stdout.Write(out)
			if err != nil {
				log.Fatalf("failed to write data: %v", err)
			}

		},
	}

	flags := ret.Flags()
	flag.BoolVar(&useMulti, "use-multi", false, "enable multi-kprobe")
	viper.BindPFlags(flags)
	return ret
}

func New() *cobra.Command {
	ret := &cobra.Command{
		Use:   "sandboxpolicy",
		Short: "sandboxpolicy utilities",
	}

	ret.AddCommand(
		convertCmd(),
		listCmd(),
	)

	return ret
}

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
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"sigs.k8s.io/yaml"

	"github.com/cilium/tetragon/cmd/tetra/common"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"

	"github.com/isovalent/hubble-fgs/pkg/sandboxpolicy"
	eecommon "github.com/isovalent/hubble-fgs/pkg/tetra/common"
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
			return eecommon.ListPolicies(
				cmd,
				spListOutputFlag,
				sandboxpolicy.SandboxDomain,
			)
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
		RunE: func(_ *cobra.Command, args []string) error {
			fname := args[0]
			data, err := os.ReadFile(fname)
			if err != nil {
				return fmt.Errorf("failed to read %s: %v", fname, err)
			}

			pol, err := sandboxpolicy.FromYAML(string(data))
			if err != nil {
				return fmt.Errorf("failed to parse %s: %v", fname, err)
			}

			var tp any
			switch sp := pol.(type) {
			case *v1alpha1.SandboxPolicy:
				tp, err = sandboxpolicy.ToTracingPolicy(sp)
				if err != nil {
					return fmt.Errorf("failed to convert %s: %v", fname, err)
				}
			case *v1alpha1.SandboxPolicyNamespaced:
				tp, err = sandboxpolicy.ToTracingPolicyNamespaced(sp)
				if err != nil {
					return fmt.Errorf("failed to convert %s: %v", fname, err)
				}
			default:
				return fmt.Errorf("unexpected parsing result of %s", fname)
			}

			out, err := yaml.Marshal(tp)
			if err != nil {
				return fmt.Errorf("failed to convert %s: %v", fname, err)
			}

			_, err = os.Stdout.Write(out)
			if err != nil {
				return fmt.Errorf("failed to write data: %v", err)
			}

			return nil
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

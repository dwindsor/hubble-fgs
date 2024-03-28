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
	"log"
	"os"

	"github.com/isovalent/hubble-fgs/pkg/sandboxpolicy"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"sigs.k8s.io/yaml"
)

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

			spCW, spNS, err := sandboxpolicy.FromYAML(string(data))
			if err != nil {
				log.Fatalf("failed to parse %s: %v", fname, err)
			}

			var tp interface{}
			if spCW != nil {
				tp, err = sandboxpolicy.ToTracingPolicy(spCW)
				if err != nil {
					log.Fatalf("failed to convert %s: %v", fname, err)
				}
			} else if spNS != nil {
				tp, err = sandboxpolicy.ToTracingPolicyNamespaced(spNS)
				if err != nil {
					log.Fatalf("failed to convert %s: %v", fname, err)
				}
			} else {
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
	)

	return ret
}

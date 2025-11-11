package main

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/isovalent/hubble-fgs/cmd/netpol/model"
	"github.com/isovalent/hubble-fgs/cmd/netpol/types"
)

var lintCommand = &cobra.Command{
	Use:   "lint [directory]",
	Short: "Find shadowed rules in a directory of policies (yaml)",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		withOutput(cmd, func(w io.Writer) {
			err := runLint(w, args[0])
			if err != nil {
				printErrorAndExit("Error: %s\n", err)
			}
		})
	},
}

func runLint(w io.Writer, dir string) error {
	if f, err := os.Stat(dir); err != nil {
		return err
	} else if !f.IsDir() {
		return fmt.Errorf("%q is not a directory", dir)
	}
	policy, err := types.ParsePolicyDir(dir)
	if err != nil {
		return err
	}

	fmt.Fprintf(w, "Input policies\n")
	fmt.Fprintf(w, "--------------\n\n")
	types.PrintPolicyTable(w, policy)
	fmt.Fprintln(w)

	if shadowed := model.FindShadowedRules(policy.Rules); len(shadowed) > 0 {
		fmt.Fprintf(w, "Shadowed rules\n")
		fmt.Fprintf(w, "--------------\n\n")
		for _, s := range shadowed {
			fmt.Fprintf(w, "  * Rule %q (%s %s %s -> %s %s %s) is shadowed by:\n",
				s.Rule.RuleName, s.Rule.Action, s.Rule.Source.Prefix.String(), s.Rule.Source.Ports(),
				s.Rule.Destination.Prefix.String(), s.Rule.Destination.Ports(), s.Rule.Source.Protocol)
			for _, r := range s.ShadowedBy {
				fmt.Fprintf(w, "    + %q (%s %s %s -> %s %s %s)\n",
					r.RuleName, r.Action, r.Source.Prefix.String(), r.Source.Ports(),
					r.Destination.Prefix.String(), r.Destination.Ports(), r.Source.Protocol)
			}
			fmt.Fprintln(w)
		}
	}
	return nil
}

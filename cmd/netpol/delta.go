package main

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/isovalent/hubble-fgs/cmd/netpol/model"
	"github.com/isovalent/hubble-fgs/cmd/netpol/types"
)

var diffCommand = &cobra.Command{
	Use:   "diff [production policy directory] [staging policy directory]",
	Short: "Show policy differences",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		withOutput(cmd, func(w io.Writer) {
			err := runDiffYAML(w, args[0], args[1])
			if err != nil {
				fmt.Fprintf(w, "Error: %s\n", err)
				os.Exit(1)
			}
		})
	},
}

func runDiffYAML(w io.Writer, prodDir, stagingDir string) error {
	prodPolicy, err := types.ParsePolicyDir(prodDir)
	if err != nil {
		return err
	}
	stagingPolicy, err := types.ParsePolicyDir(stagingDir)
	if err != nil {
		return err
	}
	prodPolicy, oldPolicy := types.SplitPolicies(prodPolicy, stagingPolicy)
	runDiff(w, prodPolicy, oldPolicy, stagingPolicy)
	return nil
}

func runDiff(w io.Writer, base, oldPolicy, newPolicy types.Policy) {
	fmt.Fprintln(w, "Verdict differences")
	fmt.Fprintf(w, "-------------------\n\n")
	model.PrintDelta(w, base, oldPolicy, newPolicy)

	oldRules, newRules, _ := model.ComputeMinimal(base, oldPolicy, newPolicy)

	fmt.Fprintf(w, "Old policy for affected intervals\n")
	fmt.Fprintf(w, "---------------------------------\n\n")
	types.PrintPolicyTable(w, types.Policy{Rules: oldRules})
	fmt.Fprintln(w)

	fmt.Fprintf(w, "New policy for affected intervals\n")
	fmt.Fprintf(w, "---------------------------------\n\n")
	types.PrintPolicyTable(w, types.Policy{Rules: newRules})
}

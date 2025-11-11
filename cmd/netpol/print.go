package main

import (
	"io"

	"github.com/spf13/cobra"

	"github.com/isovalent/hubble-fgs/cmd/netpol/types"
)

var printCommand = &cobra.Command{
	Use:   "print [directory]",
	Short: "Print policies in directory as a table",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		policy, err := types.ParsePolicyDir(args[0])
		if err != nil {
			printErrorAndExit("Error: %s\n", err)
		}
		withOutput(cmd, func(w io.Writer) {
			if err := types.PrintPolicyTable(w, policy); err != nil {
				printErrorAndExit("Error: %s\n", err)
			}
		})
	},
}

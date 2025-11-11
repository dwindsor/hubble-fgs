package main

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/isovalent/hubble-fgs/cmd/netpol/controller"
	"github.com/isovalent/hubble-fgs/cmd/netpol/tui"
)

var rootCmd = &cobra.Command{
	Use:   "netpol",
	Short: "Network policy utility",
}

func withOutput(cmd *cobra.Command, fn func(w io.Writer)) {
	w := os.Stdout
	out, _ := cmd.InheritedFlags().GetString("output")
	if out != "" {
		f, err := os.OpenFile(out, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0644)
		if err != nil {
			panic(err)
		}
		w = f
		defer f.Close()
	}
	fn(w)
}

var (
	printErrorAndExit = func(f string, args ...any) {
		fmt.Fprintf(os.Stderr, f, args...)
		os.Exit(1)
	}
)

func init() {
	rootCmd.PersistentFlags().StringP("output", "o", "", "Output file instead of stdout")
	rootCmd.AddCommand(
		tui.Command,
		controller.Command,
		lintCommand,
		diffCommand,
		checkCommand,
		printCommand,
		convertCommand,
	)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		printErrorAndExit("Error: %s\n", err)
	}
}

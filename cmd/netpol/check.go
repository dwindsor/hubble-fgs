package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"iter"
	"os"
	"time"

	"github.com/spf13/cobra"
	"go.yaml.in/yaml/v2"

	"github.com/isovalent/hubble-fgs/cmd/netpol/model"
	"github.com/isovalent/hubble-fgs/cmd/netpol/timescape"
	"github.com/isovalent/hubble-fgs/cmd/netpol/types"
)

var (
	checkServerAddress string
	checkSimulate      string
	checkDuration      time.Duration
)

var checkCommand = func() *cobra.Command {
	var tsConfig timescape.Config
	cmd := &cobra.Command{
		Use:   "check [production directory] [staging directory]",
		Short: "Check how staging policies change the verdicts for recent connections",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			if err := tsConfig.Parse(cmd.Flags()); err != nil {
				fmt.Fprintf(os.Stderr, "Error parsing flags: %s\n", err)
				os.Exit(1)
			}
			tsClient, err := timescape.NewClient(tsConfig)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error connecting to Timescape: %s\n", err)
				os.Exit(1)
			}
			withOutput(cmd, func(w io.Writer) {
				err := runCheck(w, tsClient, args[0], args[1])
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error: %s\n", err)
					os.Exit(1)

				}

			})
		},
	}
	cmd.Flags().StringVar(&checkServerAddress, "timescape", "localhost:4244", "Timescape gRPC server address")
	cmd.Flags().DurationVar(&checkDuration, "duration", 10*time.Minute, "How far back in time to look for connections")
	cmd.Flags().StringVar(&checkSimulate, "simulate", "", "Simulate with connections from file")

	tsConfig.Flags(cmd.Flags())
	return cmd
}()

func runCheck(w io.Writer, tsClient *timescape.Client, prodDir, stagingDir string) error {
	prodPolicy, err := types.ParsePolicyDir(prodDir)
	if err != nil {
		return err
	}
	stagingPolicy, err := types.ParsePolicyDir(stagingDir)
	if err != nil {
		return err
	}

	prodPolicy, oldPolicy := types.SplitPolicies(prodPolicy, stagingPolicy)

	oldRules, newRules, filter := model.ComputeMinimal(prodPolicy, oldPolicy, stagingPolicy)
	oldMinimalPolicy := types.Policy{Rules: oldRules}
	newMinimalPolicy := types.Policy{Rules: newRules}

	var flows iter.Seq[types.Flow]
	if checkSimulate != "" {
		flows = loadFlows(checkSimulate)
	} else {
		since := time.Now().Add(-checkDuration)
		until := time.Now()
		flows, err = tsClient.GetConnections(context.TODO(), since, until, filter)
		if err != nil {
			panic(err)
		}
	}

	oldModel, _ := model.NewModel(oldMinimalPolicy)
	newModel, _ := model.NewModel(newMinimalPolicy)
	diff := model.Diff(oldModel, newModel, flows)

	if len(diff.Flows) == 0 {
		fmt.Fprintln(w, "No verdict differences found")
		return nil
	}
	types.PrintFlowDiffTable(w, oldMinimalPolicy, newMinimalPolicy, diff.Flows)
	return nil
}

func loadFlows(file string) iter.Seq[types.Flow] {
	return func(yield func(types.Flow) bool) {
		f, err := os.Open(file)
		if err != nil {
			panic(err)
		}
		defer f.Close()

		dec := yaml.NewDecoder(f)

		for {
			var flow types.Flow
			err := dec.Decode(&flow)
			if errors.Is(err, io.EOF) {
				return
			}

			if !yield(flow) {
				return
			}
		}
	}
}

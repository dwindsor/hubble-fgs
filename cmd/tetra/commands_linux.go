// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package tetra

import (
	"context"

	"github.com/cilium/tetragon/cmd/tetra/bugtool"
	"github.com/cilium/tetragon/cmd/tetra/cgtracker"
	"github.com/cilium/tetragon/cmd/tetra/debug"
	"github.com/cilium/tetragon/cmd/tetra/loglevel"
	"github.com/cilium/tetragon/cmd/tetra/policyfilter"
	"github.com/cilium/tetragon/cmd/tetra/rthooks"
	"github.com/cilium/tetragon/cmd/tetra/tracingpolicy"
	bugtoolpkg "github.com/cilium/tetragon/pkg/bugtool"
	appModelV1 "github.com/isovalent/ipa/application_model/v1alpha"
	"github.com/spf13/cobra"

	"github.com/isovalent/hubble-fgs/cmd/tetra/policies"

	"github.com/isovalent/hubble-fgs/cmd/tetra/alertrule"
	"github.com/isovalent/hubble-fgs/cmd/tetra/common"
	"github.com/isovalent/hubble-fgs/cmd/tetra/network"

	"github.com/isovalent/hubble-fgs/cmd/tetra/dns"
	"github.com/isovalent/hubble-fgs/cmd/tetra/exec"
	"github.com/isovalent/hubble-fgs/cmd/tetra/file"
	"github.com/isovalent/hubble-fgs/cmd/tetra/mandate"
	"github.com/isovalent/hubble-fgs/cmd/tetra/probe"
	"github.com/isovalent/hubble-fgs/cmd/tetra/sandboxpolicy"
	"github.com/isovalent/hubble-fgs/cmd/tetra/syscallentries"
)

func addCommands(rootCmd *cobra.Command) {
	addBaseCommands(rootCmd)
	rootCmd.AddCommand(bugtool.New().
		WithCommandAction(ifConfig).
		WithGRPCAction(listAlertRules).
		WithGRPCAction(getAppModel).
		WithGRPCAction(listSandboxPolicies).
		WithGRPCAction(listNetworkPolicies).
		Command())
	rootCmd.AddCommand(tracingpolicy.New())
	rootCmd.AddCommand(file.New())
	rootCmd.AddCommand(policyfilter.New())
	rootCmd.AddCommand(rthooks.New())
	rootCmd.AddCommand(probe.New())
	rootCmd.AddCommand(sandboxpolicy.New())
	rootCmd.AddCommand(syscallentries.New())
	rootCmd.AddCommand(exec.New())
	rootCmd.AddCommand(exec.NewMonitor())
	rootCmd.AddCommand(debug.NewDumpAlias())
	rootCmd.AddCommand(loglevel.New())
	rootCmd.AddCommand(cgtracker.New())
	debugCmd := debug.New()
	debugCmd.AddCommand(dns.NewDNSCmd())
	rootCmd.AddCommand(debugCmd)
	rootCmd.AddCommand(mandate.New())
	rootCmd.AddCommand(policies.New())
}

func ifConfig(commander bugtoolpkg.Commander) error {
	return commander.ExecCmd("ifconfig.out", "ifconfig", "-a")
}

func listAlertRules(grpcer bugtoolpkg.GRPCer) error {
	res, err := alertrule.ListAlertRules()
	if err != nil {
		return err
	}
	fname := "alert_rules.json"
	return grpcer.TarAddJson(fname, res)
}

func getAppModel(grpcer bugtoolpkg.GRPCer) error {
	c, err := exec.NewApplicationModelClient(context.Background())
	if err != nil {
		return err
	}
	defer c.Close()

	res, err := c.Client.GetModel(c.Ctx, &appModelV1.GetModelRequest{})
	if err != nil {
		return err
	}

	fname := "app_model.json"
	return grpcer.TarAddJson(fname, res)
}

func listSandboxPolicies(grpcer bugtoolpkg.GRPCer) error {
	res, err := common.ListTetragonPolicies()
	if err != nil {
		return err
	}
	fname := "tracing_policies.json"
	return grpcer.TarAddJson(fname, res)
}

func listNetworkPolicies(grpcer bugtoolpkg.GRPCer) error {
	res, err := network.ListNetworkPolicies()
	if err != nil {
		return err
	}
	fname := "network_policies.json"
	return grpcer.TarAddJson(fname, res)
}

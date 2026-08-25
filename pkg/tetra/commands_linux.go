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
	"github.com/cilium/tetragon/cmd/tetra/policytest"
	"github.com/cilium/tetragon/cmd/tetra/rthooks"
	"github.com/cilium/tetragon/cmd/tetra/tracingpolicy"
	bugtoolpkg "github.com/cilium/tetragon/pkg/bugtool"
	appModelV1 "github.com/isovalent/ipa/application_model/v1alpha"
	"github.com/spf13/cobra"

	sandboxpolicypkg "github.com/isovalent/hubble-fgs/pkg/sandboxpolicy"

	"github.com/isovalent/hubble-fgs/pkg/tetra/policies"

	"github.com/isovalent/hubble-fgs/pkg/tetra/alertrule"
	"github.com/isovalent/hubble-fgs/pkg/tetra/common"
	"github.com/isovalent/hubble-fgs/pkg/tetra/network"

	"github.com/isovalent/hubble-fgs/pkg/tetra/dns"
	"github.com/isovalent/hubble-fgs/pkg/tetra/file"
	"github.com/isovalent/hubble-fgs/pkg/tetra/mandate"
	"github.com/isovalent/hubble-fgs/pkg/tetra/model"
	"github.com/isovalent/hubble-fgs/pkg/tetra/probe"
	"github.com/isovalent/hubble-fgs/pkg/tetra/sandboxpolicy"
	"github.com/isovalent/hubble-fgs/pkg/tetra/syscallentries"

	_ "github.com/isovalent/hubble-fgs/tests/policytests" // so that enterprise tests are registered
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
	rootCmd.AddCommand(model.New())
	rootCmd.AddCommand(model.NewMonitor())
	rootCmd.AddCommand(debug.NewDumpAlias())
	rootCmd.AddCommand(loglevel.New())
	rootCmd.AddCommand(cgtracker.New())
	debugCmd := debug.New()
	debugCmd.AddCommand(dns.NewDNSCmd())
	rootCmd.AddCommand(debugCmd)
	rootCmd.AddCommand(mandate.New())
	rootCmd.AddCommand(policies.New())
	ptCmd := policytest.New()
	// "run" returns errors on test failures, not usage errors, so don't
	// show the flags block on failure.
	for _, c := range ptCmd.Commands() {
		if c.Name() == "run" {
			c.SilenceUsage = true
		}
	}
	rootCmd.AddCommand(ptCmd)
}

func ifConfig(commander bugtoolpkg.Commander) error {
	return commander.ExecCmd("ifconfig.out", "ifconfig", "-a")
}

func listAlertRules(grpcer bugtoolpkg.GRPCer) error {
	res, err := alertrule.ListAlertRules("")
	if err != nil {
		return err
	}
	fname := "alert_rules.json"
	return grpcer.TarAddJson(fname, res)
}

func getAppModel(grpcer bugtoolpkg.GRPCer) error {
	c, err := model.NewApplicationModelClient(context.Background())
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
	res, err := common.ListTetragonPolicies(sandboxpolicypkg.SandboxDomain)
	if err != nil {
		return err
	}
	fname := "sandbox_policies.json"
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

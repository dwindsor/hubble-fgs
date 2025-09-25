//-----------------------------------------------------------------------------
// {C} Copyright 2023 AMD Inc. All rights reserved
//-----------------------------------------------------------------------------

package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/isovalent/hubble-fgs/pkg/dpu/pensando/dpctl/cli/utils"
)

func RegisterDebugNodes(cmd *cobra.Command) {}

// DebugCmd represents the show command
var DebugCmd = &cobra.Command{
	Use:   "debug",
	Short: "debug commands",
	Long:  "debug commands",
}

var DebugCreateCmd = &cobra.Command{
	Use:     "create",
	Short:   "debug create commands",
	Long:    "debug create commands",
	PreRunE: debugCreateSupportCmdPreRunE,
}

var DebugUpdateCmd = &cobra.Command{
	Use:     "update",
	Short:   "debug update commands",
	Long:    "debug update commands",
	PreRunE: debugUpdateSupportCmdPreRunE,
}

var DebugDeleteCmd = &cobra.Command{
	Use:     "delete",
	Short:   "debug delete commands",
	Long:    "debug delete commands",
	PreRunE: debugDeleteSupportCmdPreRunE,
}

func init() {
	RootCmd.AddCommand(DebugCmd)
	RegisterDebugNodes(DebugCmd)

	DebugCmd.AddCommand(DebugCreateCmd)
	DebugCmd.AddCommand(DebugUpdateCmd)
	DebugCmd.AddCommand(DebugDeleteCmd)
}

func debugCreateSupportCmdPreRunE(command *cobra.Command, args []string) error {
	// example to exclude this common debug create CLI for all p4Programs
	p4Program := utils.GetP4ProgramName()
	return fmt.Errorf("Command not supported for P4 program %v", p4Program)
}

func debugUpdateSupportCmdPreRunE(command *cobra.Command, args []string) error {
	// example to exclude this common debug update CLI for specific p4Programs
	p4Program := utils.GetP4ProgramName()
	if p4Program == "flow_offload" ||
		p4Program == "flow_telemetry" ||
		p4Program == "hello_world" ||
		p4Program == "sdn_policy_offload" {
		command.SilenceUsage = true
		return fmt.Errorf("Command not supported for P4 program %v", p4Program)
	}
	return nil
}

func debugDeleteSupportCmdPreRunE(command *cobra.Command, args []string) error {
	// example to exclude this common debug delete CLI for all p4Programs
	p4Program := utils.GetP4ProgramName()
	return fmt.Errorf("Command not supported for P4 program %v", p4Program)
}

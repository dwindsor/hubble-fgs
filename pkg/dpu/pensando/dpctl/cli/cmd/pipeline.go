//-----------------------------------------------------------------------------
// {C} Copyright 2023 AMD Inc. All rights reserved
//-----------------------------------------------------------------------------

package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/isovalent/hubble-fgs/pkg/dpu/pensando/dp"
	"github.com/isovalent/hubble-fgs/pkg/dpu/pensando/dpctl/cli/utils"
	"github.com/isovalent/hubble-fgs/pkg/dpu/pensando/pds"
)

// pipeline specific show command
var PipelineShowCmd = &cobra.Command{
	Use:   "pipeline",
	Short: "pipeline specific show commands",
	Long:  "pipeline specific show commands",
}

var PipelineStatsShowCmd = &cobra.Command{
	Use:   "statistics",
	Short: "show pipeline statistics",
	Long:  "show pipeline statistics",
	RunE:  pipelineStatsShowCmdHandler,
}

var pipelineDropShowCmd = &cobra.Command{
	Use:   "drop",
	Short: "show pipeline drop statistics",
	Long:  "show pipeline drop statistics",
	RunE:  pipelineDropShowCmdHandler,
}

var PipelineInternalShowCmd = &cobra.Command{
	Use:   "internal",
	Short: "internal pipeline information",
	Long:  "internal pipeline information",
}

var PipelineTableShowCmd = &cobra.Command{
	Use:   "table",
	Short: "show pipeline table information",
	Long:  "show pipeline table information",
}

var pipelineTableInfoShowCmd = &cobra.Command{
	Use:     "info",
	Short:   "show P4 pipeline table information",
	Long:    "show P4 pipeline table information",
	PreRunE: pipelineTableInfoShowCmdPreRunE,
	RunE:    pipelineTableInfoShowCmdHandler,
}

var pipelineTableConstantShowCmd = &cobra.Command{
	Use:     "constant",
	Short:   "show P4 pipeline table constant",
	Long:    "show P4 pipeline table constant",
	PreRunE: pipelineTableConstantShowCmdPreRunE,
	RunE:    pipelineTableConstantShowCmdHandler,
}

var PipelineClearCmd = &cobra.Command{
	Use:   "pipeline",
	Short: "pipeline specific clear commands",
	Long:  "pipeline specific clear commands",
}

var PipelineStatsClearCmd = &cobra.Command{
	Use:   "statistics",
	Short: "clear pipeline statistics",
	Long:  "clear pipeline statistics",
	RunE:  pipelineStatsClearCmdHandler,
}

var PipelineInternalClearCmd = &cobra.Command{
	Use:   "internal",
	Short: "internal pipeline information",
	Long:  "internal pipeline information",
}

var PipelineTableClearCmd = &cobra.Command{
	Use:   "table",
	Short: "clear pipeline table information",
	Long:  "clear pipeline table information",
}

var pipelineDropClearCmd = &cobra.Command{
	Use:   "drop",
	Short: "clear pipeline drop statistics",
	Long:  "clear pipeline statistics",
	RunE:  pipelineDropClearCmdHandler,
}

var PipelineDebugCmd = &cobra.Command{
	Use:   "pipeline",
	Short: "pipeline specific debug commands",
	Long:  "pipeline specific debug commands",
}

var PipelineInternalDebugCmd = &cobra.Command{
	Use:   "internal",
	Short: "internal pipeline information",
	Long:  "internal pipeline information",
}

var PipelineTableDebugCmd = &cobra.Command{
	Use:   "table",
	Short: "pipeline internal table debug commands",
	Long:  "pipeline internal table debug commands",
}

func init() {
	ShowCmd.AddCommand(PipelineShowCmd)

	PipelineShowCmd.AddCommand(PipelineInternalShowCmd)
	PipelineShowCmd.AddCommand(PipelineStatsShowCmd)

	PipelineInternalShowCmd.AddCommand(PipelineTableShowCmd)

	PipelineTableShowCmd.AddCommand(pipelineTableInfoShowCmd)
	PipelineTableShowCmd.AddCommand(pipelineTableConstantShowCmd)
	PipelineStatsShowCmd.AddCommand(pipelineDropShowCmd)

	ClearCmd.AddCommand(PipelineClearCmd)

	PipelineClearCmd.AddCommand(PipelineStatsClearCmd)
	PipelineStatsClearCmd.AddCommand(pipelineDropClearCmd)
	PipelineClearCmd.AddCommand(PipelineInternalClearCmd)
	PipelineInternalClearCmd.AddCommand(PipelineTableClearCmd)
}

func pipelineStatsShowCmdHandler(command *cobra.Command, args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("Invalid argument")
	}

	cmdResp, err := HandleSvcReqCommandMsg(
		dp.CommandOp_CMD_OP_PIPELINE_STATS_DUMP, nil)
	if err != nil {
		return fmt.Errorf("Command failed with %v error", err)
	}

	if cmdResp.ApiStatus != pds.ApiStatus_API_STATUS_OK {
		return fmt.Errorf("Command failed with %v error", cmdResp.ApiStatus)
	}
	return nil
}

func pipelineStatsClearCmdHandler(command *cobra.Command, args []string) error {
	if len(args) > 0 {
		err := fmt.Errorf("Invalid argument")
		return err
	}

	cmdResp, err := HandleSvcReqCommandMsg(
		dp.CommandOp_CMD_OP_PIPELINE_STATS_CLEAR, nil)
	if err != nil {
		return fmt.Errorf("Command failed with %v error", err)
	}

	if cmdResp.ApiStatus != pds.ApiStatus_API_STATUS_OK {
		return fmt.Errorf("Command failed with %v error", cmdResp.ApiStatus)
	}
	return nil
}

func pipelineDropShowCmdHandler(command *cobra.Command, args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("Invalid argument")
	}

	cmdResp, err := HandleSvcReqCommandMsg(
		dp.CommandOp_CMD_OP_PIPELINE_DROP_STATS_DUMP, nil)
	if err != nil {
		return fmt.Errorf("Command failed with %v error", err)
	}

	if cmdResp.ApiStatus != pds.ApiStatus_API_STATUS_OK {
		return fmt.Errorf("Command failed with %v error", cmdResp.ApiStatus)
	}
	return nil
}

func pipelineDropClearCmdHandler(command *cobra.Command, args []string) error {
	if len(args) > 0 {
		err := fmt.Errorf("Invalid argument")
		return err
	}

	cmdResp, err := HandleSvcReqCommandMsg(
		dp.CommandOp_CMD_OP_PIPELINE_DROP_STATS_CLEAR, nil)
	if err != nil {
		return fmt.Errorf("Command failed with %v error", err)
	}

	if cmdResp.ApiStatus != pds.ApiStatus_API_STATUS_OK {
		return fmt.Errorf("Command failed with %v error", cmdResp.ApiStatus)
	}
	return nil
}

func pipelineTableInfoShowCmdPreRunE(command *cobra.Command, args []string) error {
	// example to exclude this common pipeline CLI for specific p4_programs
	p4_program := utils.GetP4ProgramName()
	if p4_program == "replace_p4_program_name_here" {
		command.SilenceUsage = true
		return fmt.Errorf("Command not supported for p4-program %v", p4_program)
	}
	return nil
}

func pipelineTableInfoShowCmdHandler(command *cobra.Command, args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("Invalid argument")
	}

	cmdResp, err := HandleSvcReqCommandMsg(
		dp.CommandOp_CMD_OP_PIPELINE_TABLE_INFO_DUMP, nil)
	if err != nil {
		return fmt.Errorf("Command failed with %v error", err)
	}

	if cmdResp.ApiStatus != pds.ApiStatus_API_STATUS_OK {
		return fmt.Errorf("Command failed with %v error", cmdResp.ApiStatus)
	}
	return nil
}

func pipelineTableConstantShowCmdPreRunE(command *cobra.Command, args []string) error {
	// example to exclude this common pipeline CLI for specific p4_programs
	p4_program := utils.GetP4ProgramName()
	if p4_program == "replace_p4_program_name_here" {
		command.SilenceUsage = true
		return fmt.Errorf("Command not supported for p4-program %v", p4_program)
	}
	return nil
}

func pipelineTableConstantShowCmdHandler(command *cobra.Command, args []string) error {
	cmdResp, err := HandleSvcReqCommandMsg(
		dp.CommandOp_CMD_OP_PIPELINE_TABLE_CONSTANT_DUMP, nil)

	if err != nil {
		return fmt.Errorf("Command failed with %v error", err)
	}

	if cmdResp.ApiStatus != pds.ApiStatus_API_STATUS_OK {
		return fmt.Errorf("Command failed with %v error", cmdResp.ApiStatus)
	}
	return nil
}

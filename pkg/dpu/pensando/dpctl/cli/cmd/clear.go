//-----------------------------------------------------------------------------
// {C} Copyright 2023 AMD Inc. All rights reserved
//-----------------------------------------------------------------------------

package cmd

import (
	"github.com/spf13/cobra"
)

func RegisterClearNodes(cmd *cobra.Command) {}

// clearCmd represents the clear command
var ClearCmd = &cobra.Command{
	Use:   "clear",
	Short: "clear commands",
	Long:  "clear commands",
}

func init() {
	RootCmd.AddCommand(ClearCmd)
	RegisterClearNodes(ClearCmd)
}

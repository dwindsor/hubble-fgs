//-----------------------------------------------------------------------------
// {C} Copyright 2023 AMD Inc. All rights reserved
//-----------------------------------------------------------------------------

package cmd

import (
	"github.com/spf13/cobra"
)

func RegisterShowNodes(pcmd *cobra.Command) {}

// ShowCmd represents the show command
var ShowCmd = &cobra.Command{
	Use:   "show",
	Short: "show commands",
	Long:  "show commands",
}

func init() {
	RootCmd.AddCommand(ShowCmd)
	RegisterShowNodes(ShowCmd)
}

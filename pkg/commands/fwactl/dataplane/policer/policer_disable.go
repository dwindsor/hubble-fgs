// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package policer

import (
	"fmt"

	"github.com/spf13/cobra"

	dpcmd "github.com/isovalent/hubble-fgs/pkg/dpu/pensando/dp"
	"github.com/isovalent/hubble-fgs/pkg/dpu/pensando/dpctl/cli/cmd"
	"github.com/isovalent/hubble-fgs/pkg/dpu/pensando/pds"
)

// policerEnableCmd represents the policer command
var policerDisableCmd = &cobra.Command{
	Use:          "disable",
	SilenceUsage: true,
	Short:        "Dataplane disable policer",
	Long:         `Runtime disable for the policer in the P4 ingress pipeline`,
	RunE: func(command *cobra.Command, args []string) error {
		if len(args) > 0 {
			return fmt.Errorf("invalid argument")
		}
		if command != nil {
			command.SilenceUsage = true
		}

		cmdResp, err := cmd.HandleSvcReqCommandMsg(dpcmd.CommandOp_CMD_OP_HS_POLICER_OFF, nil)
		if err != nil {
			return fmt.Errorf("command failed with error %v", err)
		}
		if cmdResp.ApiStatus != pds.ApiStatus_API_STATUS_OK {
			return fmt.Errorf("command failed with error %v", cmdResp.ApiStatus)
		}
		return nil
	},
}

func init() {
	polCmd.AddCommand(policerDisableCmd)
}

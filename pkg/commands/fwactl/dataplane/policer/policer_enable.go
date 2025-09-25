package policer

import (
	"fmt"

	"github.com/spf13/cobra"

	dpcmd "github.com/isovalent/hubble-fgs/pkg/dpu/pensando/dp"
	"github.com/isovalent/hubble-fgs/pkg/dpu/pensando/dpctl/cli/cmd"
	"github.com/isovalent/hubble-fgs/pkg/dpu/pensando/pds"
)

// policerEnableCmd represents the policer command
var policerEnableCmd = &cobra.Command{
	Use:          "enable",
	SilenceUsage: true,
	Short:        "Dataplane enable policer",
	Long:         `Runtime enable for the policer in the P4 ingress pipeline`,
	RunE: func(command *cobra.Command, args []string) error {
		if len(args) > 0 {
			return fmt.Errorf("invalid argument")
		}
		if command != nil {
			command.SilenceUsage = true
		}

		cmdResp, err := cmd.HandleSvcReqCommandMsg(dpcmd.CommandOp_CMD_OP_HS_POLICER_ON, nil)
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
	polCmd.AddCommand(policerEnableCmd)
}

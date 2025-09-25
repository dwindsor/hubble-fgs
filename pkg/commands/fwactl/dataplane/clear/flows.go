package clear

import (
	"fmt"

	"github.com/spf13/cobra"

	dpcmd "github.com/isovalent/hubble-fgs/pkg/dpu/pensando/dp"
	"github.com/isovalent/hubble-fgs/pkg/dpu/pensando/dpctl/cli/cmd"
	"github.com/isovalent/hubble-fgs/pkg/dpu/pensando/pds"
)

// flowsCmd represents clearing the flows
var flowsCmd = &cobra.Command{
	Use:          "flows",
	SilenceUsage: true,
	Short:        "Dataplane clear flow information",
	Long:         `Clear statistics on packet flows through the dataplane.`,
	RunE: func(_ *cobra.Command, _ []string) error {
		cmdResp, err := cmd.HandleSvcReqCommandMsg(dpcmd.CommandOp_CMD_OP_FLOW_CLEAR, nil)
		if err != nil {
			return fmt.Errorf("command failed with error %v", err)
		}
		if cmdResp.ApiStatus != pds.ApiStatus_API_STATUS_OK {
			return fmt.Errorf("command failed with error %v", cmdResp.ApiStatus)
		}
		fmt.Printf("Clearing flows succeeded\n")
		return nil
	},
}

func init() {
	clearCmd.AddCommand(flowsCmd)
}

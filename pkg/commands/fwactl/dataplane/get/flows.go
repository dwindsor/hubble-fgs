package get

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/isovalent/hubble-fgs/pkg/commands/fwactl"
	dpcmd "github.com/isovalent/hubble-fgs/pkg/dpu/pensando/dp"
	"github.com/isovalent/hubble-fgs/pkg/dpu/pensando/dpctl/cli/cmd"
	"github.com/isovalent/hubble-fgs/pkg/dpu/pensando/dpctl/cli/utils"
	"github.com/isovalent/hubble-fgs/pkg/dpu/pensando/hs-dp-app/dp"
	"github.com/isovalent/hubble-fgs/pkg/dpu/pensando/pds"
)

var (
	flowDst     string
	flowSrc     string
	flowSrcPort uint32
	flowDstPort uint32
	flowIPProto uint32
)

// flowsCmd represents the flows command
var flowsCmd = &cobra.Command{
	Use:          "flows",
	SilenceUsage: true,
	Short:        "Dataplane get flow information",
	Long:         `Returns statistics on packet flows through the dataplane`,
	RunE: func(command *cobra.Command, args []string) error {
		if len(args) > 0 {
			return fmt.Errorf("invalid argument")
		}

		var srcIP *pds.IPAddress
		var dstIP *pds.IPAddress
		var req *dp.FlowGetRequest

		summaryOutput := command != nil && command.Flags().Changed("summary")
		srcIP = utils.IPAddrStrToPDSIPAddr(flowSrc)
		dstIP = utils.IPAddrStrToPDSIPAddr(flowDst)
		flowFilter := &dp.FlowFilter{
			SrcIP:   srcIP,
			DstIP:   dstIP,
			SrcPort: flowSrcPort,
			DstPort: flowDstPort,
			IPProto: flowIPProto,
		}
		req = &dp.FlowGetRequest{
			Filter:  flowFilter,
			Summary: summaryOutput,
		}

		cmdResp, err := cmd.HandleSvcReqCommandMsg(dpcmd.CommandOp_CMD_OP_FLOW_DUMP, req)
		if err != nil {
			return fmt.Errorf("command failed with error %v", err)
		}
		if cmdResp.ApiStatus != pds.ApiStatus_API_STATUS_OK {
			return fmt.Errorf("command failed with error %v", cmdResp.ApiStatus)
		}

		fmt.Println(cmdResp, fwactl.JSON)
		return nil
	},
}

func init() {
	flowsCmd.Flags().Uint32Var(&flowSrcPort, "srcport", 0, "Specify flow source port")
	flowsCmd.Flags().Uint32Var(&flowDstPort, "dstport", 0, "Specify flow destination port")
	flowsCmd.Flags().Uint32Var(&flowIPProto, "ipproto", 0, "Specify flow IP proto")
	flowsCmd.Flags().StringVar(&flowSrc, "src-ip", "0.0.0.0", "Specify source IP")
	flowsCmd.Flags().StringVar(&flowDst, "dst-ip", "0.0.0.0", "Specify dsetination IP")
	flowsCmd.Flags().Bool("summary", false, "Only display the number of flows")
	getCmd.AddCommand(flowsCmd)
}

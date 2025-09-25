package get

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/isovalent/hubble-fgs/pkg/commands/fwactl/dataplane"
	"github.com/isovalent/hubble-fgs/pkg/dpu/pensando/pds"
)

var portsCmd = &cobra.Command{
	Use:          "portstats",
	SilenceUsage: true,
	Short:        "Dataplane get port statistics for DPU",
	Long:         `Returns port statistics for DPU`,
	RunE: func(_ *cobra.Command, _ []string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		//PDS GRPC connection
		if err := dataplane.InitGrpcPdsConnection(); err != nil {
			return fmt.Errorf("failed to initialize gRPC connection: %v", err)
		}
		defer dataplane.GrpcConn.Close()

		client := pds.NewPortSvcClient(dataplane.GrpcConn)

		request := &pds.PortGetRequest{}
		resp, err := client.PortGet(ctx, request)
		if err != nil {
			return fmt.Errorf("failed to get ports: %v", err)
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 4, ' ', 0)

		fmt.Fprintln(w, "-------------------------------------")
		fmt.Fprintln(w, "PortId\tField\tCount")
		fmt.Fprintln(w, "-------------------------------------")

		for _, port := range resp.Response {
			portName := fmt.Sprintf("Eth1/%d", port.Spec.PortNumber)

			//MacStats
			if len(port.Stats.MacStats) > 0 {
				for i, stat := range port.Stats.MacStats {
					statName := pds.MacStatsType_name[int32(stat.Type)]
					if i == 0 {
						fmt.Fprintf(w, "%s\t%s\t%d\n", portName, statName, stat.Count)
					} else {
						fmt.Fprintf(w, "\t%s\t%d\n", statName, stat.Count)
					}
				}
			}

			//MgmtMacStats
			if len(port.Stats.MgmtMacStats) > 0 {
				for i, stat := range port.Stats.MgmtMacStats {
					statName := pds.MgmtMacStatsType_name[int32(stat.Type)]
					if i == 0 {
						fmt.Fprintf(w, "%s\t%s\t%d\n", portName, statName, stat.Count)
					} else {
						fmt.Fprintf(w, "\t%s\t%d\n", statName, stat.Count)
					}
				}
			}
		}

		w.Flush()
		return nil
	},
}

func init() {
	getCmd.AddCommand(portsCmd)
}

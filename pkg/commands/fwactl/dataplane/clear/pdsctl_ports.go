package clear

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/isovalent/hubble-fgs/pkg/commands/fwactl/dataplane"
	"github.com/isovalent/hubble-fgs/pkg/dpu/pensando/pds"
)

var (
	portId string
)

var portsCmd = &cobra.Command{
	Use:          "portstats",
	SilenceUsage: true,
	Short:        "Dataplane clear port statistics for DPU",
	Long:         `Clears port statistics for DPU`,
	RunE: func(_ *cobra.Command, _ []string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		//PDS GRPC connection
		if err := dataplane.InitGrpcPdsConnection(); err != nil {
			return fmt.Errorf("failed to initialize gRPC connection: %v", err)
		}
		defer dataplane.GrpcConn.Close()

		client := pds.NewPortSvcClient(dataplane.GrpcConn)

		var idMsg *pds.Id
		if portId != "" {
			idMsg = &pds.Id{Id: []byte(portId)}
		} else {
			idMsg = &pds.Id{Id: []byte("")}
		}

		_, err := client.PortStatsReset(ctx, idMsg)
		if err != nil {
			return fmt.Errorf("failed to get ports: %v", err)
		}

		fmt.Printf("Successfully reset port statistics\n")

		return nil

	},
}

func init() {
	portsCmd.Flags().StringVar(&portId, "port", "", "Port ID to reset statistics(empty for all ports)")
	clearCmd.AddCommand(portsCmd)
}

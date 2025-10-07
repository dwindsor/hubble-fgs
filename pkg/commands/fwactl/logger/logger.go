package logger

import (
	"context"

	"github.com/spf13/cobra"

	"github.com/isovalent/hubble-fgs/pkg/commands/fwactl"
	"github.com/isovalent/hubble-fgs/pkg/dpu"
)

var (
	DpuAgent *dpu.DPUAgent
)

// LoggerCmd represents the logger command
var LoggerCmd = &cobra.Command{
	Use:          "logger",
	SilenceUsage: true,
	Aliases:      []string{"log"},
	Short:        "Manage logger integration",
	Long:         `Used to manage configuration and send commands to logger.`,
	PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		DpuAgent = dpu.NewDPUAgent("")
		err := DpuAgent.Config(ctx, fwactl.CONFIG, fwactl.DP_SOCKET_PATH)
		if err != nil {
			return err
		}
		return nil
	},
}

func init() {
	fwactl.RootCmd.AddCommand(LoggerCmd)
}

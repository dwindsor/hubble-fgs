// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package loadconfig

import (
	"context"
	"errors"

	"github.com/spf13/cobra"

	"github.com/isovalent/hubble-fgs/pkg/commands/fwactl"
	"github.com/isovalent/hubble-fgs/pkg/dpu"
)

// loadconfigCmd represents the flows command
var loadconfigCmd = &cobra.Command{
	Use:          "loadconfig [filepath]",
	SilenceUsage: true,
	Short:        "Load configuration file",
	Long: `Provides the path to a configuration file that will be
copied to a temporary directory and used while executing
all other CLI commands.  If the configuration file
already exists, it will be updated with new values.`,
	Annotations: map[string]string{"command": "loadconfig"},
	RunE: func(_ *cobra.Command, args []string) error {
		// Checking for filepath
		if len(args) < 1 {
			return errors.New("missing filepath")
		}

		// Configuring fwa
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		DpuAgent := dpu.NewDPUAgent("")
		err := DpuAgent.Config(ctx, args[0], fwactl.DP_SOCKET_PATH, true, true)
		if err != nil {
			return err
		}
		err = DpuAgent.Cfg.SavePath(fwactl.CONFIG)
		if err != nil {
			return err
		}
		return nil
	},
}

func init() {
	fwactl.RootCmd.AddCommand(loadconfigCmd)
}

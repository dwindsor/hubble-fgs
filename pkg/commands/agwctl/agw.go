// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package agwctl

import (
	"context"
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/isovalent/hubble-fgs/pkg/ipc"
)

var loadSyslogCmd = &cobra.Command{
	Use:          "load_syslog_cfg <file>",
	SilenceUsage: true,
	Short:        "Load syslog export configuration from file and push to DPU agents",
	Long: `Load syslog export configuration from file and push to DPU agents.  This replaces
any existing syslog export configuration.  It is in the format:
{
  "123": {
    "id": "123",
    "name": "string",
    "description": "string",
    "type": "string",
    "config": {
      "host": "string",
      "port": "string",
      "mode": "string",
      "tls": "bool"
    },
    "secrets": {
	  "token": "string",
      "ca": "string",
      "cert": "string",
      "key": "string",
      "keyPassword": "string"
    }
  }
}`,
	RunE: func(_ *cobra.Command, args []string) error {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		if len(args) < 1 {
			return errors.New("missing file")
		}
		ret, err := ipc.SendCmd(ctx, CLI_SOCK, CMD_LOAD_SYSLOG_CFG, ipc.MessageData{Args: []string{args[0]}})
		if err != nil {
			return err
		}
		ipc.PrintResponse(ret, JSON)
		return nil
	},
}

var showSyslogCmd = &cobra.Command{
	Use:          "show_syslog_cfg",
	SilenceUsage: true,
	Short:        "Show syslog export configuration for DPU agents",
	Long:         `Show syslog export configuration for DPU agents.`,
	RunE: func(_ *cobra.Command, _ []string) error {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		ret, err := ipc.SendCmd(ctx, CLI_SOCK, CMD_SHOW_SYSLOG_CFG, ipc.MessageData{})
		if err != nil {
			return err
		}
		ipc.PrintResponse(ret, JSON)
		return nil
	},
}

// load policy command
var loadPolicyCmd = &cobra.Command{
	Use:          "load_policy <file>",
	SilenceUsage: true,
	Short:        "Deprecated, use 'agwctl policies add' instead",
	Long:         `Deprecated, use 'agwctl policies add' instead.`,
	Deprecated:   "Deprecated, use 'agwctl policies add' instead",
	RunE: func(_ *cobra.Command, args []string) error {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		if len(args) < 1 {
			return errors.New("missing file")
		}
		ret, err := ipc.SendCmd(ctx, CLI_SOCK, CMD_LOAD_POLICY, ipc.MessageData{Args: []string{args[0]}})
		if err != nil {
			return err
		}
		ipc.PrintResponse(ret, JSON)
		return nil
	},
}

var showPolicyCmd = &cobra.Command{
	Use:          "show_policy",
	SilenceUsage: true,
	Short:        "Deprecated, use 'agwctl policies show' instead",
	Long:         "Deprecated, use 'agwctl policies show' instead.",
	Deprecated:   "Deprecated, use 'agwctl policies show' instead",
	RunE: func(cmd *cobra.Command, _ []string) error {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		nameFilter, _ := cmd.Flags().GetString("name")

		ret, err := ipc.SendCmd(ctx, CLI_SOCK, CMD_SHOW_POLICY, ipc.MessageData{Flags: map[string]string{"name": nameFilter}})
		if err != nil {
			return err
		}
		ipc.PrintResponse(ret, JSON)
		return nil
	},
}

var healthCmd = &cobra.Command{
	Use:          "health",
	SilenceUsage: true,
	Short:        "Check agent health",
	Long:         "Check agent health",
	RunE: func(_ *cobra.Command, _ []string) error {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		ret, err := ipc.SendCmd(ctx, CLI_SOCK, CMD_HEALTH, ipc.MessageData{})
		if err != nil {
			return err
		}
		ipc.PrintResponse(ret, JSON)
		return nil
	},
}

var showStatusCmd = &cobra.Command{
	Use:          "show_status",
	SilenceUsage: true,
	Short:        "Show agent operational status",
	Long:         "Show agent operational status",
	RunE: func(_ *cobra.Command, _ []string) error {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		ret, err := ipc.SendCmd(ctx, CLI_SOCK, CMD_SHOW_STATUS, ipc.MessageData{})
		if err != nil {
			return err
		}
		ipc.PrintResponse(ret, JSON)
		return nil
	},
}

var showDpuCmd = &cobra.Command{
	Use:          "show_dpu",
	SilenceUsage: true,
	Short:        "Show DPU status",
	Long:         "Show DPU status",
	RunE: func(_ *cobra.Command, _ []string) error {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		data := ipc.MessageData{
			Flags: map[string]string{
				"json": fmt.Sprintf("%t", JSON),
			},
		}

		ret, err := ipc.SendCmd(ctx, CLI_SOCK, CMD_SHOW_DPU, data)
		if err != nil {
			return err
		}
		ipc.PrintResponse(ret, JSON)
		return nil
	},
}

var showVrfCmd = &cobra.Command{
	Use:          "show_vrf",
	SilenceUsage: true,
	Short:        "Show VRF status",
	Long:         "Show VRF status",
	RunE: func(_ *cobra.Command, _ []string) error {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		ret, err := ipc.SendCmd(ctx, CLI_SOCK, CMD_SHOW_VRF, ipc.MessageData{})
		if err != nil {
			return err
		}
		ipc.PrintResponse(ret, JSON)
		return nil
	},
}

var showLogCmd = &cobra.Command{
	Use:          "show_log",
	SilenceUsage: true,
	Short:        "Show log",
	Long:         "Show log",
	RunE: func(_ *cobra.Command, _ []string) error {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		ret, err := ipc.SendCmd(ctx, CLI_SOCK, CMD_SHOW_LOG, ipc.MessageData{})
		if err != nil {
			return err
		}
		ipc.PrintResponse(ret, JSON)
		return nil
	},
}

var delTokensCmd = &cobra.Command{
	Use:          "del_tokens",
	SilenceUsage: true,
	Short:        "Delete access and refresh tokens",
	Long:         "Delete access and refresh tokens",
	RunE: func(_ *cobra.Command, _ []string) error {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		ret, err := ipc.SendCmd(ctx, CLI_SOCK, CMD_DEL_TOKENS, ipc.MessageData{})
		if err != nil {
			return err
		}
		ipc.PrintResponse(ret, JSON)
		return nil
	},
}

var showTokensCmd = &cobra.Command{
	Use:          "show_tokens",
	SilenceUsage: true,
	Short:        "Show tokens",
	Long:         "Show tokens",
	RunE: func(_ *cobra.Command, _ []string) error {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		ret, err := ipc.SendCmd(ctx, CLI_SOCK, CMD_SHOW_TOKENS, ipc.MessageData{})
		if err != nil {
			return err
		}
		ipc.PrintResponse(ret, JSON)
		return nil
	},
}

var showTechCmd = &cobra.Command{
	Use:          "show_tech",
	SilenceUsage: true,
	Short:        "Show tech",
	Long:         "Show tech",
	RunE: func(_ *cobra.Command, _ []string) error {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		ret, err := ipc.SendCmd(ctx, CLI_SOCK, CMD_SHOW_TECH, ipc.MessageData{})
		if err != nil {
			return err
		}
		ipc.PrintResponse(ret, JSON)
		return nil
	},
}

var tacPacCmd = &cobra.Command{
	Use:          "tac_pac",
	SilenceUsage: true,
	Short:        "TAC Pac",
	Long:         "TAC Pac",
	RunE: func(_ *cobra.Command, _ []string) error {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		ret, err := ipc.SendCmd(ctx, CLI_SOCK, CMD_TAC_PAC, ipc.MessageData{})
		if err != nil {
			return err
		}
		ipc.PrintResponse(ret, JSON)
		return nil
	},
}

var pingFwaCmd = &cobra.Command{
	Use:          "ping_fwa <DPU IP>",
	SilenceUsage: true,
	Short:        "ping FWA",
	Long:         "ping FWA",
	Deprecated:   "Deprecated, no longer applicable to hubble agw/fwa.",
	RunE: func(_ *cobra.Command, args []string) error {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		if len(args) < 1 {
			return errors.New("missing DPU")
		}

		ret, err := ipc.SendCmd(ctx, CLI_SOCK, CMD_PING_FWA, ipc.MessageData{Args: []string{args[0]}})
		if err != nil {
			return err
		}
		ipc.PrintResponse(ret, JSON)
		return nil
	},
}

var restartFwaCmd = &cobra.Command{
	Use:          "restart_fwa <DPU IP>",
	SilenceUsage: true,
	Short:        "restart FWA",
	Long:         "restart FWA",
	RunE: func(_ *cobra.Command, args []string) error {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		if len(args) < 1 {
			return errors.New("missing DPU")
		}

		ret, err := ipc.SendCmd(ctx, CLI_SOCK, CMD_RESTART_FWA, ipc.MessageData{Args: []string{args[0]}})
		if err != nil {
			return err
		}
		ipc.PrintResponse(ret, JSON)
		return nil
	},
}

var showHaCmd = &cobra.Command{
	Use:          "show_ha",
	SilenceUsage: true,
	Short:        "Show high availability",
	Long:         "Show high availability",
	RunE: func(_ *cobra.Command, _ []string) error {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		ret, err := ipc.SendCmd(ctx, CLI_SOCK, CMD_SHOW_HA, ipc.MessageData{})
		if err != nil {
			return err
		}
		ipc.PrintResponse(ret, JSON)
		return nil
	},
}

var showAdjCmd = &cobra.Command{
	Use:          "show_adj",
	SilenceUsage: true,
	Short:        "Show HA adjacencies",
	Long:         "Show HA adjacencies",
	RunE: func(_ *cobra.Command, _ []string) error {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		ret, err := ipc.SendCmd(ctx, CLI_SOCK, CMD_SHOW_ADJ, ipc.MessageData{})
		if err != nil {
			return err
		}
		ipc.PrintResponse(ret, JSON)
		return nil
	},
}

var showMbrCmd = &cobra.Command{
	Use:          "show_mbr",
	SilenceUsage: true,
	Short:        "Show HA members",
	Long:         "Show HA members",
	RunE: func(_ *cobra.Command, _ []string) error {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		ret, err := ipc.SendCmd(ctx, CLI_SOCK, CMD_SHOW_MBR, ipc.MessageData{})
		if err != nil {
			return err
		}
		ipc.PrintResponse(ret, JSON)
		return nil
	},
}

var showGidCmd = &cobra.Command{
	Use:          "show_gid",
	SilenceUsage: true,
	Short:        "Show global IDs",
	Long:         "Show global IDs",
	RunE: func(_ *cobra.Command, _ []string) error {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		ret, err := ipc.SendCmd(ctx, CLI_SOCK, CMD_SHOW_GID, ipc.MessageData{})
		if err != nil {
			return err
		}
		ipc.PrintResponse(ret, JSON)
		return nil
	},
}

func init() {
	RootCmd.AddCommand(loadPolicyCmd)
	RootCmd.AddCommand(showPolicyCmd)
	showPolicyCmd.Flags().String("name", "", "Filter policies by name (supports wildcards like *vrf*)")
	RootCmd.AddCommand(healthCmd)
	RootCmd.AddCommand(showStatusCmd)
	RootCmd.AddCommand(showDpuCmd)
	RootCmd.AddCommand(showVrfCmd)
	RootCmd.AddCommand(showLogCmd)
	RootCmd.AddCommand(delTokensCmd)
	RootCmd.AddCommand(showTokensCmd)
	RootCmd.AddCommand(showTechCmd)
	RootCmd.AddCommand(tacPacCmd)
	RootCmd.AddCommand(pingFwaCmd)
	RootCmd.AddCommand(restartFwaCmd)
	RootCmd.AddCommand(loadSyslogCmd)
	RootCmd.AddCommand(showSyslogCmd)
	RootCmd.AddCommand(showHaCmd)
	RootCmd.AddCommand(showAdjCmd)
	RootCmd.AddCommand(showMbrCmd)
	RootCmd.AddCommand(showGidCmd)
}

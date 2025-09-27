package commands

import (
	"context"
	"errors"

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
		ret, err := ipc.SendCmd(ctx, CLI_SOCK, CMD_LOAD_SYSLOG_CFG, args[0])
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

		ret, err := ipc.SendCmd(ctx, CLI_SOCK, CMD_SHOW_SYSLOG_CFG, "")
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
	Short:        "Load policy from file and push to DPU agents",
	Long:         `Load policy from file and push to DPU agents.`,
	RunE: func(_ *cobra.Command, args []string) error {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		if len(args) < 1 {
			return errors.New("missing file")
		}
		ret, err := ipc.SendCmd(ctx, CLI_SOCK, CMD_LOAD_POLICY, args[0])
		if err != nil {
			return err
		}
		ipc.PrintResponse(ret, JSON)
		return nil
	},
}

var showPolicyCmd = &cobra.Command{
	Use:          "show_policy [pretty-print]",
	SilenceUsage: true,
	Short:        "Show policy from Hypershield controller",
	Long:         "Show policy from Hypershield controller",
	RunE: func(_ *cobra.Command, args []string) error {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		prettyPrint := ""
		if len(args) > 0 && args[0] == "pretty-print" {
			prettyPrint = args[0]
		}
		ret, err := ipc.SendCmd(ctx, CLI_SOCK, CMD_SHOW_POLICY, prettyPrint)
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

		ret, err := ipc.SendCmd(ctx, CLI_SOCK, CMD_HEALTH, "")
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

		ret, err := ipc.SendCmd(ctx, CLI_SOCK, CMD_SHOW_STATUS, "")
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

		ret, err := ipc.SendCmd(ctx, CLI_SOCK, CMD_SHOW_DPU, "")
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

		ret, err := ipc.SendCmd(ctx, CLI_SOCK, CMD_SHOW_VRF, "")
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

		ret, err := ipc.SendCmd(ctx, CLI_SOCK, CMD_SHOW_LOG, "")
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

		ret, err := ipc.SendCmd(ctx, CLI_SOCK, CMD_DEL_TOKENS, "")
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

		ret, err := ipc.SendCmd(ctx, CLI_SOCK, CMD_SHOW_TOKENS, "")
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

		ret, err := ipc.SendCmd(ctx, CLI_SOCK, CMD_SHOW_TECH, "")
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

		ret, err := ipc.SendCmd(ctx, CLI_SOCK, CMD_TAC_PAC, "")
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
	RunE: func(_ *cobra.Command, args []string) error {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		if len(args) < 1 {
			return errors.New("missing DPU")
		}

		ret, err := ipc.SendCmd(ctx, CLI_SOCK, CMD_PING_FWA, args[0])
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

		ret, err := ipc.SendCmd(ctx, CLI_SOCK, CMD_RESTART_FWA, args[0])
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

		ret, err := ipc.SendCmd(ctx, CLI_SOCK, CMD_SHOW_HA, "")
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

		ret, err := ipc.SendCmd(ctx, CLI_SOCK, CMD_SHOW_ADJ, "")
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

		ret, err := ipc.SendCmd(ctx, CLI_SOCK, CMD_SHOW_MBR, "")
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

		ret, err := ipc.SendCmd(ctx, CLI_SOCK, CMD_SHOW_GID, "")
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

package controller

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path"
	"runtime/pprof"
	"time"

	"github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/hive/script"
	"github.com/cilium/hive/shell"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	"github.com/isovalent/hubble-fgs/cmd/netpol/timescape"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

var controllerCell = cell.Module(
	"policy-controller",
	"Network policy validation controller",

	cell.Provide(timescape.NewClient),
	cell.Config(Config{}),

	cell.Provide(
		NewPolicyTable,
		shellCommands,

		newManager,
	),

	cell.ProvidePrivate(
		newPolicyPatchFunc,
		func(tsClient *timescape.Client) timescapeGetConnections {
			return tsClient
		},
	),

	cell.Invoke(
		// Populates Table[*Policy] from the SmartSwitchNetworkPolicy objects
		registerPopulatePolicyTable,

		// Reconciles staging policies in Table[*Policy] and write back result
		// as annotation.
		registerPolicyReconciler,
	),
)

func shellCommands(db *statedb.DB, policies statedb.RWTable[*Policy]) hive.ScriptCmdsOut {
	return hive.NewScriptCmds(map[string]script.Cmd{
		"revalidate": script.Command(
			script.CmdUsage{
				Summary: "Revalidate all staging policies",
			},
			func(s *script.State, args ...string) (script.WaitFunc, error) {
				wtxn := db.WriteTxn(policies)
				for p := range policies.All(wtxn) {
					if p.Target != "" {
						p = p.Clone()
						p.Status = reconciler.StatusPending()
						p.ReconciledGeneration = 0
						s.Logf("- %s", p.Name)
						policies.Insert(wtxn, p)
					}
				}
				wtxn.Commit()
				return nil, nil
			},
		),
	})
}

func newControllerHive(cells ...cell.Cell) *hive.Hive {
	extra := cell.Group(cells...)
	return hive.NewWithOptions(
		hive.Options{
			ModuleDecorators: cell.ModuleDecorators{
				// Provide a cell.Health scoped to the module name
				func(fmid cell.FullModuleID, h cell.Health) cell.Health {
					return h.NewScope(fmid.String())
				},
			},
			ModulePrivateProviders: cell.ModulePrivateProviders{
				// Provide a job.Group scoped to the module.
				func(reg job.Registry, h cell.Health, l *slog.Logger, lc cell.Lifecycle, mid cell.ModuleID) job.Group {
					return reg.NewGroup(h, lc,
						job.WithLogger(l),
						job.WithPprofLabels(pprof.Labels("cell", string(mid))))
				},
			},
			StartTimeout: 5 * time.Second,
			StopTimeout:  5 * time.Second,
		},

		cell.Provide(
			cell.NewSimpleHealth,
			func(sh *cell.SimpleHealth) hive.ScriptCmdOut {
				return hive.NewScriptCmd("health", cell.SimpleHealthCmd(sh))
			},
		),

		cell.Config(timescape.Config{}),

		shell.ServerCell(shellSockPath),

		statedb.Cell,
		job.Cell,

		extra,
	)
}

var controllerHive = newControllerHive(controllerCell)

type Config struct {
	KubeConfigPath           string
	ConfidenceMinConnections int
	Duration                 time.Duration
}

func (c Config) Flags(fs *pflag.FlagSet) {
	fs.String("kube-config-path", path.Join(os.Getenv("HOME"), ".kube", "config"), "Path to kubeconfig")
	fs.Duration("duration", 10*time.Minute, "How long in the past to go to look for matching connections")
	fs.Int("confidence-min-connections", 100, "Minimum number of connections needed to calculate confidence")
	fs.MarkHidden("confidence-min-connections")
}

const shellSockPath = "/tmp/netpol.sock"

var Command = func() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "controller",
		Short: "Run the network policy controller",
		Long: `Runs the network policy controller.

The controller pulls SmartSwitchNetworkPolicies and validates those marked
with 'smartswitchnetworkpolicy.isovalent.com/staging' annotation. The
validation results are written under the 'smartswitchnetworkpolicy.isovalent.com/validation'
annotation.

To validate the controller pulls connection logs from Timescape and finds
which connections have different verdict with the staging policy. The duration
can be set using '--duration' flag.

The Timescape server address can be set with '--timescape-address'. By default
the insecure transport is used. For mTLS set the '--timescape-cert', '--timescape-key'
and '--timescape-ca' flags.

To inspect the internal state of the controller run the 'controller shell'
command:

  $ netpol controller shell
  netpol> db/show policies
  ...
`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return controllerHive.Run(slog.Default())
		},
	}
	cmd.AddCommand(shell.ShellCmd(shellSockPath, "netpol> ", shellGreeting))
	controllerHive.RegisterFlags(cmd.Flags())
	return cmd
}()

func shellGreeting(w io.Writer) {
	fmt.Fprint(w, `
Welcome to the netpol controller shell!

To revalidate all staging policies: revalidate
To view policies: db/show policies
To check health: health

`)
}

package controller

import (
	"context"
	"fmt"
	"iter"
	"maps"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/script"
	"github.com/cilium/hive/script/scripttest"
	"github.com/isovalent/hubble-fgs/cmd/netpol/model"
	"github.com/isovalent/hubble-fgs/cmd/netpol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeGetConnections struct {
	flows []types.Flow
}

func (f *fakeGetConnections) load(fileName string) error {
	file, err := os.Open(fileName)
	if err != nil {
		return err
	}
	defer file.Close()
	f.flows, err = types.ParseFlowTable(fileName, file)
	return err
}

// GetConnections implements timescapeGetConnections.
func (f *fakeGetConnections) GetConnections(ctx context.Context, since time.Time, until time.Time, filter *model.Filter) (iter.Seq[types.Flow], error) {
	return slices.Values(f.flows), nil
}

var _ timescapeGetConnections = &fakeGetConnections{}

type fakePolicyPatcher struct {
	namespace, name string
	patch           []byte
}

func (f *fakePolicyPatcher) patchFunc(ctx context.Context, namespace, name string, patch []byte) (code int, err error) {
	f.namespace = namespace
	f.name = name
	f.patch = patch
	return 0, nil
}

// testCell is stripped down version of [controllerCell] with faked out
// patching and connection retrieval. The policy table is populated
// manually with db/insert.
func testCell(fgc *fakeGetConnections, fpp *fakePolicyPatcher) cell.Cell {
	return cell.Module(
		"test",
		"Policy controller test module",

		cell.Provide(
			func() Config {
				return Config{
					KubeConfigPath:           "",
					Duration:                 0,
					ConfidenceMinConnections: 5,
				}
			},
		),

		cell.Provide(
			NewPolicyTable,
			shellCommands,
		),

		cell.ProvidePrivate(
			func() policyPatchFunc {
				return fpp.patchFunc
			},
			func() timescapeGetConnections {
				return fgc
			},
		),
		cell.Invoke(
			// Reconciles staging policies in Table[*Policy] and write back result
			// as annotation.
			registerPolicyReconciler,
		),
	)
}

func TestScript(t *testing.T) {
	scripttest.Test(
		t,
		t.Context(),
		func(tb testing.TB, args []string) *script.Engine {
			log := hivetest.Logger(tb)
			e := script.NewEngine()

			fgc := &fakeGetConnections{}

			e.Cmds["load-flows"] = script.Command(
				script.CmdUsage{},
				func(s *script.State, args ...string) (script.WaitFunc, error) {
					if len(args) != 1 {
						return nil, fmt.Errorf("expected flow table filename")
					}
					return nil, fgc.load(s.Path(args[0]))
				})

			fpp := &fakePolicyPatcher{}
			e.Cmds["print-patch"] = script.Command(
				script.CmdUsage{},
				func(s *script.State, args ...string) (script.WaitFunc, error) {
					return func(s *script.State) (stdout string, stderr string, err error) {
						stdout = fmt.Sprintf("%s/%s\n%s\n", fpp.namespace, fpp.name, fpp.patch)
						return
					}, nil
				})

			h := newControllerHive(testCell(fgc, fpp))
			cmds, err := h.ScriptCommands(log)
			require.NoError(t, err)
			maps.Insert(e.Cmds, maps.All(cmds))
			require.NoError(t, h.Start(log, tb.Context()))
			tb.Cleanup(func() {
				assert.NoError(t, h.Stop(log, context.Background()))
			})
			return e
		},
		nil,
		"testdata/*.txtar",
		scripttest.NoParallel,
	)
}

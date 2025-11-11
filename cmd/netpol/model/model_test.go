package model

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/tools/txtar"

	"github.com/isovalent/hubble-fgs/cmd/netpol/types"
)

func load(t *testing.T, filename string) map[string][]byte {
	arc, err := txtar.ParseFile(filename)
	if err != nil {
		t.Fatalf("error parsing %q: %s", filename, err)
	}
	files := map[string][]byte{}
	for _, f := range arc.Files {
		files[f.Name] = f.Data
	}
	return files
}

func TestModel(t *testing.T) {
	files := load(t, "testdata/example.txtar")
	policyData, ok := files["policy"]
	require.True(t, ok, "'policy' not found")

	policy, err := types.ParsePolicyTable("policy", bytes.NewReader(policyData))
	require.NoError(t, err)
	model, err := NewModel(policy)
	require.NoError(t, err, "NewModel")

	flowsData, ok := files["flows"]
	require.True(t, ok, "'flows' not found")
	flows, err := types.ParseFlowTable("flows", bytes.NewReader(flowsData))
	require.NoError(t, err)

	for _, f := range flows {
		ruleIndex, verdict := model.Evaluate(f)
		assert.Equal(t, f.Action, verdict, "Verdict mismatch, rule %d, flow %v", ruleIndex, f.String())
	}
}

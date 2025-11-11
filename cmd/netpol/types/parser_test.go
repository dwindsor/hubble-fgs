package types

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParsePolicyTable(t *testing.T) {
	bs, err := os.ReadFile("testdata/policy.table")
	input := string(bs)
	require.NoError(t, err)
	p, err := ParsePolicyTable("policy.table", strings.NewReader(input))
	require.NoError(t, err)
	var buf strings.Builder
	PrintPolicyTable(&buf, p)
	require.Equal(t, input, buf.String())
}

func TestParseFlowTable(t *testing.T) {
	bs, err := os.ReadFile("testdata/flow.table")
	input := string(bs)
	require.NoError(t, err)
	p, err := ParseFlowTable("flow.table", strings.NewReader(input))
	require.NoError(t, err)
	var buf strings.Builder
	PrintFlowTable(&buf, p)
	require.Equal(t, input, buf.String())
}

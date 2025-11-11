package model

import (
	crand "crypto/rand"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/tools/txtar"

	"github.com/isovalent/hubble-fgs/cmd/netpol/types"
)

func TestDelta(t *testing.T) {
	arc, err := txtar.ParseFile("testdata/delta.txtar")
	if err != nil {
		t.Fatalf("error parsing %q: %s", "delta.txtar", err)
	}
	files := map[string][]byte{}
	for _, f := range arc.Files {
		files[f.Name] = f.Data
	}
	policy1 := generatePolicy("base", 10000)
	policy2 := generatePolicy("policy_old", 100)
	policy3 := mutatePolicy("policy_new", policy2)
	//policy3 := generatePolicy("policy_new", 100)
	//policy1, _ := ParsePolicyTable("policy_base", bytes.NewReader(files["policy_base"]))
	//policy2, _ := ParsePolicyTable("policy_old", bytes.NewReader(files["policy_old"]))
	//policy3, _ := ParsePolicyTable("policy_new", bytes.NewReader(files["policy_new"]))

	PrintDelta(os.Stdout, policy1, policy2, policy3)
}

func TestPortsOverlap(t *testing.T) {
	cases := []struct {
		aMin, aMax uint16
		bMin, bMax uint16
		overlaps   bool
	}{
		{1, 1, 1, 1, true},
		{1, 1, 2, 2, false},
		{1, 1, 1, 2, true},
		{0, 65535, 1, 2, true},
		{0, 65535, 0, 65535, true},
		{10000, 65535, 0, 9999, false},
		{10000, 65535, 0, 10000, true},
	}

	for _, c := range cases {
		assert.Equal(t, c.overlaps, portsOverlap(c.aMin, c.aMax, c.bMin, c.bMax), "%v", c)
	}
}

func generatePolicy(name string, num int) (p types.Policy) {
	p.Name = name
	for i := range num {
		p.Rules = append(p.Rules, randomRule(i, name))
	}
	return
}

func randomRule(i int, pname string) types.Rule {
	sMin, sMax := randomPortRange()
	dMin, dMax := randomPortRange()
	action := Allow
	if rand.IntN(10) == 1 {
		action = Deny
	}
	vlan := uint16(rand.IntN(10))
	vrf := fmt.Sprintf("vrf-%d", rand.IntN(10))
	return types.Rule{
		Index:      i,
		PolicyName: pname,
		RuleName:   fmt.Sprintf("rule-%d", i),
		Source: types.Subject{
			Prefix:   randomPrefix(),
			MinPort:  sMin,
			MaxPort:  sMax,
			Vlan:     vlan,
			Vrf:      vrf,
			Protocol: types.TCP,
		},
		Destination: types.Subject{
			Prefix:   randomPrefix(),
			MinPort:  dMin,
			MaxPort:  dMax,
			Vlan:     vlan,
			Vrf:      vrf,
			Protocol: types.TCP,
		},
		Action: action,
	}
}

func mutatePolicy(name string, p types.Policy) (p2 types.Policy) {
	p2.Name = name
	p2.Rules = slices.Clone(p.Rules)
	for i := range p2.Rules {
		p2.Rules[i].PolicyName = name
	}
	i := rand.IntN(len(p.Rules))
	p2.Rules[i] = randomRule(i, name)
	fmt.Printf("mutated: %s => %s\n", p.Rules[i], p2.Rules[i])
	return p2
}

func randomPortRange() (uint16, uint16) {
	a, b := 1+rand.IntN(65534), 1+rand.IntN(65534)
	if a > b {
		return uint16(b), uint16(a)
	}
	return uint16(a), uint16(b)
}

func randomPrefix() netip.Prefix {
	var b [4]byte
	crand.Read(b[:])
	addr := netip.AddrFrom4(b)
	var bits int
	if rand.IntN(10) == 0 {
		bits = rand.IntN(17)
	} else {
		// Bias towards smaller CIDRs
		bits = 16 + rand.IntN(17)
	}
	return netip.PrefixFrom(addr, bits).Masked()
}

func TestFindShadowedRule(t *testing.T) {
	policy, err := types.ParsePolicyTable("rules",
		strings.NewReader(`
Rule      Proto  Src          SrcPort  Dst          DstPort  Action
foo1      TCP    0.0.0.0/0    *        10.0.0.0/8   80-90    allow
foo2      TCP    0.0.0.0/0    *        10.0.0.0/24  80-90    allow
foo3      TCP    0.0.0.0/0    1-10     10.0.0.0/24  80-90    allow
foo4      TCP    0.0.0.0/0    1-10     10.0.0.0/24  80       allow
bar0      TCP    10.0.0.0/8   80-90    0.0.0.0/0    *        allow
bar1      TCP    10.0.0.0/8   80-90    0.0.0.0/0    *        deny
bar2      TCP    10.0.0.0/24  80-90    0.0.0.0/0    *        deny
bar3      TCP    10.0.0.0/24  80-90    0.0.0.0/0    1-10     deny
bar4      TCP    10.0.0.0/24  80       0.0.0.0/0    1-10     deny
	`))
	require.NoError(t, err, "ParsePolicyTable")

	rules2 := compactRules(policy.Rules)
	require.Len(t, rules2, 2)
	require.Equal(t, rules2[0].RuleName, "bar1")
	require.Equal(t, rules2[1].RuleName, "foo1")

	rand.Shuffle(len(policy.Rules),
		func(i int, j int) {
			policy.Rules[i], policy.Rules[j] = policy.Rules[j], policy.Rules[i]
		})

	shadowed := FindShadowedRules(policy.Rules)

	expected := []struct {
		rule       string
		shadowedBy []string
	}{
		{"bar0", []string{"bar1"}},
		{"bar2", []string{"bar1"}},
		{"bar3", []string{"bar1", "bar2"}},
		{"bar4", []string{"bar1", "bar2", "bar3"}},
		{"foo2", []string{"foo1"}},
		{"foo3", []string{"foo1", "foo2"}},
		{"foo4", []string{"foo1", "foo2", "foo3"}},
	}

	require.Len(t, shadowed, len(expected))

	idx := 0
	for _, s := range shadowed {
		ex := expected[idx]
		assert.Equal(t, ex.rule, s.Rule.RuleName)
		if assert.Len(t, s.ShadowedBy, len(ex.shadowedBy), ex.rule) {
			for i := range ex.shadowedBy {
				assert.Equal(t, ex.shadowedBy[i], s.ShadowedBy[i].RuleName)
			}
		}
		idx++
	}
}

func TestMakeCommonPrefix(t *testing.T) {
	cases := []struct {
		a, b, ex netip.Prefix
	}{
		{
			netip.MustParsePrefix("10.2.0.0/24"),
			netip.MustParsePrefix("10.1.0.0/24"),
			netip.MustParsePrefix("10.0.0.0/14"),
		},
		{
			netip.MustParsePrefix("10.4.0.0/24"),
			netip.MustParsePrefix("10.1.0.0/24"),
			netip.MustParsePrefix("10.0.0.0/13"),
		},
		{
			netip.MustParsePrefix("1.0.0.0/8"),
			netip.MustParsePrefix("2.0.0.0/8"),
			netip.MustParsePrefix("0.0.0.0/6"),
		},
		{
			netip.MustParsePrefix("10.2.0.0/24"),
			netip.MustParsePrefix("172.16.0.0/24"),
			netip.MustParsePrefix("0.0.0.0/0"),
		},
		{
			netip.MustParsePrefix("2001:1:1::/48"),
			netip.MustParsePrefix("2001:1:3::/48"),
			netip.MustParsePrefix("2001:1::/46"),
		},
		{
			netip.MustParsePrefix("1::/16"),
			netip.MustParsePrefix("2::/16"),
			netip.MustParsePrefix("::/14"),
		},
		{
			netip.MustParsePrefix("1::/16"),
			netip.MustParsePrefix("ffff::/16"),
			netip.MustParsePrefix("::/0"),
		},
	}

	for _, c := range cases {
		common := makeCommonPrefix(c.a, c.b)
		assert.Equal(t,
			c.ex.String(),
			common.String(),
			"a: %s, b: %s", c.a, c.b)
		assert.True(t, common.Overlaps(c.a), "%s overlaps with %s", common, c.a)
		assert.True(t, common.Overlaps(c.b), "%s overlaps with %s", common, c.b)
	}

}

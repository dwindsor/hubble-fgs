package types

import (
	"fmt"
	"net/netip"
	"os"
	"path"
	"slices"
	"strings"

	"github.com/isovalent/ipa/k8s/apis/isovalent.com/v1alpha1"
	yaml "sigs.k8s.io/yaml"
)

func ParsePolicyDir(dir string) (combinedPolicy Policy, err error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return Policy{}, err
	}
	combinedPolicy.Name = path.Base(dir)
	exts := []string{
		".yml", ".yaml", ".YML", ".YAML",
	}
	for _, ent := range ents {
		if !slices.Contains(exts, path.Ext(ent.Name())) {
			continue
		}
		p, err := parsePolicyFile(path.Join(dir, ent.Name()))
		if err != nil {
			return Policy{}, err
		}
		combinedPolicy.Rules = append(combinedPolicy.Rules, p.Rules...)
	}
	return
}

func parsePolicyFile(file string) (Policy, error) {
	var np v1alpha1.SmartSwitchNetworkPolicy
	bs, err := os.ReadFile(file)
	if err != nil {
		return Policy{}, err
	}
	if err := yaml.Unmarshal(bs, &np); err != nil {
		return Policy{}, err
	}
	return ConvertSmartSwitchNetworkPolicy(&np)
}

func SplitPolicies(prod Policy, staging Policy) (base Policy, old Policy) {
	changed := map[string]bool{}
	for _, r := range staging.Rules {
		changed[r.PolicyName] = true
	}
	base.Name = prod.Name + "-base"
	old.Name = prod.Name + "-old"
	for _, r := range prod.Rules {
		if changed[r.PolicyName] {
			old.Rules = append(old.Rules, r)
		} else {
			base.Rules = append(base.Rules, r)
		}
	}
	return
}

func ConvertSmartSwitchNetworkPolicy(np *v1alpha1.SmartSwitchNetworkPolicy) (policy Policy, err error) {
	var rules []Rule

	for _, r := range np.Spec.Rules {
		action := Deny
		if r.Action == "allow" {
			action = Allow
		}
		for _, s := range r.Source.IPBlock {
			source := Subject{
				Vrf:     s.VRF,
				Vlan:    uint16(s.VLAN),
				MinPort: 0,
				MaxPort: 65535,
			}
			var err error
			source.Prefix, err = netip.ParsePrefix(s.CIDR)
			if err != nil {
				continue
			}

			for _, d := range r.Destination.IPBlock {
				dest := Subject{
					Vrf:  d.VRF,
					Vlan: uint16(d.VLAN),
				}
				dest.Prefix, err = netip.ParsePrefix(d.CIDR)
				if err != nil {
					continue
				}
				for _, p := range r.Destination.ProtoPorts {
					dest.MinPort = uint16(p.Port)
					if p.EndPort == 0 {
						dest.MaxPort = dest.MinPort
					} else {
						dest.MaxPort = uint16(p.EndPort)
					}

					proto := TCP
					switch strings.ToLower(p.Protocol) {
					case "tcp":
						proto = TCP
					case "udp":
						proto = UDP
					case "icmp":
						proto = ICMP
					default:
						return Policy{}, fmt.Errorf("unknown protocol %q", p.Protocol)
					}
					source.Protocol = proto
					rules = append(rules, Rule{
						RuleName:    parseRuleName(r.Description),
						PolicyName:  np.Name,
						Source:      source,
						Destination: dest,
						Action:      action,
					})
				}
			}
		}
	}

	slices.SortFunc(rules, Rule.Compare)
	return Policy{
		Name:       np.Namespace + "/" + np.Name,
		Generation: np.Generation,
		Rules:      rules,
	}, nil
}

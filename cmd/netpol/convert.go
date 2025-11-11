package main

import (
	"io"
	"os"
	"path"
	"strings"

	"github.com/isovalent/ipa/k8s/apis/isovalent.com/v1alpha1"
	"github.com/spf13/cobra"
	yaml "sigs.k8s.io/yaml"

	"github.com/isovalent/hubble-fgs/cmd/netpol/types"
)

var convertCommand = &cobra.Command{
	Use:   "convert [table]",
	Short: "Convert a policy in table format input policy CRD",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		withOutput(cmd, func(w io.Writer) {
			filename := args[0]
			var inp io.Reader
			if filename == "-" {
				inp = os.Stdin
				filename = "stdin"
			} else {
				f, err := os.Open(filename)
				if err != nil {
					printErrorAndExit("Error: %s\n", err)
				}
				defer f.Close()
				inp = f
			}
			policy, err := types.ParsePolicyTable(filename, inp)
			if err != nil {
				printErrorAndExit("Error: %s\n", err)
			}
			ssnp := convertPolicy(policy)
			b, err := yaml.Marshal(ssnp)
			if err != nil {
				printErrorAndExit("Error: %s\n", err)
			}
			w.Write(b)
		})
	},
}

func convertPolicy(policy types.Policy) *v1alpha1.SmartSwitchNetworkPolicy {
	var p v1alpha1.SmartSwitchNetworkPolicy
	p.APIVersion = v1alpha1.SchemeGroupVersion.String()
	p.Kind = v1alpha1.SNPKindDefinition
	p.Name, _ = strings.CutSuffix(path.Base(policy.Name), ".table")
	for _, r := range policy.Rules {
		var sr v1alpha1.SmartSwitchNetworkPolicyRule
		sr.Action = string(r.Action)
		sr.Description = r.RuleName
		sr.Source.IPBlock = []v1alpha1.SmartSwitchNetwork{
			{
				CIDR: r.Source.Prefix.String(),
				VRF:  r.Source.Vrf,
				VLAN: int32(r.Source.Vlan),
			},
		}
		sr.Destination.IPBlock = []v1alpha1.SmartSwitchNetwork{
			{
				CIDR: r.Destination.Prefix.String(),
				VRF:  r.Destination.Vrf,
				VLAN: int32(r.Destination.Vlan),
			},
		}
		sr.Destination.ProtoPorts = []v1alpha1.SmartSwitchProtocolPort{
			{
				Port:     int32(r.Destination.MinPort),
				EndPort:  int32(r.Destination.MaxPort),
				Protocol: strings.ToLower(string(r.Destination.Protocol)),
			},
		}
		p.Spec.Rules = append(p.Spec.Rules, sr)
	}
	return &p
}

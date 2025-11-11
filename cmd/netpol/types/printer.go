package types

import (
	"fmt"
	"io"
	"text/tabwriter"
)

func PrintPolicyTable(w io.Writer, policy Policy) error {
	tw := tabwriter.NewWriter(w, 2, 2, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "Rule\tProto\tSrc\tSrcPort\tSrcVLAN\tSrcVRF\tDst\tDstPort\tDstVLAN\tDstVRF\tAction"); err != nil {
		return err
	}
	for _, r := range policy.Rules {
		if err := r.PrintRule(tw); err != nil {
			return err
		}
	}
	return tw.Flush()
}

func PrintFlowTable(w io.Writer, flows []Flow) error {
	tw := tabwriter.NewWriter(w, 2, 2, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "Src\tSrcPort\tSrcVLAN\tSrcVRF\tDst\tDstPort\tDstVLAN\tDstVRF\tProto\tVerdict"); err != nil {
		return err
	}
	for _, f := range flows {
		if _, err := fmt.Fprintf(tw,
			"%s\t%d\t%d\t%s\t%s\t%d\t%d\t%s\t%s\t%s\n",
			f.Source,
			f.SourcePort,
			f.SourceVlan,
			f.SourceVrf,
			f.Destination,
			f.DestinationPort,
			f.DestinationVlan,
			f.DestinationVrf,
			f.Protocol,
			f.Action,
		); err != nil {
			return err
		}
	}
	return tw.Flush()
}

func PrintFlowDiffTable(w io.Writer, oldPolicy, newPolicy Policy, flows []FlowDiff) error {
	tw := tabwriter.NewWriter(w, 2, 2, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "Src\tSrcPort\tSrcVLAN\tSrcVRF\tDst\tDstPort\tDstVLAN\tDstVRF\tProto\tOld Verdict\tNew Verdict"); err != nil {
		return err
	}
	for _, f := range flows {
		oldVerdict, newVerdict := string(f.V1), string(f.V2)
		if f.I1 >= 0 {
			oldVerdict += " (" + oldPolicy.Rules[f.I1].FullName() + ")"
		}
		if f.I2 >= 0 {
			newVerdict += " (" + newPolicy.Rules[f.I2].FullName() + ")"
		}

		if _, err := fmt.Fprintf(tw,
			"%s\t%d\t%d\t%s\t%s\t%d\t%d\t%s\t%s\t%s\t%s\n",
			f.Flow.Source,
			f.Flow.SourcePort,
			f.Flow.SourceVlan,
			f.Flow.SourceVrf,
			f.Flow.Destination,
			f.Flow.DestinationPort,
			f.Flow.DestinationVlan,
			f.Flow.DestinationVrf,
			f.Flow.Protocol,
			oldVerdict,
			newVerdict,
		); err != nil {
			return err
		}
	}
	return tw.Flush()
}

func showPort(minPort, maxPort uint16) string {
	switch {
	case minPort == maxPort:
		return fmt.Sprintf("%d", minPort)
	case minPort == 0 && maxPort == 65535:
		return "*"
	default:
		return fmt.Sprintf("%d-%d", minPort, maxPort)
	}
}
